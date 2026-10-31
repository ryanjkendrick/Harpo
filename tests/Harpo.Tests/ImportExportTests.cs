using System.Text;
using System.Text.Json;
using Harpo.Data;
using Harpo.Import;
using Harpo.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// Importing entries into a vault and exporting a vault as a file: who may,
/// what is created, what the files contain, and what the audit trail says.
/// </summary>
public class ImportExportTests : IDisposable
{
    private readonly TestSite _site = new("alpha");

    public void Dispose() => _site.Dispose();

    private static ImportRow Row(int row, string name, string password, string username = "", string url = "",
        string notes = "", string totp = "", string icon = "") =>
        new(row, name, username, password, url, notes, totp, icon);

    /// <summary>A shared group created by <paramref name="admin"/>, with the given members.</summary>
    private async Task<Group> GroupAsync(UserContext admin, string name, params (string User, GroupRole Role)[] members)
    {
        var group = await _site.Groups.CreateGroupAsync(admin, name, "");
        foreach (var (member, role) in members)
        {
            await _site.Groups.AddMemberAsync(admin, group.Id, member, "", role);
        }
        return group;
    }

    /// <summary>What a vault holds, every secret included, in a form two vaults can be compared by.</summary>
    private async Task<List<string>> ContentsAsync(UserContext user, Guid groupId)
    {
        var (_, entries) = await _site.Vault.GetOfflineDataAsync(user);
        return entries.Where(e => e.GroupId == groupId)
            .Select(e => string.Join(" | ", e.Name, e.Icon, e.Url, e.Username, e.Password, e.Notes, e.Totp ?? ""))
            .Order(StringComparer.Ordinal)
            .ToList();
    }

    private async Task<List<AuditEvent>> AuditAsync(string action)
    {
        await using var db = _site.Db.CreateDbContext();
        return await db.AuditEvents.Where(e => e.Action == action).ToListAsync();
    }

    // ---- import ----

    [Fact]
    public async Task Import_creates_entries_with_a_revision_by_the_importer_and_reports_each_row()
    {
        var alice = await _site.SignInAsync("alice");
        var bob = await _site.SignInAsync("bob");
        var group = await GroupAsync(alice, "Ops", ("bob", GroupRole.Member));
        await _site.Vault.CreateEntryAsync(alice, group.Id, "Mail", "🔐", "", "bob", "", "old-pw");

        var result = await _site.Vault.ImportEntriesAsync(bob, group.Id,
        [
            Row(2, "Router", "Xk9#mQ2$", username: "admin", url: "router.local", notes: " two\nlines ",
                totp: "otpauth://totp/Router?secret=JBSWY3DPEHPK3PXP&digits=8"),
            Row(3, " mail ", "new-pw", username: " BOB "),      // the same name and username as "Mail"
            Row(4, "", "pw"),                                  // no name
            Row(5, "No password", ""),
            Row(6, "Bad 2FA", "pw", totp: "not base32!"),
            Row(7, "Switch", "pw-7", username: "admin"),
            Row(8, "switch", "pw-8", username: "ADMIN"),       // a duplicate of row 7 in the same file
        ]);

        Assert.Equal(2, result.Created);
        Assert.Equal([new ImportSkip(3, "mail"), new ImportSkip(8, "switch")], result.Skipped);
        Assert.Equal([4, 5, 6], result.Failed.Select(f => f.Row));
        Assert.Equal("Name is required.", result.Failed[0].Reason);
        Assert.Equal("Password is required.", result.Failed[1].Reason);
        Assert.Equal("No password", result.Failed[1].Name);
        Assert.Contains("base32", result.Failed[2].Reason);

        var entries = await _site.Vault.GetEntriesAsync(bob, group.Id);
        Assert.Equal(["Mail", "Router", "Switch"], entries.Select(v => v.Entry.Name));
        var router = entries.Single(v => v.Entry.Name == "Router");
        Assert.Equal("https://router.local", router.Entry.Url);           // the editor's URL rule
        Assert.Equal("two\nlines", router.Notes);
        Assert.Equal(VaultService.DefaultIcon, router.Entry.Icon);
        Assert.Equal("bob", router.PasswordUpdatedBy);
        Assert.Equal("Xk9#mQ2$", await _site.Vault.RevealPasswordAsync(bob, router.Entry.Id));
        Assert.Equal(8, (await _site.Vault.GetTotpCodeAsync(bob, router.Entry.Id)).Code.Length);
        var history = Assert.Single(await _site.Vault.GetHistoryAsync(bob, router.Entry.Id));
        Assert.Equal("bob", history.CreatedBy);
        Assert.Equal("old-pw", await _site.Vault.RevealPasswordAsync(bob, entries.Single(v => v.Entry.Name == "Mail").Entry.Id));
    }

    [Fact]
    public async Task Duplicates_can_be_created_anyway()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        await _site.Vault.CreateEntryAsync(alice, group.Id, "Mail", "🔐", "", "me", "", "pw");

        var result = await _site.Vault.ImportEntriesAsync(alice, group.Id,
            [Row(2, "Mail", "pw2", username: "me"), Row(3, "Mail", "pw3", username: "me")], skipDuplicates: false);

        Assert.Equal(2, result.Created);
        Assert.Empty(result.Skipped);
        Assert.Equal(3, (await _site.Vault.GetEntriesAsync(alice, group.Id)).Count);
    }

    [Fact]
    public async Task Imported_entries_are_ordinary_they_replicate_and_count_in_health()
    {
        using var beta = new TestSite("beta", _site.Time);
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        await _site.Vault.ImportEntriesAsync(alice, group.Id, [Row(2, "Weak", "password"), Row(3, "Reused", "password")]);

        await using (var db = _site.Db.CreateDbContext())
        {
            Assert.All(await db.PasswordRevisions.ToListAsync(), r =>
            {
                Assert.NotNull(r.Fingerprint);
                Assert.NotNull(r.Strength);
                Assert.Equal("alpha", r.OriginSiteId);
            });
        }
        await beta.PullFromAsync(_site);
        var admin = TestSite.User("alice", siteAdmin: true);
        var replicated = await beta.Vault.GetEntriesAsync(admin, group.Id);
        Assert.Equal(["Reused", "Weak"], replicated.Select(v => v.Entry.Name));
        Assert.Equal("password", await beta.Vault.RevealPasswordAsync(admin, replicated[0].Entry.Id));
    }

    [Fact]
    public async Task A_viewer_cannot_import_and_a_member_can()
    {
        var alice = await _site.SignInAsync("alice");
        var bob = await _site.SignInAsync("bob");
        var carol = await _site.SignInAsync("carol");
        var group = await GroupAsync(alice, "Ops", ("bob", GroupRole.Viewer), ("carol", GroupRole.Member));

        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ImportEntriesAsync(bob, group.Id, [Row(2, "X", "pw")]));
        Assert.Equal(1, (await _site.Vault.ImportEntriesAsync(carol, group.Id, [Row(2, "X", "pw")])).Created);

        // Nobody outside the group, and nobody into someone else's personal vault — a site admin included.
        var outsider = await GroupAsync(bob, "Bob's");
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ImportEntriesAsync(carol, outsider.Id, [Row(2, "X", "pw")]));
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ImportEntriesAsync(alice, bobsVault.Id, [Row(2, "X", "pw")]));
        Assert.Equal(1, (await _site.Vault.ImportEntriesAsync(bob, bobsVault.Id, [Row(2, "X", "pw")])).Created);
    }

    [Fact]
    public async Task A_file_over_the_row_limit_is_refused_whole()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        var rows = Enumerable.Range(1, ImportReader.MaxRows + 1).Select(i => Row(i + 1, $"E{i}", "pw")).ToList();

        await Assert.ThrowsAsync<VaultValidationException>(() => _site.Vault.ImportEntriesAsync(alice, group.Id, rows));
        Assert.Empty(await _site.Vault.GetEntriesAsync(alice, group.Id));
    }

    [Fact]
    public async Task An_imported_icon_is_kept_only_when_the_editor_could_have_set_it()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        var reference = CustomIcon.ReferencePrefix + Guid.NewGuid();
        await _site.Vault.ImportEntriesAsync(alice, group.Id,
        [
            Row(2, "Emoji", "pw", icon: "🖥️"),
            Row(3, "Catalogue", "pw", icon: reference),
            Row(4, "KeePass number", "pw", icon: "12"),
            Row(5, "Image URL", "pw", icon: "https://example.com/favicon.ico"),
        ]);

        var icons = (await _site.Vault.GetEntriesAsync(alice, group.Id)).ToDictionary(v => v.Entry.Name, v => v.Entry.Icon);
        Assert.Equal("🖥️", icons["Emoji"]);
        Assert.Equal(reference, icons["Catalogue"]);
        Assert.Equal(VaultService.DefaultIcon, icons["KeePass number"]);
        Assert.Equal(VaultService.DefaultIcon, icons["Image URL"]);
    }

    // ---- export rights ----

    [Fact]
    public async Task Who_may_export()
    {
        var alice = await _site.SignInAsync("alice");   // site admin
        var bob = await _site.SignInAsync("bob");
        var carol = await _site.SignInAsync("carol");
        // bob creates the group (its admin); carol is a member; alice is a site admin outside it.
        var group = await GroupAsync(bob, "Ops", ("carol", GroupRole.Member));
        var viewersGroup = await GroupAsync(bob, "Read only", ("carol", GroupRole.Viewer));

        await _site.Vault.ExportVaultAsync(bob, group.Id, ExportFormat.Csv);              // group admin
        await _site.Vault.ExportVaultAsync(alice, group.Id, ExportFormat.Csv);            // site admin
        var member = await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ExportVaultAsync(carol, group.Id, ExportFormat.Csv));
        Assert.Equal("Only the group's admins can export it.", member.Message);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ExportVaultAsync(carol, viewersGroup.Id, ExportFormat.Json));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.RequireCanExportAsync(carol, group.Id));

        // Personal vaults: the owner, and only the owner.
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await _site.Vault.ExportVaultAsync(bob, bobsVault.Id, ExportFormat.Json);
        var admin = await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ExportVaultAsync(alice, bobsVault.Id, ExportFormat.Json));
        Assert.Contains("Only its owner", admin.Message);
        await Assert.ThrowsAsync<VaultNotFoundException>(
            () => _site.Vault.ExportVaultAsync(bob, Guid.NewGuid(), ExportFormat.Csv));
    }

    [Fact]
    public async Task An_ended_session_can_neither_import_nor_export()
    {
        var principal = await _site.SignInPrincipalAsync("bob");
        var bob = UserContext.FromPrincipal(principal);
        var vault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await _site.Sessions.EndAsync(bob.SessionId);

        var import = await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ImportEntriesAsync(bob, vault.Id, [Row(2, "X", "pw")]));
        Assert.Equal(SessionService.SessionEndedMessage, import.Message);
        var export = await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ExportVaultAsync(bob, vault.Id, ExportFormat.Csv));
        Assert.Equal(SessionService.SessionEndedMessage, export.Message);

        var result = await Endpoint(principal, vault.Id, "csv");
        Assert.Equal(StatusCodes.Status401Unauthorized, StatusOf(result));
    }

    [Fact]
    public async Task The_site_switch_turns_export_off_and_the_endpoint_dark()
    {
        var principal = await _site.SignInPrincipalAsync("bob");
        var bob = UserContext.FromPrincipal(principal);
        var vault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        Assert.True(_site.Vault.ExportEnabled);

        _site.ExportOptions.Enabled = false;
        Assert.False(_site.Vault.ExportEnabled);
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.ExportVaultAsync(bob, vault.Id, ExportFormat.Csv));
        Assert.Equal(StatusCodes.Status404NotFound, StatusOf(await Endpoint(principal, vault.Id, "csv")));
        Assert.Empty(await AuditAsync(AuditActions.VaultExport));

        // Import is not part of the switch.
        Assert.Equal(1, (await _site.Vault.ImportEntriesAsync(bob, vault.Id, [Row(2, "X", "pw")])).Created);
    }

    // ---- export files ----

    [Fact]
    public async Task The_csv_has_the_bitwarden_header_a_bom_and_guards_against_formulas()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        await _site.Vault.CreateEntryAsync(alice, group.Id, "=HYPERLINK(\"http://evil\",\"x\")", "🔐", "https://a", "@admin",
            "notes, with \"quotes\"\nand a second line", "-pw,1", "JBSWY3DPEHPK3PXP");

        var file = await _site.Vault.ExportVaultAsync(alice, group.Id, ExportFormat.Csv);

        Assert.Equal("text/csv; charset=utf-8", file.ContentType);
        Assert.Matches(@"^harpo-ops-\d{4}-\d{2}-\d{2}\.csv$", file.FileName);
        Assert.Equal(1, file.EntryCount);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, file.Content[..3]);
        var text = Encoding.UTF8.GetString(file.Content[3..]);
        Assert.Equal(
            "name,login_uri,login_username,login_password,notes,login_totp\r\n" +
            "\"'=HYPERLINK(\"\"http://evil\"\",\"\"x\"\")\",https://a,\"'@admin\",\"'-pw,1\"," +
            "\"notes, with \"\"quotes\"\"\nand a second line\",JBSWY3DPEHPK3PXP\r\n",
            text);
    }

    [Fact]
    public async Task The_json_holds_every_field_and_says_where_it_came_from()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        var entry = await _site.Vault.CreateEntryAsync(alice, group.Id, "Router", "🖥️", "https://r", "admin", "n1\nn2", "pw-1",
            "otpauth://totp/Router?secret=JBSWY3DPEHPK3PXP");
        await _site.Vault.ChangePasswordAsync(alice, entry.Id, "pw-2");

        var file = await _site.Vault.ExportVaultAsync(alice, group.Id, ExportFormat.Json);

        Assert.Equal("application/json; charset=utf-8", file.ContentType);
        Assert.EndsWith(".json", file.FileName);
        using var json = JsonDocument.Parse(file.Content);
        var root = json.RootElement;
        Assert.Equal(VaultExport.JsonFormatName, root.GetProperty("format").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal("alice", root.GetProperty("exportedBy").GetString());
        Assert.Equal("alpha", root.GetProperty("site").GetString());
        Assert.Equal("Ops", root.GetProperty("vault").GetProperty("name").GetString());
        Assert.False(root.GetProperty("vault").GetProperty("personal").GetBoolean());
        Assert.Equal(1, root.GetProperty("entryCount").GetInt32());
        var only = Assert.Single(root.GetProperty("entries").EnumerateArray().ToList());
        Assert.Equal("Router", only.GetProperty("name").GetString());
        Assert.Equal("🖥️", only.GetProperty("icon").GetString());
        Assert.Equal("pw-2", only.GetProperty("password").GetString());     // current password only
        Assert.DoesNotContain("pw-1", Encoding.UTF8.GetString(file.Content));
        Assert.Equal("n1\nn2", only.GetProperty("notes").GetString());
        Assert.Equal("otpauth://totp/Router?secret=JBSWY3DPEHPK3PXP", only.GetProperty("totp").GetString());
    }

    [Fact]
    public async Task Deleted_entries_are_not_exported()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        await _site.Vault.CreateEntryAsync(alice, group.Id, "Kept", "🔐", "", "", "", "pw");
        var gone = await _site.Vault.CreateEntryAsync(alice, group.Id, "Gone", "🔐", "", "", "", "pw");
        await _site.Vault.DeleteEntryAsync(alice, gone.Id);

        var file = await _site.Vault.ExportVaultAsync(alice, group.Id, ExportFormat.Csv);
        Assert.Equal(1, file.EntryCount);
        Assert.DoesNotContain("Gone", Encoding.UTF8.GetString(file.Content));
    }

    // ---- round trips ----

    private async Task<Group> FilledGroupAsync(UserContext admin, string name)
    {
        var group = await GroupAsync(admin, name);
        await _site.Vault.CreateEntryAsync(admin, group.Id, "Router", VaultService.DefaultIcon, "https://router.local", "admin",
            "Console on port 2,\n\"ask\" Kim", "Xk9#mQ2$vL7!", "otpauth://totp/Router?secret=JBSWY3DPEHPK3PXP&digits=8&period=60");
        await _site.Vault.CreateEntryAsync(admin, group.Id, "=SUM(A1)", VaultService.DefaultIcon, "", "@ops", "", "-starts-with-a-dash",
            "JBSWY3DPEHPK3PXP");
        await _site.Vault.CreateEntryAsync(admin, group.Id, "Ünïcödé 🔑", VaultService.DefaultIcon, "mailto:it@example.com", " spaced ",
            "+44 notes\r\nwindows lines", " pass word ");
        // Values that begin with a quote of their own must survive the formula guard.
        await _site.Vault.CreateEntryAsync(admin, group.Id, "'quoted name", VaultService.DefaultIcon, "", "'", "''two", "'=secret");
        return group;
    }

    [Theory]
    [InlineData(ExportFormat.Csv, "harpo.csv")]
    [InlineData(ExportFormat.Json, "harpo.json")]
    public async Task What_is_exported_imports_back_identically(ExportFormat format, string fileName)
    {
        var alice = await _site.SignInAsync("alice");
        var source = await FilledGroupAsync(alice, "Source");
        if (format == ExportFormat.Json)
        {
            // JSON keeps icons; CSV has no column for them.
            await _site.Vault.CreateEntryAsync(alice, source.Id, "With icon", "🏦", "", "", "", "pw");
        }
        var target = await GroupAsync(alice, "Target");

        var file = await _site.Vault.ExportVaultAsync(alice, source.Id, format);
        var table = ImportReader.Read(fileName, ImportReader.Decode(file.Content));
        var rows = ImportReader.BuildRows(table, ImportReader.GuessMapping(table.Columns));
        var result = await _site.Vault.ImportEntriesAsync(alice, target.Id, rows);

        Assert.Equal(file.EntryCount, result.Created);
        Assert.Empty(result.Failed);
        Assert.Equal(await ContentsAsync(alice, source.Id), await ContentsAsync(alice, target.Id));
    }

    // ---- audit ----

    [Fact]
    public async Task Import_and_export_are_audited_with_counts_and_no_secrets()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupAsync(alice, "Ops");
        await _site.Vault.ImportEntriesAsync(alice, group.Id,
            [Row(2, "Router", "s3cret-pw", notes: "secret note"), Row(3, "Router", "x"), Row(4, "No pw", "")]);
        await _site.Vault.ExportVaultAsync(alice, group.Id, ExportFormat.Json);

        var import = Assert.Single(await AuditAsync(AuditActions.VaultImport));
        Assert.Equal(("alice", "Ops", group.Id), (import.Username, import.Target, import.GroupId));
        Assert.Equal("CSV: 1 created, 1 skipped as duplicates, 1 failed", import.Detail);
        Assert.Equal(AuditCategory.Changes, AuditActions.CategoryOf(import.Action));

        var export = Assert.Single(await AuditAsync(AuditActions.VaultExport));
        Assert.Equal(("alice", "Ops", group.Id), (export.Username, export.Target, export.GroupId));
        Assert.Equal("JSON, 1 entry", export.Detail);
        Assert.Equal(AuditCategory.Reveals, AuditActions.CategoryOf(export.Action));
        Assert.Contains(await _site.Audit.GetEventsAsync(alice, category: AuditCategory.Reveals), e => e.Id == export.Id);

        foreach (var e in new[] { import, export })
        {
            Assert.DoesNotContain("s3cret", e.Target + e.Detail);
            Assert.DoesNotContain("secret note", e.Target + e.Detail);
        }
    }

    [Fact]
    public async Task In_a_personal_vault_the_audit_trail_names_neither_the_entries_nor_the_owner()
    {
        var bob = await _site.SignInAsync("bob");
        var vault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await _site.Vault.ImportEntriesAsync(bob, vault.Id, [Row(2, "Bob's bank", "pw", username: "bob.private")]);
        var file = await _site.Vault.ExportVaultAsync(bob, vault.Id, ExportFormat.Csv);

        Assert.Equal($"harpo-personal-{_site.Time.GetUtcNow():yyyy-MM-dd}.csv", file.FileName);
        var events = (await AuditAsync(AuditActions.VaultImport)).Concat(await AuditAsync(AuditActions.VaultExport)).ToList();
        Assert.Equal(2, events.Count);
        Assert.All(events, e =>
        {
            Assert.Equal(VaultService.PersonalVaultDescription, e.Target);
            Assert.Equal("bob", e.Username); // who did it is recorded, as for every personal-vault event
            Assert.DoesNotContain("bank", e.Target + e.Detail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("bob.private", e.Target + e.Detail);
            Assert.DoesNotContain("bob", e.Target + e.Detail); // nor whose vault it is
        });
        Assert.Equal("CSV, 1 entry", events.Single(e => e.Action == AuditActions.VaultExport).Detail);
    }

    // ---- the download endpoint ----

    private async Task<IResult> Endpoint(
        System.Security.Claims.ClaimsPrincipal principal, Guid groupId, string? format,
        ExportThrottle? throttle = null, string? fetchSite = null, HttpContext? http = null)
    {
        http ??= new DefaultHttpContext();
        if (fetchSite is not null)
        {
            http.Request.Headers["Sec-Fetch-Site"] = fetchSite;
        }
        return await ExportEndpoints.HandleAsync(groupId, format, principal, http, _site.Vault, _site.Sessions,
            throttle ?? new ExportThrottle(_site.Time), Options.Create(_site.ExportOptions), CancellationToken.None);
    }

    private static int? StatusOf(IResult result) => (result as IStatusCodeHttpResult)?.StatusCode;

    [Fact]
    public async Task The_endpoint_sends_an_uncached_attachment()
    {
        var principal = await _site.SignInPrincipalAsync("bob");
        var bob = UserContext.FromPrincipal(principal);
        var vault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await _site.Vault.CreateEntryAsync(bob, vault.Id, "Bank", "🔐", "", "", "", "pw");
        var http = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
            Response = { Body = new MemoryStream() },
        };

        var result = await Endpoint(principal, vault.Id, "csv", fetchSite: "same-origin", http: http);
        var file = Assert.IsType<FileContentHttpResult>(result);
        Assert.Equal("text/csv; charset=utf-8", file.ContentType);
        await result.ExecuteAsync(http);

        Assert.Equal(StatusCodes.Status200OK, http.Response.StatusCode);
        Assert.StartsWith("attachment;", http.Response.Headers.ContentDisposition.ToString());
        Assert.Contains("harpo-personal-", http.Response.Headers.ContentDisposition.ToString());
        Assert.Contains("no-store", http.Response.Headers.CacheControl.ToString());
        Assert.Equal("no-cache", http.Response.Headers.Pragma.ToString());
        Assert.Equal("nosniff", http.Response.Headers.XContentTypeOptions.ToString());
        Assert.Single(await AuditAsync(AuditActions.VaultExport));
    }

    [Fact]
    public async Task The_endpoint_refuses_viewers_members_and_other_peoples_vaults_with_403()
    {
        var alice = await _site.SignInPrincipalAsync("alice");
        var bob = await _site.SignInPrincipalAsync("bob");
        var carol = await _site.SignInPrincipalAsync("carol");
        var group = await GroupAsync(UserContext.FromPrincipal(alice), "Ops",
            ("bob", GroupRole.Viewer), ("carol", GroupRole.Member));
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(UserContext.FromPrincipal(bob));

        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await Endpoint(bob, group.Id, "csv")));
        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await Endpoint(carol, group.Id, "json")));
        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await Endpoint(alice, bobsVault.Id, "csv")));
        Assert.Equal(StatusCodes.Status404NotFound, StatusOf(await Endpoint(alice, Guid.NewGuid(), "csv")));
        Assert.IsType<FileContentHttpResult>(await Endpoint(alice, group.Id, "csv"));
        Assert.Single(await AuditAsync(AuditActions.VaultExport)); // only the export that happened
    }

    [Fact]
    public async Task The_endpoint_rate_limits_each_user_after_checking_their_rights()
    {
        var bob = await _site.SignInPrincipalAsync("bob");
        var carol = await _site.SignInPrincipalAsync("carol");
        var vault = await _site.Groups.EnsurePersonalVaultAsync(UserContext.FromPrincipal(bob));
        var throttle = new ExportThrottle(_site.Time);

        // A refused request does not use up the caller's slot.
        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await Endpoint(carol, vault.Id, "csv", throttle)));
        var carolsVault = await _site.Groups.EnsurePersonalVaultAsync(UserContext.FromPrincipal(carol));
        Assert.IsType<FileContentHttpResult>(await Endpoint(carol, carolsVault.Id, "csv", throttle));

        Assert.IsType<FileContentHttpResult>(await Endpoint(bob, vault.Id, "csv", throttle));
        var http = new DefaultHttpContext();
        Assert.Equal(StatusCodes.Status429TooManyRequests, StatusOf(await Endpoint(bob, vault.Id, "json", throttle, http: http)));
        Assert.Equal("10", http.Response.Headers.RetryAfter.ToString());

        _site.Time.Advance(TimeSpan.FromSeconds(_site.ExportOptions.MinSecondsBetweenExports));
        Assert.IsType<FileContentHttpResult>(await Endpoint(bob, vault.Id, "json", throttle));
    }

    [Theory]
    [InlineData("cross-site", StatusCodes.Status403Forbidden)]
    [InlineData("same-site", StatusCodes.Status403Forbidden)]
    [InlineData("same-origin", StatusCodes.Status200OK)]
    [InlineData("none", StatusCodes.Status200OK)]   // the address typed in, or a bookmark
    public async Task A_link_on_another_site_cannot_start_a_download(string fetchSite, int expected)
    {
        var bob = await _site.SignInPrincipalAsync("bob");
        var vault = await _site.Groups.EnsurePersonalVaultAsync(UserContext.FromPrincipal(bob));

        var result = await Endpoint(bob, vault.Id, "csv", fetchSite: fetchSite);
        Assert.Equal(expected, result is FileContentHttpResult ? StatusCodes.Status200OK : StatusOf(result));
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("CSV", true)]
    [InlineData("json", true)]
    [InlineData("xml", false)]
    public async Task The_format_is_csv_or_json(string? format, bool accepted)
    {
        var bob = await _site.SignInPrincipalAsync("bob");
        var vault = await _site.Groups.EnsurePersonalVaultAsync(UserContext.FromPrincipal(bob));

        var result = await Endpoint(bob, vault.Id, format);
        if (accepted)
        {
            Assert.IsType<FileContentHttpResult>(result);
        }
        else
        {
            Assert.Equal(StatusCodes.Status400BadRequest, StatusOf(result));
        }
    }

    [Fact]
    public void File_names_are_safe_everywhere()
    {
        var day = new DateTime(2026, 10, 31);
        Assert.Equal("harpo-core-routers-eu-2026-10-31.csv", VaultExport.FileName("Core routers (EU)", false, day, ExportFormat.Csv));
        Assert.Equal("harpo-personal-2026-10-31.json", VaultExport.FileName("Personal", true, day, ExportFormat.Json));
        Assert.Equal("harpo-vault-2026-10-31.csv", VaultExport.FileName("🔑 🔑", false, day, ExportFormat.Csv));
        Assert.Matches(@"^harpo-[a-z0-9-]+-2026-10-31\.csv$", VaultExport.FileName("Ünïcödé 🔑", false, day, ExportFormat.Csv));
        Assert.Matches(@"^harpo-[a-z0-9-]+-2026-10-31\.csv$", VaultExport.FileName("../../etc/passwd\"; x", false, day, ExportFormat.Csv));
    }
}
