using System.IO.Compression;
using System.Text;
using Harpo.Data;
using Harpo.Import;
using Harpo.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// The site administrators' export of every shared group as one archive: who
/// may, both switches, what goes in (and what never does), the names inside
/// the zip, the README, the round trip, the audit event and the endpoint.
/// </summary>
public partial class ImportExportTests
{
    /// <summary>The archive's files in order, each with its content (a CSV's byte order mark kept).</summary>
    private static List<(string Name, byte[] Content)> Unzip(byte[] archive)
    {
        using var zip = new ZipArchive(new MemoryStream(archive), ZipArchiveMode.Read);
        return zip.Entries.Select(e =>
        {
            using var stream = e.Open();
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            return (e.FullName, copy.ToArray());
        }).ToList();
    }

    private static string Text(byte[] content) => Encoding.UTF8.GetString(content);

    private void AllowAllGroups() => _site.ExportOptions.AllGroupsEnabled = true;

    private async Task<IResult> AllGroupsEndpoint(
        System.Security.Claims.ClaimsPrincipal principal, string? format,
        AllGroupsExportThrottle? throttle = null, string? fetchSite = null, HttpContext? http = null)
    {
        http ??= new DefaultHttpContext();
        if (fetchSite is not null)
        {
            http.Request.Headers["Sec-Fetch-Site"] = fetchSite;
        }
        return await ExportEndpoints.HandleAllGroupsAsync(format, principal, http, _site.Vault, _site.Sessions,
            throttle ?? new AllGroupsExportThrottle(_site.Time), Options.Create(_site.ExportOptions), CancellationToken.None);
    }

    // ---- rights and switches ----

    [Fact]
    public async Task Only_site_admins_may_export_all_groups_not_a_group_admin()
    {
        AllowAllGroups();
        var alicePrincipal = await _site.SignInPrincipalAsync("alice");
        var bobPrincipal = await _site.SignInPrincipalAsync("bob");
        var alice = UserContext.FromPrincipal(alicePrincipal);
        var bob = UserContext.FromPrincipal(bobPrincipal);
        // bob is the admin of a group, and the only member of it: still not enough.
        var bobs = await GroupAsync(bob, "Bob's team");
        await _site.Vault.CreateEntryAsync(bob, bobs.Id, "Switch", "🔐", "", "", "", "pw");

        var denied = await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.ExportAllGroupsAsync(bob, ExportFormat.Csv));
        Assert.Equal("Only site administrators can export all groups.", denied.Message);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.RequireCanExportAllGroupsAsync(bob));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetAllGroupsExportSummaryAsync(bob));
        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await AllGroupsEndpoint(bobPrincipal, "csv")));

        // A principal claiming the role is not enough either: the live session must agree.
        var forged = bob with { IsSiteAdmin = true };
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.ExportAllGroupsAsync(forged, ExportFormat.Csv));

        // alice, a site admin outside bob's group, may.
        var file = await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv);
        Assert.Equal(1, file.GroupCount);
        Assert.IsType<FileContentHttpResult>(await AllGroupsEndpoint(alicePrincipal, "csv"));
        Assert.Equal(2, (await AuditAsync(AuditActions.SiteExport)).Count); // the two that happened, none for bob
        Assert.All(await AuditAsync(AuditActions.SiteExport), e => Assert.Equal("alice", e.Username));
    }

    [Fact]
    public async Task An_ended_session_cannot_export_all_groups()
    {
        AllowAllGroups();
        var principal = await _site.SignInPrincipalAsync("alice");
        var alice = UserContext.FromPrincipal(principal);
        await GroupAsync(alice, "Ops");
        await _site.Sessions.EndAsync(alice.SessionId);

        var refused = await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv));
        Assert.Equal(SessionService.SessionEndedMessage, refused.Message);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetAllGroupsExportSummaryAsync(alice));
        Assert.Equal(StatusCodes.Status401Unauthorized, StatusOf(await AllGroupsEndpoint(principal, "csv")));
        Assert.Empty(await AuditAsync(AuditActions.SiteExport));
    }

    [Fact]
    public async Task It_is_off_by_default_and_needs_both_switches()
    {
        var principal = await _site.SignInPrincipalAsync("alice");
        var alice = UserContext.FromPrincipal(principal);
        await GroupAsync(alice, "Ops");

        // Default: the export switch on, the all-groups switch off.
        Assert.True(_site.ExportOptions.Enabled);
        Assert.False(new ExportOptions().AllGroupsEnabled);
        Assert.False(_site.Vault.AllGroupsExportEnabled);
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.GetAllGroupsExportSummaryAsync(alice));
        Assert.Equal(StatusCodes.Status404NotFound, StatusOf(await AllGroupsEndpoint(principal, "csv")));

        // Its own switch alone is not enough while exports are off.
        _site.ExportOptions.AllGroupsEnabled = true;
        _site.ExportOptions.Enabled = false;
        Assert.False(_site.Vault.AllGroupsExportEnabled);
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv));
        Assert.Equal(StatusCodes.Status404NotFound, StatusOf(await AllGroupsEndpoint(principal, "csv")));
        // The switch is checked first: another site's page or a bad format still gets 404.
        Assert.Equal(StatusCodes.Status404NotFound, StatusOf(await AllGroupsEndpoint(principal, "xml", fetchSite: "cross-site")));
        Assert.Empty(await AuditAsync(AuditActions.SiteExport));

        _site.ExportOptions.Enabled = true;
        Assert.True(_site.Vault.AllGroupsExportEnabled);
        Assert.IsType<FileContentHttpResult>(await AllGroupsEndpoint(principal, "csv"));
        Assert.Single(await AuditAsync(AuditActions.SiteExport));

        // And turning the all-groups switch off leaves the per-vault export alone.
        _site.ExportOptions.AllGroupsEnabled = false;
        Assert.True(_site.Vault.ExportEnabled);
    }

    // ---- what goes in ----

    [Fact]
    public async Task Personal_vaults_never_appear_in_the_archive_the_counts_or_the_audit()
    {
        AllowAllGroups();
        var alice = await _site.SignInAsync("alice");
        var bob = await _site.SignInAsync("bob");
        var carol = await _site.SignInAsync("carol");
        var ops = await GroupAsync(alice, "Ops");
        await _site.Vault.CreateEntryAsync(alice, ops.Id, "Router", "🔐", "", "admin", "", "router-pw");
        // Personal vaults, the exporting admin's own included, each with something unmistakable in it.
        var mine = await _site.Groups.EnsurePersonalVaultAsync(alice);
        await _site.Vault.CreateEntryAsync(alice, mine.Id, "Alice diary", "🔐", "https://alice.private", "alice.private",
            "alice note", "alice-secret-pw", "JBSWY3DPEHPK3PXP");
        var bobs = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await _site.Vault.CreateEntryAsync(bob, bobs.Id, "Bob bank", "🔐", "https://bob.private", "bob.private",
            "bob note", "bob-secret-pw");
        var carols = await _site.Groups.EnsurePersonalVaultAsync(carol); // empty: not even an empty file
        var personalSecrets = new[] { "Alice diary", "alice.private", "alice note", "alice-secret-pw", "JBSWY3DPEHPK3PXP",
            "Bob bank", "bob.private", "bob note", "bob-secret-pw" };

        var summary = await _site.Vault.GetAllGroupsExportSummaryAsync(alice);
        Assert.Equal(new AllGroupsSummary(1, 1), summary);

        foreach (var format in new[] { ExportFormat.Csv, ExportFormat.Json })
        {
            var file = await _site.Vault.ExportAllGroupsAsync(alice, format);
            Assert.Equal((1, 1), (file.GroupCount, file.EntryCount));
            var files = Unzip(file.Content);
            Assert.Equal([AllGroupsArchive.ReadmeName, $"Ops.{VaultExport.Extension(format)}"], files.Select(f => f.Name));
            foreach (var (name, content) in files)
            {
                var text = Text(content);
                Assert.All(personalSecrets, secret => Assert.DoesNotContain(secret, name + text));
                Assert.DoesNotContain(mine.Id.ToString(), text);
                Assert.DoesNotContain(bobs.Id.ToString(), text);
                Assert.DoesNotContain(carols.Id.ToString(), text);
                Assert.DoesNotContain(PersonalVaultName, name);
            }
            Assert.Contains("router-pw", Text(files[1].Content));
            // The README lists the groups; a personal vault is not one of them.
            var readme = Text(files[0].Content);
            Assert.Contains("1 group, 1 entry", readme);
            Assert.DoesNotContain($"{PersonalVaultName}  ->", readme);
        }

        var events = await AuditAsync(AuditActions.SiteExport);
        Assert.Equal(2, events.Count);
        Assert.All(events, e =>
        {
            Assert.Equal(VaultService.AllGroupsAuditTarget, e.Target);
            Assert.Null(e.GroupId);
            Assert.Null(e.EntryId);
            Assert.Matches(@"^(CSV|JSON), 1 group, 1 entry$", e.Detail);
            Assert.All(personalSecrets.Append("Ops").Append("Router").Append(PersonalVaultName),
                s => Assert.DoesNotContain(s, e.Target + e.Detail, StringComparison.OrdinalIgnoreCase));
        });

        // Once a site admin has taken a vault over it is an ordinary group, and goes in like one.
        await _site.Groups.TakeOverPersonalVaultAsync(alice, bobs.Id, "Bob's old vault");
        _site.Time.Advance(TimeSpan.FromSeconds(1));
        var after = Unzip((await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv)).Content);
        Assert.Equal([AllGroupsArchive.ReadmeName, "Bob's old vault.csv", "Ops.csv"], after.Select(f => f.Name));
        Assert.Equal(new AllGroupsSummary(2, 2), await _site.Vault.GetAllGroupsExportSummaryAsync(alice));
        Assert.All(after, f => Assert.DoesNotContain("alice-secret-pw", Text(f.Content)));
    }

    /// <summary>What <see cref="GroupService.EnsurePersonalVaultAsync"/> names every personal vault.</summary>
    private static string PersonalVaultName => GroupService.PersonalVaultName;

    [Fact]
    public async Task Deleted_groups_and_entries_are_left_out_and_empty_groups_kept()
    {
        AllowAllGroups();
        var alice = await _site.SignInAsync("alice");
        var kept = await GroupAsync(alice, "Kept");
        await _site.Vault.CreateEntryAsync(alice, kept.Id, "Live", "🔐", "", "", "", "live-pw");
        var gone = await _site.Vault.CreateEntryAsync(alice, kept.Id, "Gone entry", "🔐", "", "", "", "gone-entry-pw");
        await _site.Vault.DeleteEntryAsync(alice, gone.Id);
        var deleted = await GroupAsync(alice, "Deleted group");
        await _site.Vault.CreateEntryAsync(alice, deleted.Id, "In a deleted group", "🔐", "", "", "", "deleted-group-pw");
        await _site.Groups.DeleteGroupAsync(alice, deleted.Id);
        await GroupAsync(alice, "Empty");

        Assert.Equal(new AllGroupsSummary(2, 1), await _site.Vault.GetAllGroupsExportSummaryAsync(alice));
        var file = await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv);
        Assert.Equal((2, 1), (file.GroupCount, file.EntryCount));
        var files = Unzip(file.Content);
        Assert.Equal([AllGroupsArchive.ReadmeName, "Empty.csv", "Kept.csv"], files.Select(f => f.Name));
        var all = string.Concat(files.Select(f => f.Name + Text(f.Content)));
        Assert.DoesNotContain("gone-entry-pw", all);
        Assert.DoesNotContain("Gone entry", all);
        Assert.DoesNotContain("deleted-group-pw", all);
        Assert.DoesNotContain("Deleted group", all);
        // The empty group is a header-only file, exactly what its own export would be.
        Assert.Equal(CsvWriter.ToUtf8WithBom(VaultExport.ToCsv([])), files[1].Content);
        Assert.Contains("Empty  ->  Empty.csv  (0 entries)", Text(files[0].Content));
    }

    // ---- names inside the zip ----

    [Theory]
    [InlineData("Ops", "Ops")]
    [InlineData("../../etc/passwd", "etc_passwd")]
    [InlineData("..\\..\\Windows\\System32", "Windows_System32")]
    [InlineData("/etc/shadow", "etc_shadow")]
    [InlineData("C:\\boot.ini", "C_boot.ini")]
    [InlineData("a<b>c:d\"e|f?g*h", "a_b_c_d_e_f_g_h")]
    [InlineData("line\nbreak\ttab\0nul", "line_break_tab_nul")]
    [InlineData("invoice\u202Etxt.exe", "invoice_txt.exe")]          // a right-to-left override hiding ".exe"
    [InlineData("zero\u200Bwidth", "zero_width")]
    [InlineData("...", "group")]
    [InlineData("  .hidden  ", "hidden")]
    [InlineData("trailing dots...", "trailing dots")]
    [InlineData("a....b", "a.b")]
    [InlineData("CON", "CON_")]
    [InlineData("nul.backup", "nul_.backup")]
    [InlineData("com1", "com1_")]
    [InlineData("CONSOLE", "CONSOLE")]
    [InlineData("Ünïcödé 🔑 Ops", "Ünïcödé 🔑 Ops")]
    [InlineData("many   spaces", "many spaces")]
    [InlineData("", "group")]
    public void Group_names_become_safe_file_names(string groupName, string expectedStem)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Assert.Equal(expectedStem + ".csv", AllGroupsArchive.EntryName(groupName, ExportFormat.Csv, used));
    }

    [Fact]
    public void Long_names_are_cut_on_a_character_boundary()
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ascii = AllGroupsArchive.EntryName(new string('a', 300), ExportFormat.Json, used);
        Assert.Equal(new string('a', AllGroupsArchive.MaxStemBytes) + ".json", ascii);

        var emoji = AllGroupsArchive.EntryName(string.Concat(Enumerable.Repeat("🔑", 60)), ExportFormat.Csv, used);
        var stem = emoji[..^4];
        Assert.True(Encoding.UTF8.GetByteCount(stem) <= AllGroupsArchive.MaxStemBytes);
        Assert.Equal(AllGroupsArchive.MaxStemBytes / 4, stem.EnumerateRunes().Count());
        Assert.All(stem.EnumerateRunes(), r => Assert.Equal("🔑", r.ToString())); // no half an emoji

        var cutAtDot = AllGroupsArchive.EntryName(new string('b', AllGroupsArchive.MaxStemBytes - 1) + ".tail", ExportFormat.Csv, used);
        Assert.Equal(new string('b', AllGroupsArchive.MaxStemBytes - 1) + ".csv", cutAtDot); // no "bbb..csv"
    }

    [Fact]
    public void Duplicate_names_are_numbered_ignoring_case_and_never_take_the_readme()
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { AllGroupsArchive.ReadmeName };
        Assert.Equal("Ops.csv", AllGroupsArchive.EntryName("Ops", ExportFormat.Csv, used));
        Assert.Equal("Ops (2).csv", AllGroupsArchive.EntryName("Ops", ExportFormat.Csv, used));
        Assert.Equal("ops (3).csv", AllGroupsArchive.EntryName("ops", ExportFormat.Csv, used));
        Assert.Equal("Ops (4).csv", AllGroupsArchive.EntryName("Ops/", ExportFormat.Csv, used));     // sanitises to "Ops" too
        Assert.Equal("Ops (2) (2).csv", AllGroupsArchive.EntryName("Ops (2)", ExportFormat.Csv, used));
        Assert.Equal("README.csv", AllGroupsArchive.EntryName("README", ExportFormat.Csv, used));    // a different file
        Assert.Equal("group.csv", AllGroupsArchive.EntryName("..", ExportFormat.Csv, used));
        Assert.Equal("group (2).csv", AllGroupsArchive.EntryName("//", ExportFormat.Csv, used));
    }

    [Fact]
    public async Task The_archive_extracts_safely_with_one_file_per_group()
    {
        AllowAllGroups();
        var alice = await _site.SignInAsync("alice");
        foreach (var name in new[] { "../../etc/passwd", "Ops", "Ops", "ops", "..\\evil", "CON", "a/b/c", "\u202Eexe.txt" })
        {
            var group = await GroupAsync(alice, name);
            await _site.Vault.CreateEntryAsync(alice, group.Id, $"Entry of {name}", "🔐", "", "", "", "pw");
        }

        var file = await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv);
        Assert.Equal(8, file.GroupCount);
        var names = Unzip(file.Content).Select(f => f.Name).ToList();
        Assert.Equal(9, names.Count);
        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains("etc_passwd.csv", names);
        Assert.Contains("Ops.csv", names);
        Assert.Contains("Ops (2).csv", names);
        Assert.Contains("ops (3).csv", names);
        Assert.Contains("CON_.csv", names);
        Assert.Contains("a_b_c.csv", names);
        Assert.All(names, n =>
        {
            Assert.DoesNotContain("/", n);
            Assert.DoesNotContain("\\", n);
            Assert.DoesNotContain("..", n);
            Assert.False(n.StartsWith('.'));
            Assert.DoesNotContain(n, c => char.IsControl(c) || c == '\u202E');
        });

        // Extracted for real, everything lands directly in the target folder.
        var target = Directory.CreateTempSubdirectory("harpo-all-groups-");
        try
        {
            ZipFile.ExtractToDirectory(new MemoryStream(file.Content), target.FullName);
            Assert.Equal(9, target.GetFiles().Length);
            Assert.Empty(target.GetDirectories());
            Assert.Equal(names.Order(StringComparer.Ordinal), target.GetFiles().Select(f => f.Name).Order(StringComparer.Ordinal));
        }
        finally
        {
            target.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task The_readme_says_what_the_archive_is_when_by_whom_and_where_each_group_went()
    {
        AllowAllGroups();
        var alice = await _site.SignInAsync("alice");
        var ops = await GroupAsync(alice, "Ops");
        await _site.Vault.CreateEntryAsync(alice, ops.Id, "Router", "🔐", "", "", "", "pw");
        await _site.Vault.CreateEntryAsync(alice, ops.Id, "Switch", "🔐", "", "", "", "pw");
        _site.Time.Advance(TimeSpan.FromSeconds(1));
        await GroupAsync(alice, "Ops");
        await GroupAsync(alice, "Two\nlines");

        var file = await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Json);
        var readme = Text(Unzip(file.Content).Single(f => f.Name == AllGroupsArchive.ReadmeName).Content);

        Assert.Contains("Site:         alpha", readme);
        Assert.Contains($"Exported at:  {_site.Time.GetUtcNow():yyyy-MM-dd HH:mm:ss} UTC", readme);
        Assert.Contains("Exported by:  alice", readme);
        Assert.Contains("JSON", readme);
        Assert.Contains("3 groups, 2 entries", readme);
        Assert.Contains("NOT ENCRYPTED", readme);
        Assert.Contains("audit log", readme);
        Assert.Contains("Delete this archive", readme);
        Assert.Contains("personal vaults", readme);
        // Which of the two Ops went where is fixed by creation time: the older one keeps the plain name.
        Assert.Contains("Ops  ->  Ops.json  (2 entries)", readme);
        Assert.Contains("Ops  ->  Ops (2).json  (0 entries)", readme);
        Assert.Contains("Two lines  ->  Two_lines.json  (0 entries)", readme); // a name never breaks the list
        Assert.Matches(@"^harpo-alpha-all-groups-\d{4}-\d{2}-\d{2}\.zip$", file.FileName);
    }

    // ---- round trip ----

    [Theory]
    [InlineData(ExportFormat.Csv)]
    [InlineData(ExportFormat.Json)]
    public async Task Each_group_file_is_the_groups_own_export_and_imports_back_identically(ExportFormat format)
    {
        AllowAllGroups();
        var alice = await _site.SignInAsync("alice");
        var first = await FilledGroupAsync(alice, "First");
        var second = await FilledGroupAsync(alice, "Second");
        if (format == ExportFormat.Json)
        {
            await _site.Vault.CreateEntryAsync(alice, second.Id, "With icon", "🏦", "", "", "", "pw");
        }

        var archive = Unzip((await _site.Vault.ExportAllGroupsAsync(alice, format)).Content);
        foreach (var source in new[] { first, second })
        {
            var fileName = $"{source.Name}.{VaultExport.Extension(format)}";
            var content = archive.Single(f => f.Name == fileName).Content;
            // Byte for byte what the group's own export gives (the clock has not moved, so the JSON's date agrees).
            Assert.Equal((await _site.Vault.ExportVaultAsync(alice, source.Id, format)).Content, content);

            var target = await GroupAsync(alice, $"{source.Name} again");
            var table = ImportReader.Read(fileName, ImportReader.Decode(content));
            var rows = ImportReader.BuildRows(table, ImportReader.GuessMapping(table.Columns));
            var result = await _site.Vault.ImportEntriesAsync(alice, target.Id, rows);
            Assert.Empty(result.Failed);
            Assert.Equal(await ContentsAsync(alice, source.Id), await ContentsAsync(alice, target.Id));
        }
    }

    // ---- audit ----

    [Fact]
    public async Task Each_download_is_one_audit_event_with_the_format_and_counts_only()
    {
        AllowAllGroups();
        var alice = await _site.SignInAsync("alice");
        var a = await GroupAsync(alice, "Alpha team");
        var b = await GroupAsync(alice, "Beta team");
        await _site.Vault.CreateEntryAsync(alice, a.Id, "Router", "🔐", "", "admin", "secret note", "s3cret-pw");
        await _site.Vault.CreateEntryAsync(alice, a.Id, "Switch", "🔐", "", "", "", "pw");
        await _site.Vault.CreateEntryAsync(alice, b.Id, "Firewall", "🔐", "", "", "", "pw");
        var before = (await AuditAsync(AuditActions.VaultExport)).Count + (await AuditAsync(AuditActions.PasswordReveal)).Count;

        await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Json);

        var only = Assert.Single(await AuditAsync(AuditActions.SiteExport));
        Assert.Equal(("alice", "all groups", "JSON, 2 groups, 3 entries"), (only.Username, only.Target, only.Detail));
        Assert.Null(only.GroupId);
        Assert.Equal(AuditCategory.Reveals, AuditActions.CategoryOf(only.Action));
        Assert.Contains(await _site.Audit.GetEventsAsync(alice, category: AuditCategory.Reveals), e => e.Id == only.Id);
        foreach (var name in new[] { "Alpha", "Beta", "Router", "Switch", "Firewall", "s3cret", "secret note", "admin" })
        {
            Assert.DoesNotContain(name, only.Target + only.Detail);
        }
        // No per-group or per-entry events beside it.
        Assert.Equal(before, (await AuditAsync(AuditActions.VaultExport)).Count + (await AuditAsync(AuditActions.PasswordReveal)).Count);

        _site.Time.Advance(TimeSpan.FromMinutes(1));
        await _site.Groups.DeleteGroupAsync(alice, a.Id);
        await _site.Vault.ExportAllGroupsAsync(alice, ExportFormat.Csv);
        Assert.Contains(await AuditAsync(AuditActions.SiteExport), e => e.Detail == "CSV, 1 group, 1 entry");
    }

    // ---- the download endpoint ----

    [Fact]
    public async Task The_all_groups_endpoint_sends_an_uncached_zip_attachment()
    {
        AllowAllGroups();
        var principal = await _site.SignInPrincipalAsync("alice");
        var ops = await GroupAsync(UserContext.FromPrincipal(principal), "Ops");
        await _site.Vault.CreateEntryAsync(UserContext.FromPrincipal(principal), ops.Id, "Router", "🔐", "", "", "", "pw");
        var http = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
            Response = { Body = new MemoryStream() },
        };

        var result = await AllGroupsEndpoint(principal, "csv", fetchSite: "same-origin", http: http);
        var file = Assert.IsType<FileContentHttpResult>(result);
        Assert.Equal("application/zip", file.ContentType);
        await result.ExecuteAsync(http);

        Assert.Equal(StatusCodes.Status200OK, http.Response.StatusCode);
        var disposition = http.Response.Headers.ContentDisposition.ToString();
        Assert.StartsWith("attachment;", disposition);
        Assert.Contains($"harpo-alpha-all-groups-{_site.Time.GetUtcNow():yyyy-MM-dd}.zip", disposition);
        Assert.Contains("no-store", http.Response.Headers.CacheControl.ToString());
        Assert.Equal("no-cache", http.Response.Headers.Pragma.ToString());
        Assert.Equal("nosniff", http.Response.Headers.XContentTypeOptions.ToString());
        var body = ((MemoryStream)http.Response.Body).ToArray();
        Assert.Equal("PK"u8.ToArray(), body[..2]);
        Assert.Equal([AllGroupsArchive.ReadmeName, "Ops.csv"], Unzip(body).Select(f => f.Name));
        Assert.Single(await AuditAsync(AuditActions.SiteExport));
    }

    [Theory]
    [InlineData("cross-site", "csv", StatusCodes.Status403Forbidden)]
    [InlineData("same-site", "csv", StatusCodes.Status403Forbidden)]
    [InlineData("cross-site", "xml", StatusCodes.Status403Forbidden)] // the origin is checked before the format
    [InlineData("same-origin", "xml", StatusCodes.Status400BadRequest)]
    [InlineData("none", "JSON", StatusCodes.Status200OK)]
    [InlineData(null, null, StatusCodes.Status200OK)]                 // csv by default
    public async Task The_all_groups_endpoint_checks_origin_then_format(string? fetchSite, string? format, int expected)
    {
        AllowAllGroups();
        var principal = await _site.SignInPrincipalAsync("alice");

        var result = await AllGroupsEndpoint(principal, format, fetchSite: fetchSite);
        Assert.Equal(expected, result is FileContentHttpResult ? StatusCodes.Status200OK : StatusOf(result));
        Assert.Equal(expected == StatusCodes.Status200OK ? 1 : 0, (await AuditAsync(AuditActions.SiteExport)).Count);
    }

    [Fact]
    public async Task The_all_groups_endpoint_allows_one_archive_a_minute_per_user_with_its_own_slots()
    {
        AllowAllGroups();
        var alice = await _site.SignInPrincipalAsync("alice");
        var bob = await _site.SignInPrincipalAsync("bob");
        var throttle = new AllGroupsExportThrottle(_site.Time);
        var vaultThrottle = new ExportThrottle(_site.Time);
        var alicesVault = await _site.Groups.EnsurePersonalVaultAsync(UserContext.FromPrincipal(alice));
        Assert.Equal(60, _site.ExportOptions.MinSecondsBetweenAllGroupsExports);

        // A refusal costs no slot: refused by origin or format first, then the download.
        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await AllGroupsEndpoint(alice, "csv", throttle, fetchSite: "cross-site")));
        Assert.Equal(StatusCodes.Status403Forbidden, StatusOf(await AllGroupsEndpoint(bob, "csv", throttle)));
        Assert.IsType<FileContentHttpResult>(await AllGroupsEndpoint(alice, "csv", throttle));

        var http = new DefaultHttpContext();
        Assert.Equal(StatusCodes.Status429TooManyRequests, StatusOf(await AllGroupsEndpoint(alice, "json", throttle, http: http)));
        Assert.Equal("60", http.Response.Headers.RetryAfter.ToString());
        // A vault export is not held up by it.
        Assert.IsType<FileContentHttpResult>(await ExportEndpoints.HandleAsync(alicesVault.Id, "csv", alice, new DefaultHttpContext(),
            _site.Vault, _site.Sessions, vaultThrottle, Options.Create(_site.ExportOptions), CancellationToken.None));

        _site.Time.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal(StatusCodes.Status429TooManyRequests, StatusOf(await AllGroupsEndpoint(alice, "json", throttle)));
        _site.Time.Advance(TimeSpan.FromSeconds(1));
        Assert.IsType<FileContentHttpResult>(await AllGroupsEndpoint(alice, "json", throttle));
        Assert.Equal(2, (await AuditAsync(AuditActions.SiteExport)).Count);
    }
}
