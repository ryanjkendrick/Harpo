using Harpo.Data;
using Harpo.Services;

namespace Harpo.Tests;

public class IconTests : IDisposable
{
    // A real 1×1 transparent PNG.
    private static readonly byte[] TinyPng = Convert.FromBase64String(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==");

    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _admin = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    [Fact]
    public async Task Icons_can_be_added_listed_served_and_deleted()
    {
        var icon = await _site.Icons.AddAsync(_alice, "GitLab", "image/png", TinyPng);
        Assert.StartsWith("icon:", icon.Reference);
        Assert.Equal(icon.Id, CustomIcon.ParseReference(icon.Reference));

        var listed = Assert.Single(await _site.Icons.GetAllAsync());
        Assert.Equal("GitLab", listed.Name);
        Assert.Equal(TinyPng.Length, listed.SizeBytes);

        var served = await _site.Icons.GetDataAsync(icon.Id);
        Assert.Equal(TinyPng, served!.Value.Data);
        Assert.Equal("image/png", served.Value.ContentType);

        // Curation is admin-only; deletion tombstones and stops serving.
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Icons.DeleteAsync(_alice, icon.Id));
        await _site.Icons.DeleteAsync(_admin, icon.Id);
        Assert.Empty(await _site.Icons.GetAllAsync());
        Assert.Null(await _site.Icons.GetDataAsync(icon.Id));

        var actions = (await _site.Audit.GetEventsAsync(_admin)).Select(e => e.Action).ToList();
        Assert.Contains(AuditActions.IconAdd, actions);
        Assert.Contains(AuditActions.IconDelete, actions);
    }

    [Fact]
    public async Task Uploads_are_validated_hard()
    {
        // Wrong magic bytes for the declared type.
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Icons.AddAsync(_alice, "Fake", "image/png", "not a png"u8.ToArray()));
        // Type not on the allowlist.
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Icons.AddAsync(_alice, "Nope", "text/html", TinyPng));
        // Size cap.
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Icons.AddAsync(_alice, "Big", "image/png",
                [.. TinyPng, .. new byte[CustomIcon.MaxBytes]]));
        // SVG must actually look like SVG.
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Icons.AddAsync(_alice, "NotSvg", "image/svg+xml", "<script>alert(1)</script>"u8.ToArray()));
        Assert.NotNull(await _site.Icons.AddAsync(_alice, "RealSvg", "image/svg+xml",
            """<svg xmlns="http://www.w3.org/2000/svg"><rect width="8" height="8"/></svg>"""u8.ToArray()));
    }

    [Fact]
    public async Task Usage_counts_reference_live_entries_only()
    {
        var icon = await _site.Icons.AddAsync(_alice, "GitLab", "image/png", TinyPng);
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var used = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Repo", icon.Reference, "", "", "", "pw1");
        await _site.Vault.CreateEntryAsync(_alice, group.Id, "Other", "🌐", "", "", "", "pw2");

        Assert.Equal(1, (await _site.Icons.GetUsageAsync()).GetValueOrDefault(icon.Id));

        await _site.Vault.DeleteEntryAsync(_alice, used.Id);
        Assert.Equal(0, (await _site.Icons.GetUsageAsync()).GetValueOrDefault(icon.Id));
    }

    [Theory]
    [InlineData("https://gitlab.com/group/repo", "gitlab.com")]
    [InlineData("gitlab.com", "gitlab.com")]
    [InlineData("GIT.GitLab.com:8443/x", "git.gitlab.com")]
    [InlineData("not a url at all", null)]
    [InlineData("", null)]
    [InlineData("localhost", null)] // single-label hosts don't attribute
    public void Hosts_are_extracted_from_whatever_users_type(string input, string? expected) =>
        Assert.Equal(expected, IconUrlMatcher.ExtractHost(input));

    [Fact]
    public void Host_lists_normalize_and_matching_prefers_specificity()
    {
        Assert.Equal("git.corp.io gitlab.com",
            IconUrlMatcher.NormalizeHostList("https://gitlab.com/x, GIT.corp.io; gitlab.com"));

        var generic = new IconSummary(Guid.NewGuid(), "Corp", "alice", 1, "image/png", "corp.io");
        var specific = new IconSummary(Guid.NewGuid(), "Corp Git", "alice", 1, "image/png", "git.corp.io");
        var unrelated = new IconSummary(Guid.NewGuid(), "Other", "alice", 1, "image/png", "other.example");
        var icons = new[] { unrelated, generic, specific };

        // Subdomain of the specific attribution → the specific icon wins.
        Assert.Equal(specific.Id, IconUrlMatcher.FindBestMatch("https://sub.git.corp.io/repo", icons)!.Id);
        // Sibling host only matches the generic attribution.
        Assert.Equal(generic.Id, IconUrlMatcher.FindBestMatch("wiki.corp.io", icons)!.Id);
        // "notcorp.io" must not suffix-match "corp.io".
        Assert.Null(IconUrlMatcher.FindBestMatch("https://notcorp.io", icons));
        Assert.Null(IconUrlMatcher.FindBestMatch("unrelated.net", icons));
    }

    [Fact]
    public async Task Admins_can_rename_and_reattribute_icons_from_one_edit()
    {
        var icon = await _site.Icons.AddAsync(_alice, "GitLab", "image/png", TinyPng,
            matchUrls: "https://gitlab.com/some/path");
        Assert.Equal("gitlab.com", Assert.Single(await _site.Icons.GetAllAsync()).MatchUrls);

        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Icons.UpdateAsync(_alice, icon.Id, matchUrls: "corp.io"));
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Icons.UpdateAsync(_admin, icon.Id, name: "   "));

        await _site.Icons.UpdateAsync(_admin, icon.Id, name: "Corp Git", matchUrls: "GIT.corp.io, gitlab.com");
        var updated = Assert.Single(await _site.Icons.GetAllAsync());
        Assert.Equal("Corp Git", updated.Name);
        Assert.Equal("git.corp.io gitlab.com", updated.MatchUrls);
        Assert.Contains(await _site.Audit.GetEventsAsync(_admin),
            e => e.Action == AuditActions.IconUpdate
                 && e.Detail.Contains("renamed") && e.Detail.Contains("git.corp.io"));

        // Null parameters keep values; a no-op edit records no audit event.
        var auditCount = (await _site.Audit.GetEventsAsync(_admin)).Count;
        await _site.Icons.UpdateAsync(_admin, icon.Id, name: "Corp Git");
        Assert.Equal(auditCount, (await _site.Audit.GetEventsAsync(_admin)).Count);
    }

    private static IconService ImportingIconService(TestSite site, string path) => new(
        site.Db, site.Time, site.Audit,
        Microsoft.Extensions.Options.Options.Create(new IconOptions { ImportPath = path }),
        Microsoft.Extensions.Logging.Abstractions.NullLogger<IconService>.Instance);

    [Fact]
    public async Task Server_folder_import_is_idempotent_and_respects_curation()
    {
        var dir = Directory.CreateTempSubdirectory("harpo-icons-").FullName;
        try
        {
            await File.WriteAllBytesAsync(Path.Combine(dir, "gitlab.example.com.png"), TinyPng);
            await File.WriteAllTextAsync(Path.Combine(dir, "Plain.svg"),
                """<svg xmlns="http://www.w3.org/2000/svg"><rect width="8" height="8"/></svg>""");
            await File.WriteAllTextAsync(Path.Combine(dir, "README.txt"), "not an image");
            await File.WriteAllBytesAsync(Path.Combine(dir, "corrupt.png"), "not a png"u8.ToArray());

            var icons = ImportingIconService(_site, dir);
            Assert.Equal(2, await icons.ImportFromDirectoryAsync()); // txt skipped, corrupt skipped with a warning

            var catalogue = await icons.GetAllAsync();
            var attributed = Assert.Single(catalogue, i => i.Name == "gitlab.example.com");
            Assert.Equal("gitlab.example.com", attributed.MatchUrls); // hostname filename → attribution
            var plain = Assert.Single(catalogue, i => i.Name == "Plain");
            Assert.Equal("", plain.MatchUrls);
            Assert.All(catalogue, i => Assert.Equal("server", i.CreatedBy));

            // Restart (re-run): nothing new.
            Assert.Equal(0, await icons.ImportFromDirectoryAsync());
            Assert.Equal(2, (await icons.GetAllAsync()).Count);

            // An admin deleting a server icon wins over the next import.
            await icons.DeleteAsync(_admin, attributed.Id);
            Assert.Equal(0, await icons.ImportFromDirectoryAsync());
            Assert.Single(await icons.GetAllAsync());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Same_folder_on_two_sites_merges_instead_of_duplicating()
    {
        var dir = Directory.CreateTempSubdirectory("harpo-icons-").FullName;
        try
        {
            await File.WriteAllBytesAsync(Path.Combine(dir, "shared.png"), TinyPng);

            var clock = new ManualTime();
            using var alpha = new TestSite("alpha", clock);
            using var beta = new TestSite("beta", clock);
            Assert.Equal(1, await ImportingIconService(alpha, dir).ImportFromDirectoryAsync());
            Assert.Equal(1, await ImportingIconService(beta, dir).ImportFromDirectoryAsync());

            // Content-hash-derived ids: both sites minted the SAME row, so
            // replication merges rather than duplicating.
            await beta.PullFromAsync(alpha, viaJson: true);
            await alpha.PullFromAsync(beta);
            Assert.Single(await alpha.Icons.GetAllAsync());
            Assert.Single(await beta.Icons.GetAllAsync());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Icons_replicate_between_sites_bytes_intact()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");
        var admin = TestSite.User("root", siteAdmin: true);

        var icon = await alpha.Icons.AddAsync(alice, "GitLab", "image/png", TinyPng, matchUrls: "gitlab.com");
        await beta.PullFromAsync(alpha, viaJson: true); // real wire format: byte[] rides as base64

        var onBeta = await beta.Icons.GetDataAsync(icon.Id);
        Assert.Equal(TinyPng, onBeta!.Value.Data);
        // Attributions replicate too, so URL→icon suggestions work on every site.
        Assert.Equal("gitlab.com", Assert.Single(await beta.Icons.GetAllAsync()).MatchUrls);

        // Tombstones replicate too.
        clock.Advance(TimeSpan.FromMinutes(1));
        await beta.Icons.DeleteAsync(admin, icon.Id);
        await alpha.PullFromAsync(beta);
        Assert.Null(await alpha.Icons.GetDataAsync(icon.Id));
    }
}
