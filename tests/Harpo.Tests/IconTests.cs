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

    [Fact]
    public async Task Icons_replicate_between_sites_bytes_intact()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");
        var admin = TestSite.User("root", siteAdmin: true);

        var icon = await alpha.Icons.AddAsync(alice, "GitLab", "image/png", TinyPng);
        await beta.PullFromAsync(alpha, viaJson: true); // real wire format: byte[] rides as base64

        var onBeta = await beta.Icons.GetDataAsync(icon.Id);
        Assert.Equal(TinyPng, onBeta!.Value.Data);

        // Tombstones replicate too.
        clock.Advance(TimeSpan.FromMinutes(1));
        await beta.Icons.DeleteAsync(admin, icon.Id);
        await alpha.PullFromAsync(beta);
        Assert.Null(await alpha.Icons.GetDataAsync(icon.Id));
    }
}
