using Harpo.Data;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

public class AuditTests : IDisposable
{
    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _admin = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    private async Task<List<AuditEvent>> AllEventsAsync()
    {
        await using var db = _site.Db.CreateDbContext();
        return await db.AuditEvents.OrderBy(e => e.OccurredAtUtc).ToListAsync();
    }

    [Fact]
    public async Task Reveal_copy_and_history_reveal_are_recorded_with_target_names()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _site.Vault.ChangePasswordAsync(_alice, entry.Id, "pw2");

        await _site.Vault.RevealPasswordAsync(_alice, entry.Id);
        await _site.Vault.RevealPasswordAsync(_alice, entry.Id, RevealPurpose.Copy);
        var history = await _site.Vault.GetHistoryAsync(_alice, entry.Id);
        await _site.Vault.RevealRevisionAsync(_alice, entry.Id, history[1].RevisionId);

        var events = await AllEventsAsync();
        Assert.Equal(
            new[] { AuditActions.PasswordReveal, AuditActions.PasswordCopy, AuditActions.RevisionReveal },
            events.Select(e => e.Action));
        Assert.All(events, e =>
        {
            Assert.Equal("alice", e.Username);
            Assert.Equal("Router (Infra)", e.Target);
            Assert.Equal(entry.Id, e.EntryId);
            Assert.Equal(group.Id, e.GroupId);
        });
        Assert.Contains("by alice", events[2].Detail);
    }

    [Fact]
    public async Task Membership_and_deletion_changes_are_recorded()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);
        await _site.Groups.SetMemberRoleAsync(_alice, group.Id, "bob", GroupRole.Admin);
        await _site.Groups.RemoveMemberAsync(_alice, group.Id, "bob");
        await _site.Vault.DeleteEntryAsync(_alice, entry.Id);
        await _site.Groups.DeleteGroupAsync(_alice, group.Id);

        var actions = (await AllEventsAsync()).Select(e => e.Action).ToList();
        Assert.Equal(
            new[]
            {
                AuditActions.MemberAdd, AuditActions.MemberRole, AuditActions.MemberRemove,
                AuditActions.EntryDelete, AuditActions.GroupDelete,
            },
            actions);
    }

    [Fact]
    public async Task Disabled_audit_records_nothing()
    {
        var disabledAudit = new AuditService(
            _site.Db, Options.Create(new AuditOptions { Enabled = false }), _site.Time,
            NullLogger<AuditService>.Instance);
        var vault = new VaultService(_site.Db, _site.Crypto, _site.Time, NullLogger<VaultService>.Instance, disabledAudit);

        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await vault.RevealPasswordAsync(_alice, entry.Id);
        await vault.DeleteEntryAsync(_alice, entry.Id);

        Assert.Empty(await AllEventsAsync());
    }

    [Fact]
    public async Task Only_site_admins_can_read_the_trail()
    {
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Audit.GetEventsAsync(_alice));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Audit.CountAsync(_bob));
        Assert.Empty(await _site.Audit.GetEventsAsync(_admin));
    }

    [Fact]
    public async Task Events_page_newest_first_with_before_cursor()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        for (var i = 0; i < 3; i++)
        {
            _site.Time.Advance(TimeSpan.FromMinutes(1));
            await _site.Vault.RevealPasswordAsync(_alice, entry.Id);
        }

        var firstPage = await _site.Audit.GetEventsAsync(_admin, take: 2);
        Assert.Equal(2, firstPage.Count);
        Assert.True(firstPage[0].OccurredAtUtc >= firstPage[1].OccurredAtUtc);

        var secondPage = await _site.Audit.GetEventsAsync(_admin, beforeUtc: firstPage[^1].OccurredAtUtc, take: 2);
        Assert.Single(secondPage);
    }

    [Fact]
    public async Task Retention_purges_only_expired_events()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        await _site.Vault.RevealPasswordAsync(_alice, entry.Id); // old event
        _site.Time.Advance(TimeSpan.FromDays(400));
        await _site.Vault.RevealPasswordAsync(_alice, entry.Id); // fresh event

        var purged = await _site.Audit.PurgeExpiredAsync();
        Assert.Equal(1, purged);
        var remaining = await AllEventsAsync();
        Assert.Single(remaining);

        // Purged rows do not come back from a peer: its vector already covers them.
        Assert.Equal(0, await _site.Audit.PurgeExpiredAsync());
    }

    [Fact]
    public async Task Audit_events_replicate_between_sites()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");
        var admin = TestSite.User("root", siteAdmin: true);

        var group = await alpha.Groups.CreateGroupAsync(alice, "Infra", "");
        var entry = await alpha.Vault.CreateEntryAsync(alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await alpha.Vault.RevealPasswordAsync(alice, entry.Id);

        await beta.PullFromAsync(alpha, viaJson: true);

        var onBeta = await beta.Audit.GetEventsAsync(admin);
        var reveal = Assert.Single(onBeta, e => e.Action == AuditActions.PasswordReveal);
        Assert.Equal("alpha", reveal.OriginSiteId);
        Assert.Equal("Router (Infra)", reveal.Target);

        // Idempotent: pulling again duplicates nothing.
        await beta.PullFromAsync(alpha);
        Assert.Single(await beta.Audit.GetEventsAsync(admin), e => e.Action == AuditActions.PasswordReveal);
    }
}
