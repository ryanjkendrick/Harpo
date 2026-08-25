using Harpo.Data;
using Harpo.Replication;
using Harpo.Services;

namespace Harpo.Tests;

public class ReplicationTests : IDisposable
{
    // One shared clock across sites keeps cause-and-effect ordering sane in tests.
    private readonly ManualTime _clock = new();
    private readonly TestSite _alpha;
    private readonly TestSite _beta;
    private readonly UserContext _alice = TestSite.User("alice");

    public ReplicationTests()
    {
        _alpha = new TestSite("alpha", _clock);
        _beta = new TestSite("beta", _clock);
    }

    public void Dispose()
    {
        _alpha.Dispose();
        _beta.Dispose();
    }

    [Fact]
    public async Task Groups_entries_and_passwords_replicate_between_sites()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "Shared infra");
        var entry = await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "https://router", "admin", "", "pw1");

        await _beta.PullFromAsync(_alpha, viaJson: true);

        var groups = await _beta.Groups.GetMyGroupsAsync(_alice);
        var summary = Assert.Single(groups);
        Assert.Equal("Infra", summary.Group.Name);
        Assert.Equal(GroupRole.Admin, summary.MyRole);

        var entries = await _beta.Vault.GetEntriesAsync(_alice, group.Id);
        Assert.Single(entries);
        // Ciphertext replicated as-is decrypts on the other site (shared master key).
        Assert.Equal("pw1", await _beta.Vault.RevealPasswordAsync(_alice, entry.Id));
    }

    [Fact]
    public async Task Sync_is_idempotent_and_vector_prevents_re_sending()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _beta.PullFromAsync(_alpha);

        // A second pull with the advanced vector returns nothing.
        var request = new PullRequest { SiteId = "beta", Vector = await _beta.Engine.GetVectorAsync() };
        var response = await _alpha.Engine.BuildResponseAsync(request);
        Assert.Equal(0, response.RowCount);
        Assert.False(response.HasMore);

        // Re-applying an old response changes nothing.
        var fullResponse = await _alpha.Engine.BuildResponseAsync(new PullRequest { SiteId = "beta" });
        Assert.True(fullResponse.RowCount > 0);
        await _beta.Engine.ApplyAsync(fullResponse);
        Assert.Single(await _beta.Groups.GetMyGroupsAsync(_alice));
    }

    [Fact]
    public async Task Newest_edit_wins_on_both_sites()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _beta.PullFromAsync(_alpha);

        // Divergent edits: alpha renames first, beta renames later (newer clock).
        _clock.Advance(TimeSpan.FromMinutes(1));
        await _alpha.Vault.UpdateEntryAsync(_alice, entry.Id, "Alpha Name", "🌐", "", "", "");
        _clock.Advance(TimeSpan.FromMinutes(1));
        await _beta.Vault.UpdateEntryAsync(_alice, entry.Id, "Beta Name", "🌐", "", "", "");

        await _beta.PullFromAsync(_alpha);
        await _alpha.PullFromAsync(_beta);

        Assert.Equal("Beta Name", (await _alpha.Vault.GetEntriesAsync(_alice, group.Id))[0].Entry.Name);
        Assert.Equal("Beta Name", (await _beta.Vault.GetEntriesAsync(_alice, group.Id))[0].Entry.Name);
    }

    [Fact]
    public async Task Simultaneous_edits_converge_deterministically()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _beta.PullFromAsync(_alpha);

        // Same timestamp on both sites — the tie-break (origin site id) must pick one winner everywhere.
        _clock.Advance(TimeSpan.FromMinutes(1));
        await _alpha.Vault.UpdateEntryAsync(_alice, entry.Id, "Alpha Name", "🌐", "", "", "");
        await _beta.Vault.UpdateEntryAsync(_alice, entry.Id, "Beta Name", "🌐", "", "", "");

        await _beta.PullFromAsync(_alpha);
        await _alpha.PullFromAsync(_beta);

        var nameOnAlpha = (await _alpha.Vault.GetEntriesAsync(_alice, group.Id))[0].Entry.Name;
        var nameOnBeta = (await _beta.Vault.GetEntriesAsync(_alice, group.Id))[0].Entry.Name;
        Assert.Equal(nameOnAlpha, nameOnBeta);
        Assert.Equal("Beta Name", nameOnAlpha); // "beta" > "alpha" ordinally
    }

    [Fact]
    public async Task Concurrent_password_changes_both_survive_in_history()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _beta.PullFromAsync(_alpha);

        _clock.Advance(TimeSpan.FromMinutes(1));
        await _alpha.Vault.ChangePasswordAsync(_alice, entry.Id, "alpha-pw");
        _clock.Advance(TimeSpan.FromMinutes(1));
        await _beta.Vault.ChangePasswordAsync(_alice, entry.Id, "beta-pw");

        await _beta.PullFromAsync(_alpha);
        await _alpha.PullFromAsync(_beta);

        foreach (var site in new[] { _alpha, _beta })
        {
            var history = await site.Vault.GetHistoryAsync(_alice, entry.Id);
            Assert.Equal(3, history.Count); // nothing lost
            Assert.Equal("beta-pw", await site.Vault.RevealPasswordAsync(_alice, entry.Id));
        }
    }

    [Fact]
    public async Task Deletions_replicate_as_tombstones()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _beta.PullFromAsync(_alpha);

        _clock.Advance(TimeSpan.FromMinutes(1));
        await _alpha.Vault.DeleteEntryAsync(_alice, entry.Id);
        await _beta.PullFromAsync(_alpha);
        Assert.Empty(await _beta.Vault.GetEntriesAsync(_alice, group.Id));

        _clock.Advance(TimeSpan.FromMinutes(1));
        await _beta.Groups.DeleteGroupAsync(_alice, group.Id);
        await _alpha.PullFromAsync(_beta);
        Assert.Empty(await _alpha.Groups.GetMyGroupsAsync(_alice));
    }

    [Fact]
    public async Task Same_member_added_on_both_sites_merges_into_one_row()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _beta.PullFromAsync(_alpha);

        _clock.Advance(TimeSpan.FromMinutes(1));
        await _alpha.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Member);
        await _beta.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bobby", GroupRole.Admin);

        await _beta.PullFromAsync(_alpha);
        await _alpha.PullFromAsync(_beta);

        var membersOnAlpha = await _alpha.Groups.GetMembersAsync(_alice, group.Id);
        var membersOnBeta = await _beta.Groups.GetMembersAsync(_alice, group.Id);
        Assert.Equal(2, membersOnAlpha.Count); // alice + exactly one bob
        Assert.Equal(2, membersOnBeta.Count);
        var bobA = membersOnAlpha.Single(m => m.Username == "bob");
        var bobB = membersOnBeta.Single(m => m.Username == "bob");
        Assert.Equal(bobA.Role, bobB.Role);
        Assert.Equal(bobA.DisplayName, bobB.DisplayName);
    }

    [Fact]
    public async Task Changes_flow_transitively_through_an_intermediate_site()
    {
        using var gamma = new TestSite("gamma", _clock);

        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        // Topology: alpha ↔ beta ↔ gamma (alpha and gamma never talk directly).
        await _beta.PullFromAsync(_alpha);
        await gamma.PullFromAsync(_beta);

        var entries = await gamma.Vault.GetEntriesAsync(_alice, group.Id);
        Assert.Single(entries);
        Assert.Equal("alpha", entries[0].Entry.OriginSiteId);
    }

    [Fact]
    public async Task Large_change_sets_paginate_with_contiguous_windows()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw-0");
        for (var i = 1; i <= 150; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(1));
            await _alpha.Vault.ChangePasswordAsync(_alice, entry.Id, $"pw-{i}");
        }

        // Batch size is 100 in tests, so this needs several HasMore rounds.
        await _beta.PullFromAsync(_alpha);

        var history = await _beta.Vault.GetHistoryAsync(_alice, entry.Id);
        Assert.Equal(151, history.Count);
        Assert.Equal("pw-150", await _beta.Vault.RevealPasswordAsync(_alice, entry.Id));
    }

    [Fact]
    public async Task Restored_site_recovers_its_own_rows_and_counter_from_peers()
    {
        var group = await _alpha.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _alpha.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _beta.PullFromAsync(_alpha);

        // Alpha loses its database and comes back empty with the same site id.
        using var alphaRestored = new TestSite("alpha", _clock);
        await alphaRestored.PullFromAsync(_beta);

        Assert.Single(await alphaRestored.Groups.GetMyGroupsAsync(_alice));

        // Its sequence counter must have jumped past everything already in the mesh,
        // so new local writes don't reuse (site, seq) pairs.
        _clock.Advance(TimeSpan.FromMinutes(1));
        var group2 = await alphaRestored.Groups.CreateGroupAsync(_alice, "New Group", "");
        await using var db = alphaRestored.Db.CreateDbContext();
        var newRow = db.Groups.Single(g => g.Id == group2.Id);
        var maxOldAlphaSeq = db.PasswordRevisions.Where(r => r.OriginSiteId == "alpha").Max(r => r.OriginSeq);
        Assert.True(newRow.OriginSeq > maxOldAlphaSeq);
    }

    [Fact]
    public void Conflict_resolution_is_a_total_order()
    {
        var older = new Group { UpdatedAtUtc = new DateTime(2026, 1, 1), OriginSiteId = "a", OriginSeq = 5 };
        var newer = new Group { UpdatedAtUtc = new DateTime(2026, 1, 2), OriginSiteId = "a", OriginSeq = 6 };
        Assert.True(ReplicationEngine.IncomingWins(newer, older));
        Assert.False(ReplicationEngine.IncomingWins(older, newer));

        var tieA = new Group { UpdatedAtUtc = new DateTime(2026, 1, 1), OriginSiteId = "a", OriginSeq = 5 };
        var tieB = new Group { UpdatedAtUtc = new DateTime(2026, 1, 1), OriginSiteId = "b", OriginSeq = 3 };
        Assert.True(ReplicationEngine.IncomingWins(tieB, tieA));
        Assert.False(ReplicationEngine.IncomingWins(tieA, tieB));

        // Identical stamps: no-op.
        Assert.False(ReplicationEngine.IncomingWins(tieA, tieA));
    }
}
