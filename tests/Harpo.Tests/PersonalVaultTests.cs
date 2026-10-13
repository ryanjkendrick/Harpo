using Harpo.Data;
using Harpo.Replication;
using Harpo.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Tests;

/// <summary>
/// Personal vaults: one per user, created on first use, visible to its owner
/// alone — the one place a site admin's see-everything right does not reach —
/// and convertible into an ordinary group when the owner has left.
/// </summary>
public class PersonalVaultTests : IDisposable
{
    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _root = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    private static async Task<PasswordEntry> AddPersonalEntryAsync(
        TestSite site, UserContext owner, string name, string password = "pw-1")
    {
        var vault = await site.Groups.EnsurePersonalVaultAsync(owner);
        return await site.Vault.CreateEntryAsync(owner, vault.Id, name, "🔐", "", "me", "", password);
    }

    [Fact]
    public async Task Everyone_gets_one_personal_vault_with_an_id_derived_from_their_name()
    {
        var first = await _site.Groups.EnsurePersonalVaultAsync(_alice);
        var again = await _site.Groups.EnsurePersonalVaultAsync(_alice);

        Assert.Equal(DeterministicGuid.For("personal", "alice"), first.Id);
        Assert.Equal(first.Id, again.Id);
        Assert.True(first.IsPersonal);
        Assert.Equal("alice", first.OwnerUsername);
        Assert.Equal(GroupService.PersonalVaultName, first.Name);

        // Listed first, as its owner's own group, with its one member.
        var listed = await _site.Groups.GetMyGroupsAsync(_alice);
        var summary = Assert.Single(listed);
        Assert.True(summary.Group.IsPersonal);
        Assert.Equal(GroupRole.Admin, summary.MyRole);
        Assert.Equal(1, summary.MemberCount);

        // And fully usable: create, reveal, edit, trash, restore.
        var entry = await _site.Vault.CreateEntryAsync(_alice, first.Id, "Bank", "🏦", "https://bank", "me", "note", "pw-1");
        Assert.Equal("pw-1", await _site.Vault.RevealPasswordAsync(_alice, entry.Id));
        await _site.Vault.UpdateEntryAsync(_alice, entry.Id, "Bank!", "🏦", "", "me", "note");
        await _site.Vault.DeleteEntryAsync(_alice, entry.Id);
        Assert.Single((await _site.Vault.GetDeletedEntriesAsync(_alice, first.Id)).Items);
        await _site.Vault.RestoreEntryAsync(_alice, entry.Id);
        Assert.Equal("Bank!", Assert.Single(await _site.Vault.GetEntriesAsync(_alice, first.Id)).Entry.Name);
    }

    [Fact]
    public async Task Nobody_else_can_open_a_personal_vault_not_even_a_site_admin()
    {
        var entry = await AddPersonalEntryAsync(_site, _alice, "Bank");
        var vault = entry.GroupId;

        foreach (var outsider in new[] { _root, _bob })
        {
            Assert.DoesNotContain(await _site.Groups.GetMyGroupsAsync(outsider), g => g.Group.Id == vault);
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.GetGroupAsync(outsider, vault));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.GetMembersAsync(outsider, vault));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetEntriesAsync(outsider, vault));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetDeletedEntriesAsync(outsider, vault));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.RevealPasswordAsync(outsider, entry.Id));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetHistoryAsync(outsider, entry.Id));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(
                () => _site.Vault.CreateEntryAsync(outsider, vault, "Mine", "🔐", "", "", "", "pw"));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(
                () => _site.Vault.UpdateEntryAsync(outsider, entry.Id, "Renamed", "🔐", "", "", ""));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.DeleteEntryAsync(outsider, entry.Id));
        }

        // A membership row that somehow lands on a personal vault (a tampering
        // peer, say) opens nothing either: the owner check comes first.
        await using (var db = _site.Db.CreateDbContext())
        {
            db.GroupMembers.Add(new GroupMember
            {
                Id = DeterministicGuid.For(vault.ToString("N"), "bob"), GroupId = vault, Username = "bob",
                DisplayName = "Bob", Role = GroupRole.Admin, AddedBy = "bob", CreatedAtUtc = DateTime.UtcNow,
            });
            await db.SaveChangesAsync();
        }
        Assert.DoesNotContain(await _site.Groups.GetMyGroupsAsync(_bob), g => g.Group.Id == vault);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetEntriesAsync(_bob, vault));
        Assert.Empty((await _site.Vault.GetOfflineDataAsync(_bob)).Entries);
    }

    [Fact]
    public async Task A_personal_vault_has_no_settings_or_members_to_manage()
    {
        var vault = await _site.Groups.EnsurePersonalVaultAsync(_alice);

        foreach (var user in new[] { _alice, _root })
        {
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.UpdateGroupAsync(user, vault.Id, "Renamed", ""));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.DeleteGroupAsync(user, vault.Id));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(
                () => _site.Groups.AddMemberAsync(user, vault.Id, "bob", "Bob", GroupRole.Member));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(
                () => _site.Groups.SetMemberRoleAsync(user, vault.Id, "alice", GroupRole.Viewer));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.RemoveMemberAsync(user, vault.Id, "alice"));
        }
        Assert.Equal(GroupService.PersonalVaultName, (await _site.Groups.GetGroupAsync(_alice, vault.Id)).Group.Name);

        // The admin pages that list groups by state leave personal vaults out —
        // even a tombstoned one that arrived by replication cannot be "restored"
        // into an admin's view.
        await using (var db = _site.Db.CreateDbContext())
        {
            db.Groups.Add(new Group
            {
                Id = DeterministicGuid.For("personal", "carol"), Name = GroupService.PersonalVaultName,
                OwnerUsername = "carol", CreatedBy = "carol", CreatedAtUtc = DateTime.UtcNow, IsDeleted = true,
            });
            db.Groups.Add(new Group
            {
                Id = DeterministicGuid.For("personal", "dave"), Name = GroupService.PersonalVaultName,
                OwnerUsername = "dave", CreatedBy = "dave", CreatedAtUtc = DateTime.UtcNow,
            }); // no membership row at all: not "a group without an admin" either
            await db.SaveChangesAsync();
        }
        Assert.Empty((await _site.Groups.GetDeletedGroupsAsync(_root)).Items);
        Assert.Empty(await _site.Groups.GetGroupsWithoutAdminAsync(_root));
        await Assert.ThrowsAsync<VaultNotFoundException>(
            () => _site.Groups.RestoreGroupAsync(_root, DeterministicGuid.For("personal", "carol")));
    }

    [Fact]
    public async Task Audit_events_for_personal_entries_name_no_entry()
    {
        var entry = await AddPersonalEntryAsync(_site, _alice, "Dating app");
        await _site.Vault.RevealPasswordAsync(_alice, entry.Id);
        await _site.Vault.RevealPasswordAsync(_alice, entry.Id, RevealPurpose.Copy);
        await _site.Vault.UpdateEntryAsync(_alice, entry.Id, "Dating app", "🔐", "", "me", "", "JBSWY3DPEHPK3PXP");
        await _site.Vault.GetTotpCodeAsync(_alice, entry.Id);
        var history = await _site.Vault.GetHistoryAsync(_alice, entry.Id);
        await _site.Vault.RevealRevisionAsync(_alice, entry.Id, history[0].RevisionId);
        await _site.Vault.DeleteEntryAsync(_alice, entry.Id);
        await _site.Vault.RestoreEntryAsync(_alice, entry.Id);

        var events = await _site.Audit.GetEventsAsync(_root);
        var personal = events.Where(e => e.Username == "alice").ToList();
        Assert.Equal(7, personal.Count); // reveal, copy, totp.change, totp.reveal, revision.reveal, delete, restore
        Assert.All(personal, e => Assert.Equal(VaultService.PersonalEntryDescription, e.Target));
        Assert.DoesNotContain(events, e => e.Target.Contains("Dating") || e.Detail.Contains("Dating"));
        // Still a full record of what happened.
        Assert.Contains(personal, e => e.Action == AuditActions.PasswordReveal && e.EntryId == entry.Id);
        Assert.Contains(personal, e => e.Action == AuditActions.EntryDelete && e.GroupId == entry.GroupId);
    }

    [Fact]
    public async Task The_health_report_never_shows_someone_elses_personal_entries()
    {
        const string shared = "Same-Pass-Everywhere-1!";
        var infra = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Router", "🌐", "", "", "", shared);
        await AddPersonalEntryAsync(_site, _alice, "My bank", shared);
        await AddPersonalEntryAsync(_site, _alice, "Weak thing", "password");

        // The site admin's report: Infra is in scope, alice's vault is not — its
        // reuse of the router password is a count, its weak password is nobody's business.
        var admin = await _site.Health.GetReportAsync(_root);
        Assert.NotNull(admin);
        Assert.Equal(1, admin.Analyzed);
        Assert.Empty(admin.Weak);
        var cluster = Assert.Single(admin.Reused);
        Assert.Equal("Router", Assert.Single(cluster.Entries).Name);
        Assert.Equal(1, cluster.HiddenCount);

        // Alice administers Infra and owns the vault: all three are hers to see.
        var owner = await _site.Health.GetReportAsync(_alice);
        Assert.NotNull(owner);
        Assert.Equal(3, owner.Analyzed);
        Assert.Equal("Weak thing", Assert.Single(owner.Weak).Name);
        Assert.Equal(new[] { "Router", "My bank" }, Assert.Single(owner.Reused).Entries.Select(e => e.Name).OrderByDescending(n => n));
    }

    [Fact]
    public async Task The_offline_snapshot_carries_the_owners_personal_vault()
    {
        var entry = await AddPersonalEntryAsync(_site, _alice, "Bank", "bank-pw");

        var (groups, entries) = await _site.Vault.GetOfflineDataAsync(_alice);
        Assert.Equal(GroupService.PersonalVaultName, Assert.Single(groups).Name);
        Assert.Equal("bank-pw", Assert.Single(entries).Password);
        Assert.Equal(entry.Id, entries[0].Id);

        await _site.Groups.EnsurePersonalVaultAsync(_root);
        Assert.Empty((await _site.Vault.GetOfflineDataAsync(_root)).Entries);
    }

    [Fact]
    public async Task Personal_vaults_replicate_and_stay_personal_on_the_other_site()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);

        var entry = await AddPersonalEntryAsync(alpha, _alice, "Bank", "bank-pw");
        await beta.PullFromAsync(alpha, viaJson: true);

        Assert.Equal("bank-pw", await beta.Vault.RevealPasswordAsync(_alice, entry.Id));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => beta.Vault.GetEntriesAsync(_root, entry.GroupId));
        Assert.DoesNotContain(await beta.Groups.GetMyGroupsAsync(_root), g => g.Group.Id == entry.GroupId);
        Assert.Equal(entry.GroupId, (await beta.Groups.EnsurePersonalVaultAsync(_alice)).Id); // no second vault
    }

    [Fact]
    public async Task Two_sites_that_first_see_the_same_person_while_apart_end_up_with_one_vault()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);

        var onAlpha = await AddPersonalEntryAsync(alpha, _bob, "From alpha");
        clock.Advance(TimeSpan.FromSeconds(1));
        var onBeta = await AddPersonalEntryAsync(beta, _bob, "From beta");
        Assert.Equal(onAlpha.GroupId, onBeta.GroupId);

        await alpha.PullFromAsync(beta, viaJson: true);
        await beta.PullFromAsync(alpha, viaJson: true);

        foreach (var site in new[] { alpha, beta })
        {
            var vault = Assert.Single(await site.Groups.GetMyGroupsAsync(_bob));
            Assert.True(vault.Group.IsPersonal);
            Assert.Equal(1, vault.MemberCount);
            Assert.Equal(2, (await site.Vault.GetEntriesAsync(_bob, vault.Group.Id)).Count);
        }
    }

    [Fact]
    public async Task A_site_admin_can_take_a_personal_vault_over_and_its_owner_gets_a_fresh_one()
    {
        var entry = await AddPersonalEntryAsync(_site, _alice, "Payroll portal", "payroll-pw");
        var oldVault = entry.GroupId;
        var listed = Assert.Single(await _site.Groups.GetPersonalVaultsAsync(_root));
        Assert.Equal("alice", listed.Group.OwnerUsername);
        Assert.Equal("Alice", listed.OwnerDisplayName);
        Assert.Equal(1, listed.EntryCount);

        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.TakeOverPersonalVaultAsync(_bob, oldVault, ""));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.GetPersonalVaultsAsync(_alice));

        var group = await _site.Groups.TakeOverPersonalVaultAsync(_root, oldVault, "  ");
        Assert.Equal("alice's personal vault", group.Name);
        Assert.False(group.IsPersonal);

        // Now an ordinary group: the admin reads it, alice is still in it, and
        // the trail says what happened and to whom.
        Assert.Equal("payroll-pw", await _site.Vault.RevealPasswordAsync(_root, entry.Id));
        var members = await _site.Groups.GetMembersAsync(_root, oldVault);
        Assert.Equal(new[] { "alice", "root" }, members.Select(m => m.Username));
        Assert.All(members, m => Assert.Equal(GroupRole.Admin, m.Role));
        var aliceSees = Assert.Single(await _site.Groups.GetMyGroupsAsync(_alice), g => g.Group.Id == oldVault);
        Assert.False(aliceSees.Group.IsPersonal);
        var takeover = Assert.Single(await _site.Audit.GetEventsAsync(_root), e => e.Action == AuditActions.PersonalTakeover);
        Assert.Equal("root", takeover.Username);
        Assert.Equal("alice's personal vault", takeover.Target);
        Assert.Equal("was the personal vault of alice", takeover.Detail);
        Assert.Equal(oldVault, takeover.GroupId);
        Assert.Empty(await _site.Groups.GetPersonalVaultsAsync(_root));
        await Assert.ThrowsAsync<VaultValidationException>(() => _site.Groups.TakeOverPersonalVaultAsync(_root, oldVault, ""));

        // Alice's next visit: a new, empty personal vault under the next derived id.
        var fresh = await _site.Groups.EnsurePersonalVaultAsync(_alice);
        Assert.NotEqual(oldVault, fresh.Id);
        Assert.Equal(DeterministicGuid.For("personal", "alice", "2"), fresh.Id);
        Assert.True(fresh.IsPersonal);
        Assert.Empty(await _site.Vault.GetEntriesAsync(_alice, fresh.Id));
        Assert.Equal(fresh.Id, (await _site.Groups.EnsurePersonalVaultAsync(_alice)).Id);
        var groups = await _site.Groups.GetMyGroupsAsync(_alice);
        Assert.Equal(2, groups.Count);
        Assert.Equal(fresh.Id, groups[0].Group.Id); // personal first
    }

    [Fact]
    public async Task A_taken_over_vault_can_be_renamed_and_managed_like_any_group()
    {
        var entry = await AddPersonalEntryAsync(_site, _alice, "Portal");
        await _site.Groups.TakeOverPersonalVaultAsync(_root, entry.GroupId, "Alice's leftovers");
        await _site.Groups.UpdateGroupAsync(_root, entry.GroupId, "Finance leftovers", "from alice");
        await _site.Groups.AddMemberAsync(_root, entry.GroupId, "bob", "Bob", GroupRole.Viewer);
        Assert.Equal("pw-1", await _site.Vault.RevealPasswordAsync(_bob, entry.Id));
        await _site.Groups.DeleteGroupAsync(_root, entry.GroupId);
        Assert.Single((await _site.Groups.GetDeletedGroupsAsync(_root)).Items);
    }
}

public class PersonalVaultConcurrencyTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("harpo-personal-").FullName;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task Two_pages_opening_at_once_create_one_personal_vault()
    {
        var hook = new CommandHook();
        using var site = new TestSite("a", databasePath: Path.Combine(_dir, "a.db"), interceptors: hook);
        var alice = TestSite.User("alice");

        // The first call is held just before its insert; the second must wait
        // for it rather than also find nothing and insert the same row.
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        hook.Before(sql => sql.Contains("INSERT INTO \"Groups\""), async () =>
        {
            reached.SetResult();
            await release.Task;
        });
        var first = Task.Run(() => site.Groups.EnsurePersonalVaultAsync(alice));
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var second = Task.Run(() => site.Groups.EnsurePersonalVaultAsync(alice));
        await Task.Delay(500);
        release.SetResult();

        var ids = await Task.WhenAll(first, second);
        Assert.Equal(ids[0].Id, ids[1].Id);
        await using var db = site.Db.CreateDbContext();
        Assert.Equal(1, await db.Groups.CountAsync(g => g.OwnerUsername == "alice"));
        Assert.Equal(1, await db.GroupMembers.CountAsync(m => m.GroupId == ids[0].Id));
    }
}

public class PersonalVaultUpgradeTests
{
    [Fact]
    public async Task A_site_that_received_a_vault_while_on_an_older_version_marks_it_personal_after_upgrading()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");
        var root = TestSite.User("root", siteAdmin: true);

        var vault = await alpha.Groups.EnsurePersonalVaultAsync(alice);
        await alpha.Vault.CreateEntryAsync(alice, vault.Id, "Bank", "🏦", "", "", "", "pw");

        // Beta on 0.4.0: it stores the group without the owner mark, because it
        // has no column for one. Reproduced by dropping the property from the wire.
        var request = new PullRequest { SiteId = "beta", Vector = await beta.Engine.GetVectorAsync() };
        var json = System.Text.Json.JsonSerializer.Serialize(await alpha.Engine.BuildResponseAsync(request), Web);
        var stripped = System.Text.RegularExpressions.Regex.Replace(json, "\"ownerUsername\":\"[^\"]*\",?", "");
        Assert.DoesNotContain("ownerUsername", stripped);
        await beta.Engine.ApplyAsync(System.Text.Json.JsonSerializer.Deserialize<PullResponse>(stripped, Web)!);
        Assert.Contains(await beta.Groups.GetMyGroupsAsync(root), g => g.Group.Id == vault.Id); // the gap
        long seqBefore;
        await using (var db = beta.Db.CreateDbContext())
        {
            seqBefore = (await db.Groups.SingleAsync(g => g.Id == vault.Id)).OriginSeq;
        }

        // Beta upgrades: nothing new on alpha, so an ordinary pull brings nothing...
        await beta.PullFromAsync(alpha, viaJson: true);
        Assert.Contains(await beta.Groups.GetMyGroupsAsync(root), g => g.Group.Id == vault.Id);

        // ...which is why the first start after the upgrade forgets the cursors.
        await UpgradeResync.EnsureAsync(beta.Db, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        await beta.PullFromAsync(alpha, viaJson: true);

        Assert.DoesNotContain(await beta.Groups.GetMyGroupsAsync(root), g => g.Group.Id == vault.Id);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => beta.Vault.GetEntriesAsync(root, vault.Id));
        Assert.Equal("Bank", Assert.Single(await beta.Vault.GetEntriesAsync(alice, vault.Id)).Entry.Name);
        await using (var check = beta.Db.CreateDbContext())
        {
            var healed = await check.Groups.SingleAsync(g => g.Id == vault.Id);
            Assert.Equal("alice", healed.OwnerUsername);
            Assert.Equal(seqBefore, healed.OriginSeq); // healed in place, not re-stamped
            Assert.Equal("alpha", healed.OriginSiteId);
            Assert.Single(await check.SiteSettings.Where(s => s.Id == UpgradeResync.MarkerId).ToListAsync());
        }

        // Second start: the marker is set, the cursors stay, nothing is fetched again.
        var cursorsBefore = await beta.Engine.GetVectorAsync();
        await UpgradeResync.EnsureAsync(beta.Db, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        Assert.Equal(cursorsBefore, await beta.Engine.GetVectorAsync());
    }

    [Fact]
    public async Task A_vault_taken_over_elsewhere_is_not_re_marked_by_an_older_copy()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");
        var root = TestSite.User("root", siteAdmin: true);

        var vault = await alpha.Groups.EnsurePersonalVaultAsync(alice);
        await beta.PullFromAsync(alpha, viaJson: true);
        clock.Advance(TimeSpan.FromSeconds(1));
        await beta.Groups.TakeOverPersonalVaultAsync(root, vault.Id, "");

        // Alpha still holds the personal version; beta's newer takeover must win
        // on alpha, and alpha's older copy must not restore the mark on beta.
        await alpha.PullFromAsync(beta, viaJson: true);
        await UpgradeResync.EnsureAsync(beta.Db, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        await beta.PullFromAsync(alpha, viaJson: true);
        foreach (var site in new[] { alpha, beta })
        {
            var group = (await site.Groups.GetGroupAsync(root, vault.Id)).Group;
            Assert.False(group.IsPersonal);
            Assert.Equal("alice's personal vault", group.Name);
        }
    }

    private static readonly System.Text.Json.JsonSerializerOptions Web = new(System.Text.Json.JsonSerializerDefaults.Web);
}
