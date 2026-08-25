using Harpo.Data;
using Harpo.Services;

namespace Harpo.Tests;

public class ServiceTests : IDisposable
{
    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _admin = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    [Fact]
    public async Task Creator_becomes_group_admin_and_sees_group()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "Servers etc.");

        var mine = await _site.Groups.GetMyGroupsAsync(_alice);
        var summary = Assert.Single(mine);
        Assert.Equal(group.Id, summary.Group.Id);
        Assert.Equal(GroupRole.Admin, summary.MyRole);
        Assert.Equal(1, summary.MemberCount);
    }

    [Fact]
    public async Task Non_members_cannot_see_or_reveal_group_passwords()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "https://r", "admin", "", "pw1");

        Assert.Empty(await _site.Groups.GetMyGroupsAsync(_bob));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetEntriesAsync(_bob, group.Id));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.RevealPasswordAsync(_bob, entry.Id));
    }

    [Fact]
    public async Task Added_member_gains_access_and_removal_revokes_it()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        await _site.Groups.AddMemberAsync(_alice, group.Id, "BOB", "Bob", GroupRole.Member);
        Assert.Single(await _site.Vault.GetEntriesAsync(_bob, group.Id));

        // Membership is normalized to lower case, and duplicates are rejected.
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member));

        await _site.Groups.RemoveMemberAsync(_alice, group.Id, "bob");
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetEntriesAsync(_bob, group.Id));

        // Re-adding revives the tombstoned membership row.
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);
        Assert.Single(await _site.Vault.GetEntriesAsync(_bob, group.Id));
    }

    [Fact]
    public async Task Viewers_can_read_and_reveal_but_change_nothing()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Viewer);

        // Read side: everything works.
        Assert.Single(await _site.Vault.GetEntriesAsync(_bob, group.Id));
        Assert.Equal("pw1", await _site.Vault.RevealPasswordAsync(_bob, entry.Id));
        Assert.Single(await _site.Vault.GetHistoryAsync(_bob, entry.Id));

        // Write side: everything is denied.
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.CreateEntryAsync(_bob, group.Id, "New", "🔐", "", "", "", "pw"));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.UpdateEntryAsync(_bob, entry.Id, "Renamed", "🌐", "", "", ""));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.ChangePasswordAsync(_bob, entry.Id, "pw2"));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Vault.DeleteEntryAsync(_bob, entry.Id));

        // Promoting a viewer to member unlocks writes.
        await _site.Groups.SetMemberRoleAsync(_alice, group.Id, "bob", GroupRole.Member);
        _site.Time.Advance(TimeSpan.FromMinutes(1));
        await _site.Vault.ChangePasswordAsync(_bob, entry.Id, "pw2");
        Assert.Equal("pw2", await _site.Vault.RevealPasswordAsync(_bob, entry.Id));
    }

    [Fact]
    public async Task Members_cannot_manage_membership_but_admins_can()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);

        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Groups.AddMemberAsync(_bob, group.Id, "carol", "", GroupRole.Member));

        await _site.Groups.SetMemberRoleAsync(_alice, group.Id, "bob", GroupRole.Admin);
        await _site.Groups.AddMemberAsync(_bob, group.Id, "carol", "", GroupRole.Member);
        Assert.Equal(3, (await _site.Groups.GetMembersAsync(_alice, group.Id)).Count);
    }

    [Fact]
    public async Task The_last_admin_cannot_be_removed_or_demoted()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);

        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Groups.RemoveMemberAsync(_alice, group.Id, "alice"));
        await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Groups.SetMemberRoleAsync(_alice, group.Id, "alice", GroupRole.Member));
    }

    [Fact]
    public async Task Site_admin_sees_everything_without_membership()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        var groups = await _site.Groups.GetMyGroupsAsync(_admin);
        Assert.Single(groups);
        Assert.Null(groups[0].MyRole);
        Assert.Single(await _site.Vault.GetEntriesAsync(_admin, group.Id));
        Assert.Equal("pw1", await _site.Vault.RevealPasswordAsync(_admin, entry.Id));
    }

    [Fact]
    public async Task Password_history_records_every_change_with_author()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "first");

        _site.Time.Advance(TimeSpan.FromMinutes(5));
        await _site.Vault.ChangePasswordAsync(_bob, entry.Id, "second");
        _site.Time.Advance(TimeSpan.FromMinutes(5));
        await _site.Vault.ChangePasswordAsync(_alice, entry.Id, "third");

        Assert.Equal("third", await _site.Vault.RevealPasswordAsync(_alice, entry.Id));

        var history = await _site.Vault.GetHistoryAsync(_alice, entry.Id);
        Assert.Equal(3, history.Count);
        Assert.True(history[0].IsCurrent);
        Assert.Equal(new[] { "alice", "bob", "alice" }, history.Select(h => h.CreatedBy));
        Assert.Equal("second", await _site.Vault.RevealRevisionAsync(_alice, entry.Id, history[1].RevisionId));

        // The vault list shows who last changed the password.
        var views = await _site.Vault.GetEntriesAsync(_alice, group.Id);
        Assert.Equal("alice", views[0].PasswordUpdatedBy);
    }

    [Fact]
    public async Task Deleting_entry_hides_it_but_keeps_history()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        await _site.Vault.DeleteEntryAsync(_alice, entry.Id);

        Assert.Empty(await _site.Vault.GetEntriesAsync(_alice, group.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.RevealPasswordAsync(_alice, entry.Id));
        await using var db = _site.Db.CreateDbContext();
        Assert.Single(db.PasswordRevisions.Where(r => r.EntryId == entry.Id));
    }

    [Fact]
    public async Task Deleted_entries_appear_in_trash_and_can_be_restored()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _site.Vault.DeleteEntryAsync(_alice, entry.Id);

        var trash = await _site.Vault.GetDeletedEntriesAsync(_alice, group.Id);
        Assert.Equal(entry.Id, Assert.Single(trash).Id);

        // Viewers have no trash access; restore requires write rights.
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Viewer);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetDeletedEntriesAsync(_bob, group.Id));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.RestoreEntryAsync(_bob, entry.Id));

        await _site.Vault.RestoreEntryAsync(_alice, entry.Id);
        Assert.Single(await _site.Vault.GetEntriesAsync(_alice, group.Id));
        Assert.Empty(await _site.Vault.GetDeletedEntriesAsync(_alice, group.Id));
        Assert.Equal("pw1", await _site.Vault.RevealPasswordAsync(_alice, entry.Id));
    }

    [Fact]
    public async Task Deleted_groups_can_be_restored_by_site_admins_only()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");
        await _site.Groups.DeleteGroupAsync(_alice, group.Id);

        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.GetDeletedGroupsAsync(_alice));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Groups.RestoreGroupAsync(_alice, group.Id));

        var deleted = await _site.Groups.GetDeletedGroupsAsync(_admin);
        Assert.Equal(group.Id, Assert.Single(deleted).Id);

        await _site.Groups.RestoreGroupAsync(_admin, group.Id);
        // The group and its surviving entries come back for its members.
        var mine = await _site.Groups.GetMyGroupsAsync(_alice);
        Assert.Equal(group.Id, Assert.Single(mine).Group.Id);
        Assert.Single(await _site.Vault.GetEntriesAsync(_alice, group.Id));

        // Both restores landed in the audit trail.
        var actions = (await _site.Audit.GetEventsAsync(_admin)).Select(e => e.Action).ToList();
        Assert.Contains(AuditActions.GroupRestore, actions);
    }

    [Fact]
    public async Task Deleted_group_disappears_from_listings()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.DeleteGroupAsync(_alice, group.Id);

        Assert.Empty(await _site.Groups.GetMyGroupsAsync(_alice));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Groups.GetGroupAsync(_alice, group.Id));
    }

    [Fact]
    public async Task Offline_snapshot_contains_only_membership_groups_with_decrypted_passwords()
    {
        var infra = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Router", "🌐", "https://r", "admin", "", "router-pw");
        var hr = await _site.Groups.CreateGroupAsync(_alice, "HR", "");
        await _site.Vault.CreateEntryAsync(_alice, hr.Id, "Payroll", "💳", "", "", "", "payroll-pw");
        await _site.Groups.AddMemberAsync(_alice, infra.Id, "bob", "", GroupRole.Member);

        // Bob is a member of Infra only — HR must not leak into his snapshot.
        var (groups, entries) = await _site.Vault.GetOfflineDataAsync(_bob);
        Assert.Equal("Infra", Assert.Single(groups).Name);
        var entry = Assert.Single(entries);
        Assert.Equal("Router", entry.Name);
        Assert.Equal("router-pw", entry.Password); // decrypted, ready for device re-encryption
        Assert.Equal("alice", entry.PasswordUpdatedBy);
    }

    [Fact]
    public async Task Offline_snapshot_for_site_admin_covers_only_explicit_memberships()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "", "", "pw1");

        // Site admins see everything online, but their offline copy carries only
        // groups they are actually members of — here, none.
        var (groups, entries) = await _site.Vault.GetOfflineDataAsync(_admin);
        Assert.Empty(groups);
        Assert.Empty(entries);
    }

    [Fact]
    public async Task Offline_snapshot_excludes_tombstoned_entries_and_groups()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var kept = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Kept", "🌐", "", "", "", "pw1");
        var deleted = await _site.Vault.CreateEntryAsync(_alice, group.Id, "Gone", "🌐", "", "", "", "pw2");
        await _site.Vault.DeleteEntryAsync(_alice, deleted.Id);

        var (_, entries) = await _site.Vault.GetOfflineDataAsync(_alice);
        Assert.Equal(kept.Id, Assert.Single(entries).Id);

        await _site.Groups.DeleteGroupAsync(_alice, group.Id);
        var (groupsAfter, entriesAfter) = await _site.Vault.GetOfflineDataAsync(_alice);
        Assert.Empty(groupsAfter);
        Assert.Empty(entriesAfter);
    }

    [Fact]
    public async Task Group_updates_require_admin()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);

        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Groups.UpdateGroupAsync(_bob, group.Id, "Renamed", ""));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Groups.DeleteGroupAsync(_bob, group.Id));

        await _site.Groups.UpdateGroupAsync(_admin, group.Id, "Renamed", "by site admin");
        var (updated, _) = await _site.Groups.GetGroupAsync(_alice, group.Id);
        Assert.Equal("Renamed", updated.Name);
    }
}
