using System.Diagnostics;
using Harpo.Data;
using Harpo.Import;
using Harpo.Replication;
using Harpo.Security;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;
using Xunit.Abstractions;

namespace Harpo.Tests;

/// <summary>
/// Purge: a deleted entry (or a deleted group) erased for good — its whole
/// password history, notes, 2FA secret, name, URL, username and icon — leaving
/// only a blank tombstone that replicates, wins over every version that is not
/// purged, and makes every site erase its own copy.
/// </summary>
public class PurgeTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ManualTime _clock = new();
    private readonly TestSite _site;
    // bob creates the shared group (its admin); carol is a member, erin a viewer.
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _carol = TestSite.User("carol");
    private readonly UserContext _erin = TestSite.User("erin");
    private readonly UserContext _dave = TestSite.User("dave");
    private readonly UserContext _root = TestSite.User("root", siteAdmin: true);

    public PurgeTests(ITestOutputHelper output)
    {
        _output = output;
        _site = NewSite("alpha");
    }

    public void Dispose() => _site.Dispose();

    private TestSite NewSite(string id, string? databasePath = null)
    {
        var site = new TestSite(id, _clock, databasePath: databasePath);
        site.DevDirectory.DevUsers.Add(new DevAuthOptions.DevUser { Username = "erin", Password = "erin" });
        site.DevDirectory.DevUsers.Add(new DevAuthOptions.DevUser { Username = "dave", Password = "dave" });
        return site;
    }

    private async Task<Group> SharedGroupAsync(TestSite site, string name = "Infra")
    {
        var group = await site.Groups.CreateGroupAsync(_bob, name, "the shared one");
        await site.Groups.AddMemberAsync(_bob, group.Id, "carol", "Carol", GroupRole.Member);
        await site.Groups.AddMemberAsync(_bob, group.Id, "erin", "Erin", GroupRole.Viewer);
        return group;
    }

    /// <summary>An entry with notes, a 2FA secret and three passwords in its history.</summary>
    private async Task<PasswordEntry> RichEntryAsync(TestSite site, UserContext user, Guid groupId, string name = "Router")
    {
        var entry = await site.Vault.CreateEntryAsync(user, groupId, name, "🌐", "https://router.example", "admin",
            "recovery codes 1111-2222", "first-password", totpSecret: "JBSWY3DPEHPK3PXP");
        _clock.Advance(TimeSpan.FromMinutes(1));
        await site.Vault.ChangePasswordAsync(user, entry.Id, "second-password");
        _clock.Advance(TimeSpan.FromMinutes(1));
        await site.Vault.ChangePasswordAsync(user, entry.Id, "third-password");
        _clock.Advance(TimeSpan.FromMinutes(1));
        return entry;
    }

    private static async Task<PasswordEntry> RawEntryAsync(TestSite site, Guid id)
    {
        await using var db = site.Db.CreateDbContext();
        return await db.PasswordEntries.AsNoTracking().SingleAsync(e => e.Id == id);
    }

    private static async Task<int> RevisionCountAsync(TestSite site, Guid entryId)
    {
        await using var db = site.Db.CreateDbContext();
        return await db.PasswordRevisions.CountAsync(r => r.EntryId == entryId);
    }

    private static async Task<List<AuditEvent>> AuditAsync(TestSite site)
    {
        await using var db = site.Db.CreateDbContext();
        return await db.AuditEvents.AsNoTracking().OrderBy(e => e.OccurredAtUtc).ThenBy(e => e.OriginSeq).ToListAsync();
    }

    private static void AssertErased(PasswordEntry entry)
    {
        Assert.True(entry.IsPurged);
        Assert.True(entry.IsDeleted);
        Assert.Equal("", entry.Name);
        Assert.Equal("", entry.Icon);
        Assert.Equal("", entry.Url);
        Assert.Equal("", entry.Username);
        Assert.Equal("", entry.EncryptedNotes);
        Assert.Null(entry.EncryptedTotpSecret);
    }

    // ---- what a purge erases ----

    [Fact]
    public async Task Purging_erases_the_whole_history_notes_2fa_secret_and_every_field()
    {
        var group = await SharedGroupAsync(_site);
        var entry = await RichEntryAsync(_site, _bob, group.Id);
        var keep = await RichEntryAsync(_site, _bob, group.Id, "Switch");
        Assert.Equal(3, await RevisionCountAsync(_site, entry.Id));
        await _site.Vault.DeleteEntryAsync(_bob, entry.Id);
        await _site.Vault.DeleteEntryAsync(_bob, keep.Id);
        var before = await RawEntryAsync(_site, entry.Id);

        await _site.Purge.PurgeEntryAsync(_bob, entry.Id);

        var after = await RawEntryAsync(_site, entry.Id);
        AssertErased(after);
        Assert.Equal(group.Id, after.GroupId);
        Assert.Equal("bob", after.UpdatedBy);
        // A fresh write, so it replicates.
        Assert.True(after.OriginSeq > before.OriginSeq);
        // No revision row is left: no ciphertext, fingerprint or strength.
        Assert.Equal(0, await RevisionCountAsync(_site, entry.Id));

        // Gone from the recycle bin, and cannot be restored, edited or revealed.
        var bin = await _site.Vault.GetDeletedEntriesAsync(_bob, group.Id);
        Assert.Equal(keep.Id, Assert.Single(bin.Items).Id);
        Assert.Equal(1, bin.Total);
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.RestoreEntryAsync(_bob, entry.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.RevealPasswordAsync(_bob, entry.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Vault.GetHistoryAsync(_bob, entry.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(
            () => _site.Vault.UpdateEntryAsync(_bob, entry.Id, "Back", "🌐", "", "", ""));
        // Purging again finds nothing to purge.
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Purge.PurgeEntryAsync(_bob, entry.Id));

        // The other deleted entry is untouched and still restorable.
        Assert.Equal(3, await RevisionCountAsync(_site, keep.Id));
        await _site.Vault.RestoreEntryAsync(_bob, keep.Id);
        Assert.Equal("third-password", await _site.Vault.RevealPasswordAsync(_bob, keep.Id));
        Assert.False(await _site.Scrubber.IsPendingAsync()); // the file was rewritten after the purge
    }

    [Fact]
    public async Task Only_a_deleted_entry_can_be_purged()
    {
        var group = await SharedGroupAsync(_site);
        var entry = await RichEntryAsync(_site, _bob, group.Id);

        var refused = await Assert.ThrowsAsync<VaultValidationException>(() => _site.Purge.PurgeEntryAsync(_bob, entry.Id));
        Assert.Contains("deleted", refused.Message);
        Assert.Equal("Router", (await RawEntryAsync(_site, entry.Id)).Name);
        Assert.Equal(3, await RevisionCountAsync(_site, entry.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Purge.PurgeEntryAsync(_bob, Guid.NewGuid()));

        // Emptying the bin leaves live entries alone.
        Assert.Equal(0, await _site.Purge.EmptyRecycleBinAsync(_bob, group.Id));
        Assert.Equal("third-password", await _site.Vault.RevealPasswordAsync(_bob, entry.Id));
    }

    // ---- who may purge ----

    [Fact]
    public async Task Viewers_members_and_outsiders_cannot_purge_group_admins_and_site_admins_can()
    {
        var group = await SharedGroupAsync(_site);
        var entries = new List<PasswordEntry>();
        for (var i = 0; i < 3; i++)
        {
            var e = await _site.Vault.CreateEntryAsync(_bob, group.Id, $"Entry {i}", "🔐", "", "", "", "pw");
            await _site.Vault.DeleteEntryAsync(_bob, e.Id);
            entries.Add(e);
        }

        foreach (var refused in new[] { _erin, _carol, _dave })
        {
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Purge.PurgeEntryAsync(refused, entries[0].Id));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Purge.EmptyRecycleBinAsync(refused, group.Id));
        }
        // A member can still delete and restore (the everyday, undoable part).
        await _site.Vault.RestoreEntryAsync(_carol, entries[2].Id);
        await _site.Vault.DeleteEntryAsync(_carol, entries[2].Id);
        Assert.Equal(3, (await _site.Vault.GetDeletedEntriesAsync(_carol, group.Id)).Total);

        await _site.Purge.PurgeEntryAsync(_bob, entries[0].Id);       // the group's admin
        await _site.Purge.PurgeEntryAsync(_root, entries[1].Id);      // a site admin
        Assert.Equal(1, await _site.Purge.EmptyRecycleBinAsync(_root, group.Id));
        foreach (var e in entries)
        {
            AssertErased(await RawEntryAsync(_site, e.Id));
        }

        // A deleted group is purged by site admins only — its own admins cannot even see it.
        await _site.Groups.DeleteGroupAsync(_bob, group.Id);
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Purge.PurgeGroupAsync(_bob, group.Id));
        await _site.Purge.PurgeGroupAsync(_root, group.Id);
    }

    [Fact]
    public async Task Only_its_owner_can_purge_in_a_personal_vault_not_even_a_site_admin()
    {
        var vault = await _site.Groups.EnsurePersonalVaultAsync(_carol);
        var first = await _site.Vault.CreateEntryAsync(_carol, vault.Id, "Bank", "🏦", "", "me", "", "pw-1");
        var second = await _site.Vault.CreateEntryAsync(_carol, vault.Id, "Mail", "📧", "", "me", "", "pw-2");
        await _site.Vault.DeleteEntryAsync(_carol, first.Id);
        await _site.Vault.DeleteEntryAsync(_carol, second.Id);

        foreach (var outsider in new[] { _root, _bob })
        {
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Purge.PurgeEntryAsync(outsider, first.Id));
            await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Purge.EmptyRecycleBinAsync(outsider, vault.Id));
        }
        Assert.Equal("Bank", (await RawEntryAsync(_site, first.Id)).Name);

        await _site.Purge.PurgeEntryAsync(_carol, first.Id);
        Assert.Equal(1, await _site.Purge.EmptyRecycleBinAsync(_carol, vault.Id));
        AssertErased(await RawEntryAsync(_site, first.Id));
        AssertErased(await RawEntryAsync(_site, second.Id));
    }

    [Fact]
    public async Task An_ended_session_cannot_purge()
    {
        var bob = await _site.SignInAsync("bob");
        var root = await _site.SignInAsync("alice"); // a site admin in the test directory
        var group = await _site.Groups.CreateGroupAsync(bob, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(bob, group.Id, "Router", "🌐", "", "", "", "pw");
        await _site.Vault.DeleteEntryAsync(bob, entry.Id);

        await _site.Sessions.EndAsync(bob.SessionId);
        await _site.Sessions.EndAsync(root.SessionId);

        foreach (var call in new Func<Task>[]
                 {
                     () => _site.Purge.PurgeEntryAsync(bob, entry.Id),
                     () => _site.Purge.EmptyRecycleBinAsync(bob, group.Id),
                     () => _site.Purge.PurgeGroupAsync(root, group.Id),
                 })
        {
            var ex = await Assert.ThrowsAsync<VaultAccessDeniedException>(call);
            Assert.Equal(SessionService.SessionEndedMessage, ex.Message);
        }
        Assert.Equal("Router", (await RawEntryAsync(_site, entry.Id)).Name);
    }

    // ---- emptying the bin, purging a group ----

    [Fact]
    public async Task Emptying_a_recycle_bin_of_5000_entries_is_one_quick_operation()
    {
        var dir = Directory.CreateTempSubdirectory("harpo-purge-bin-").FullName;
        try
        {
            using var site = NewSite("alpha", Path.Combine(dir, "harpo.db"));
            var group = await SharedGroupAsync(site);
            var rows = Enumerable.Range(1, 5000)
                .Select(i => new ImportRow(i, $"Entry {i}", "user", $"password-{i}", "https://example.com", "a note", ""))
                .ToList();
            Assert.Equal(5000, (await site.Vault.ImportEntriesAsync(_bob, group.Id, rows)).Created);
            var keep = await site.Vault.CreateEntryAsync(_bob, group.Id, "Keep me", "🔐", "", "", "", "kept");
            await using (var db = site.Db.CreateDbContext())
            {
                // Deleting 5,000 one by one is not what this test is about.
                await db.PasswordEntries.Where(e => e.Id != keep.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.IsDeleted, true));
            }
            Assert.Equal(5000, (await site.Vault.GetDeletedEntriesAsync(_bob, group.Id)).Total);

            var watch = Stopwatch.StartNew();
            var purged = await site.Purge.EmptyRecycleBinAsync(_bob, group.Id);
            watch.Stop();
            _output.WriteLine($"Emptied a bin of {purged} entries (file-backed, scrub included) in {watch.ElapsedMilliseconds} ms");

            Assert.Equal(5000, purged);
            Assert.Equal(0, (await site.Vault.GetDeletedEntriesAsync(_bob, group.Id)).Total);
            await using (var db = site.Db.CreateDbContext())
            {
                Assert.Equal(1, await db.PasswordRevisions.CountAsync());
                Assert.Equal(5000, await db.PasswordEntries.CountAsync(e => e.IsPurged && e.Name == "" && e.EncryptedNotes == ""));
                // Every tombstone is a distinct write that replicates.
                Assert.Equal(5000, await db.PasswordEntries.Where(e => e.IsPurged).Select(e => e.OriginSeq).Distinct().CountAsync());
            }
            Assert.Equal("kept", await site.Vault.RevealPasswordAsync(_bob, keep.Id));
            var bin = Assert.Single(await AuditAsync(site), e => e.Action == AuditActions.BinEmpty);
            Assert.Equal("5000 entries", bin.Detail);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"took {watch.Elapsed}");
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Purging_a_deleted_group_purges_every_entry_in_it_and_it_cannot_be_restored()
    {
        var group = await SharedGroupAsync(_site, "Lab");
        var live = await RichEntryAsync(_site, _bob, group.Id, "Live one");
        var deleted = await RichEntryAsync(_site, _bob, group.Id, "Deleted one");
        await _site.Vault.DeleteEntryAsync(_bob, deleted.Id);
        var other = await SharedGroupAsync(_site, "Other");
        var elsewhere = await RichEntryAsync(_site, _bob, other.Id, "Elsewhere");

        // Only a deleted group can be purged.
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Purge.PurgeGroupAsync(_root, group.Id));
        await _site.Groups.DeleteGroupAsync(_bob, group.Id);
        Assert.Equal(1, (await _site.Groups.GetDeletedGroupsAsync(_root)).Total);

        Assert.Equal(2, await _site.Purge.PurgeGroupAsync(_root, group.Id));

        await using (var db = _site.Db.CreateDbContext())
        {
            var row = await db.Groups.AsNoTracking().SingleAsync(g => g.Id == group.Id);
            Assert.True(row.IsPurged);
            Assert.True(row.IsDeleted);
            Assert.Equal("", row.Name);
            Assert.Equal("", row.Description);
        }
        AssertErased(await RawEntryAsync(_site, live.Id));
        AssertErased(await RawEntryAsync(_site, deleted.Id));
        Assert.Equal(0, await RevisionCountAsync(_site, live.Id));
        Assert.Equal(0, await RevisionCountAsync(_site, deleted.Id));
        Assert.Equal(3, await RevisionCountAsync(_site, elsewhere.Id));

        var page = await _site.Groups.GetDeletedGroupsAsync(_root);
        Assert.Empty(page.Items);
        Assert.Equal(0, page.Total);
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Groups.RestoreGroupAsync(_root, group.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => _site.Purge.PurgeGroupAsync(_root, group.Id));
        Assert.Equal(1, (await _site.Engine.GetStatusAsync()).Entries);
    }

    // ---- audit ----

    [Fact]
    public async Task Purges_are_audited_as_deletions_and_the_audit_trail_itself_is_kept()
    {
        var group = await SharedGroupAsync(_site);
        var one = await _site.Vault.CreateEntryAsync(_bob, group.Id, "Router", "🌐", "", "", "", "pw");
        var two = await _site.Vault.CreateEntryAsync(_bob, group.Id, "Switch", "🌐", "", "", "", "pw");
        var three = await _site.Vault.CreateEntryAsync(_bob, group.Id, "Printer", "🖨", "", "", "", "pw");
        await _site.Vault.CreateEntryAsync(_bob, group.Id, "Still live", "🔐", "", "", "", "pw");
        foreach (var e in new[] { one, two, three })
        {
            await _site.Vault.DeleteEntryAsync(_bob, e.Id);
        }

        await _site.Purge.PurgeEntryAsync(_bob, one.Id);
        await _site.Purge.EmptyRecycleBinAsync(_bob, group.Id);
        await _site.Groups.DeleteGroupAsync(_bob, group.Id);
        await _site.Purge.PurgeGroupAsync(_root, group.Id);

        var trail = await AuditAsync(_site);
        var purge = Assert.Single(trail, e => e.Action == AuditActions.EntryPurge);
        Assert.Equal("Router (Infra)", purge.Target);
        Assert.Equal(one.Id, purge.EntryId);
        Assert.Equal("bob", purge.Username);
        var bin = Assert.Single(trail, e => e.Action == AuditActions.BinEmpty);
        Assert.Equal("Infra", bin.Target);
        Assert.Equal("2 entries", bin.Detail);
        var groupPurge = Assert.Single(trail, e => e.Action == AuditActions.GroupPurge);
        Assert.Equal("Infra", groupPurge.Target);
        Assert.Equal("root", groupPurge.Username);
        Assert.Equal("1 entry", groupPurge.Detail); // the one entry not purged already
        // The deletions recorded before the purge are still there.
        Assert.Equal(3, trail.Count(e => e.Action == AuditActions.EntryDelete));
        foreach (var action in new[] { AuditActions.EntryPurge, AuditActions.BinEmpty, AuditActions.GroupPurge })
        {
            Assert.Equal(AuditCategory.Deletions, AuditActions.CategoryOf(action));
        }
    }

    [Fact]
    public async Task Purges_in_a_personal_vault_are_audited_without_naming_anything()
    {
        var vault = await _site.Groups.EnsurePersonalVaultAsync(_carol);
        var one = await _site.Vault.CreateEntryAsync(_carol, vault.Id, "My bank", "🏦", "", "me", "", "pw");
        var two = await _site.Vault.CreateEntryAsync(_carol, vault.Id, "My mail", "📧", "", "me", "", "pw");
        await _site.Vault.DeleteEntryAsync(_carol, one.Id);
        await _site.Vault.DeleteEntryAsync(_carol, two.Id);

        await _site.Purge.PurgeEntryAsync(_carol, one.Id);
        await _site.Purge.EmptyRecycleBinAsync(_carol, vault.Id);

        var trail = await AuditAsync(_site);
        Assert.Equal(VaultService.PersonalEntryDescription, Assert.Single(trail, e => e.Action == AuditActions.EntryPurge).Target);
        var bin = Assert.Single(trail, e => e.Action == AuditActions.BinEmpty);
        Assert.Equal(VaultService.PersonalVaultDescription, bin.Target);
        Assert.Equal("1 entry", bin.Detail);
        Assert.DoesNotContain(trail, e => e.Target.Contains("My ") || e.Detail.Contains("My "));
    }

    [Fact]
    public async Task A_purged_entry_appears_nowhere()
    {
        var group = await SharedGroupAsync(_site);
        var entry = await _site.Vault.CreateEntryAsync(_bob, group.Id, "Findable", "🌐", "https://findable", "admin", "", "weak");
        await _site.Vault.DeleteEntryAsync(_bob, entry.Id);
        await _site.Purge.PurgeEntryAsync(_bob, entry.Id);
        // Even if a restore were attempted around the service (it cannot be), the list
        // queries never show a tombstone: it stays deleted.
        Assert.Empty(await _site.Vault.GetEntriesAsync(_bob, group.Id));
        Assert.Empty((await _site.Vault.GetDeletedEntriesAsync(_bob, group.Id)).Items);
        Assert.Empty(await _site.Vault.SearchEntriesAsync(_bob, "Findable"));
        Assert.Empty((await _site.Vault.GetOfflineDataAsync(_bob)).Entries);
        Assert.Equal(0, (await _site.Vault.ExportVaultAsync(_bob, group.Id, ExportFormat.Csv)).EntryCount);
        Assert.Equal(0, (await _site.Health.GetReportAsync(_bob))!.Analyzed);
        Assert.Equal(0, Assert.Single(await _site.Groups.GetMyGroupsAsync(_bob)).EntryCount);
        Assert.Equal(0, (await _site.Engine.GetStatusAsync()).Entries);
    }

    // ---- replication ----

    [Fact]
    public async Task A_purge_replicates_and_the_peer_erases_its_own_copy_of_the_history()
    {
        using var beta = NewSite("beta");
        var group = await SharedGroupAsync(_site);
        var entry = await RichEntryAsync(_site, _bob, group.Id);
        await beta.PullFromAsync(_site, viaJson: true);
        Assert.Equal(3, await RevisionCountAsync(beta, entry.Id));
        // beta adds history of its own, which alpha has not seen yet.
        await beta.Vault.ChangePasswordAsync(_bob, entry.Id, "beta-password");
        _clock.Advance(TimeSpan.FromMinutes(1));
        await beta.Vault.DeleteEntryAsync(_bob, entry.Id);
        await _site.PullFromAsync(beta, viaJson: true);
        await _site.Purge.PurgeEntryAsync(_bob, entry.Id);

        await beta.PullFromAsync(_site, viaJson: true);

        AssertErased(await RawEntryAsync(beta, entry.Id));
        Assert.Equal(0, await RevisionCountAsync(beta, entry.Id));
        await Assert.ThrowsAsync<VaultNotFoundException>(() => beta.Vault.RestoreEntryAsync(_bob, entry.Id));
        Assert.Empty((await beta.Vault.GetDeletedEntriesAsync(_bob, group.Id)).Items);
        // The purge asked for a scrub of beta's file; the scrub service runs it.
        Assert.True(await beta.Scrubber.IsPendingAsync());
        Assert.True(await beta.Scrubber.ScrubIfPendingAsync());
        Assert.False(await beta.Scrubber.IsPendingAsync());
        // And the audit event travelled too.
        Assert.Single(await AuditAsync(beta), e => e.Action == AuditActions.EntryPurge);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_concurrent_restore_on_another_site_loses_to_the_purge_on_both(bool betaPullsFirst)
    {
        using var beta = NewSite("beta");
        var group = await SharedGroupAsync(_site);
        var entry = await RichEntryAsync(_site, _bob, group.Id);
        await _site.Vault.DeleteEntryAsync(_bob, entry.Id);
        await beta.PullFromAsync(_site);

        // Out of contact: alpha purges, and a minute LATER beta restores and edits.
        await _site.Purge.PurgeEntryAsync(_bob, entry.Id);
        _clock.Advance(TimeSpan.FromMinutes(1));
        await beta.Vault.RestoreEntryAsync(_bob, entry.Id);
        await beta.Vault.UpdateEntryAsync(_bob, entry.Id, "Renamed on beta", "🌐", "", "", "new notes");
        await beta.Vault.ChangePasswordAsync(_bob, entry.Id, "beta-password");

        for (var round = 0; round < 2; round++)
        {
            if (betaPullsFirst)
            {
                await beta.PullFromAsync(_site, viaJson: true);
                await _site.PullFromAsync(beta, viaJson: true);
            }
            else
            {
                await _site.PullFromAsync(beta, viaJson: true);
                await beta.PullFromAsync(_site, viaJson: true);
            }
        }

        var onAlpha = await RawEntryAsync(_site, entry.Id);
        var onBeta = await RawEntryAsync(beta, entry.Id);
        AssertErased(onAlpha);
        AssertErased(onBeta);
        // The same version of the row on both sites: converged, not just both blank.
        Assert.Equal((onAlpha.OriginSiteId, onAlpha.OriginSeq, onAlpha.UpdatedAtUtc),
            (onBeta.OriginSiteId, onBeta.OriginSeq, onBeta.UpdatedAtUtc));
        // Re-issued newer than the restore, so a site that only knows
        // last-writer-wins would take the tombstone as well.
        Assert.True(onAlpha.UpdatedAtUtc > _clock.GetUtcNow().UtcDateTime);
        Assert.Equal(0, await RevisionCountAsync(_site, entry.Id));
        Assert.Equal(0, await RevisionCountAsync(beta, entry.Id));
        Assert.Empty(await beta.Vault.GetEntriesAsync(_bob, group.Id));
        Assert.Empty(await _site.Vault.GetEntriesAsync(_bob, group.Id));

        // Quiet afterwards: nothing more to exchange in either direction.
        var request = new PullRequest { SiteId = "beta", Vector = await beta.Engine.GetVectorAsync() };
        Assert.Equal(0, (await _site.Engine.BuildResponseAsync(request)).RowCount);
        request = new PullRequest { SiteId = "alpha", Vector = await _site.Engine.GetVectorAsync() };
        Assert.Equal(0, (await beta.Engine.BuildResponseAsync(request)).RowCount);
    }

    /// <summary>
    /// The rows of one entry as a peer would send them before and after its purge:
    /// the old version and its revisions, and the tombstone.
    /// </summary>
    private async Task<(PasswordEntry Entry, PullResponse Before, PullResponse After)> PurgedOnAlphaAsync()
    {
        var group = await SharedGroupAsync(_site);
        var entry = await RichEntryAsync(_site, _bob, group.Id);
        await _site.Vault.DeleteEntryAsync(_bob, entry.Id);
        var before = await _site.Engine.BuildResponseAsync(new PullRequest { SiteId = "x" });
        Assert.Equal(3, before.Revisions.Count);
        await _site.Purge.PurgeEntryAsync(_bob, entry.Id);
        var after = await _site.Engine.BuildResponseAsync(new PullRequest { SiteId = "x" });
        Assert.Empty(after.Revisions);
        Assert.True(Assert.Single(after.Entries).IsPurged);
        return (entry, before, after);
    }

    private static PullResponse Only(PullResponse source, bool groups = false, bool members = false, bool entries = false,
        bool revisions = false) => new()
    {
        SiteId = source.SiteId,
        UtcNow = source.UtcNow,
        Groups = groups ? source.Groups : [],
        Members = members ? source.Members : [],
        Entries = entries ? source.Entries : [],
        Revisions = revisions ? source.Revisions : [],
    };

    private static PullResponse Copy(PullResponse response) =>
        System.Text.Json.JsonSerializer.Deserialize<PullResponse>(
            System.Text.Json.JsonSerializer.Serialize(response, Web), Web)!;

    private static readonly System.Text.Json.JsonSerializerOptions Web = new(System.Text.Json.JsonSerializerDefaults.Web);

    [Fact]
    public async Task A_revision_arriving_after_the_purge_is_never_stored()
    {
        var (entry, before, after) = await PurgedOnAlphaAsync();
        using var beta = NewSite("beta");

        await beta.Engine.ApplyAsync(Copy(after));
        // A site that has not heard of the purge sends the old rows, revisions included.
        await beta.Engine.ApplyAsync(Copy(Only(before, groups: true, members: true, entries: true)));
        await beta.Engine.ApplyAsync(Copy(Only(before, revisions: true)));

        AssertErased(await RawEntryAsync(beta, entry.Id));
        Assert.Equal(0, await RevisionCountAsync(beta, entry.Id));
    }

    [Fact]
    public async Task A_revision_that_arrived_before_the_purge_is_erased_when_it_comes()
    {
        var (entry, before, after) = await PurgedOnAlphaAsync();
        using var beta = NewSite("beta");

        // Revisions first, even before their entry exists here.
        await beta.Engine.ApplyAsync(Copy(Only(before, revisions: true)));
        Assert.Equal(3, await RevisionCountAsync(beta, entry.Id));
        await beta.Engine.ApplyAsync(Copy(after));

        AssertErased(await RawEntryAsync(beta, entry.Id));
        Assert.Equal(0, await RevisionCountAsync(beta, entry.Id));
        Assert.True(beta.Engine.LastErased >= 3);
    }

    [Fact]
    public async Task A_revision_in_the_same_batch_as_the_purge_is_never_stored()
    {
        var (entry, before, after) = await PurgedOnAlphaAsync();
        using var beta = NewSite("beta");

        var mixed = Copy(after);
        mixed.Revisions.AddRange(Copy(before).Revisions);
        await beta.Engine.ApplyAsync(mixed);

        AssertErased(await RawEntryAsync(beta, entry.Id));
        Assert.Equal(0, await RevisionCountAsync(beta, entry.Id));
    }

    /// <summary>What a site on 0.6 sends: the same JSON with no isPurged property anywhere.</summary>
    private static PullResponse AsFromAnOlderPeer(PullResponse response)
    {
        var json = System.Text.Json.Nodes.JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(response, Web))!;
        foreach (var list in new[] { "groups", "entries" })
        {
            foreach (var row in json[list]!.AsArray())
            {
                row!.AsObject().Remove("isPurged");
            }
        }
        var text = json.ToJsonString();
        Assert.DoesNotContain("isPurged", text);
        return System.Text.Json.JsonSerializer.Deserialize<PullResponse>(text, Web)!;
    }

    [Fact]
    public async Task A_row_from_an_older_peer_never_un_purges_anything()
    {
        var (entry, before, _) = await PurgedOnAlphaAsync();
        var purged = await RawEntryAsync(_site, entry.Id);

        // A 0.6 site restored and edited its copy after the purge happened.
        _clock.Advance(TimeSpan.FromMinutes(5));
        var fromOld = AsFromAnOlderPeer(Only(before, entries: true));
        var row = Assert.Single(fromOld.Entries);
        row.IsDeleted = false;
        row.Name = "Restored on the old site";
        row.OriginSiteId = "old";
        row.OriginSeq = 1;
        row.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        fromOld.SiteId = "old";
        fromOld.Revisions = AsFromAnOlderPeer(Only(before, revisions: true)).Revisions;
        await _site.Engine.ApplyAsync(fromOld);

        var after = await RawEntryAsync(_site, entry.Id);
        AssertErased(after);
        Assert.Equal(0, await RevisionCountAsync(_site, entry.Id));
        // Re-issued under alpha's stamps, newer than the old site's restore: last-writer-wins,
        // all the old site knows, makes it take the (blank, deleted) tombstone back.
        Assert.Equal("alpha", after.OriginSiteId);
        Assert.True(after.OriginSeq > purged.OriginSeq);
        Assert.True(after.UpdatedAtUtc > row.UpdatedAtUtc);
    }

    [Fact]
    public async Task A_tombstone_relayed_by_an_older_peer_without_its_flag_still_purges()
    {
        var (entry, before, after) = await PurgedOnAlphaAsync();
        using var gamma = NewSite("gamma");
        await gamma.Engine.ApplyAsync(Copy(before));
        Assert.Equal(3, await RevisionCountAsync(gamma, entry.Id));

        // A 0.6 site stored the tombstone (no column for the flag) and passes it on.
        var relayed = AsFromAnOlderPeer(after);
        Assert.False(Assert.Single(relayed.Entries).IsPurged);
        await gamma.Engine.ApplyAsync(relayed);

        AssertErased(await RawEntryAsync(gamma, entry.Id));
        Assert.Equal(0, await RevisionCountAsync(gamma, entry.Id));
    }

    [Fact]
    public async Task An_upgraded_site_finishes_the_purges_it_received_while_older()
    {
        var group = await SharedGroupAsync(_site);
        var entry = await RichEntryAsync(_site, _bob, group.Id);
        var other = await RichEntryAsync(_site, _bob, group.Id, "Other");
        await using (var db = _site.Db.CreateDbContext())
        {
            // What 0.6 does with a tombstone: last-writer-wins blanks the row, the
            // flag has nowhere to go, the history stays.
            db.SuppressReplicationStamping = true;
            var row = await db.PasswordEntries.SingleAsync(e => e.Id == entry.Id);
            row.IsDeleted = true;
            row.Name = row.Icon = row.Url = row.Username = row.EncryptedNotes = "";
            row.EncryptedTotpSecret = null;
            await db.SaveChangesAsync();
        }
        var stamps = await RawEntryAsync(_site, entry.Id);

        await Purging.FinishAsync(_site.Db, _site.Scrubber, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        var finished = await RawEntryAsync(_site, entry.Id);
        AssertErased(finished);
        Assert.Equal((stamps.OriginSiteId, stamps.OriginSeq), (finished.OriginSiteId, finished.OriginSeq));
        Assert.Equal(0, await RevisionCountAsync(_site, entry.Id));
        Assert.Equal(3, await RevisionCountAsync(_site, other.Id));
        Assert.False(await _site.Scrubber.IsPendingAsync());

        // Nothing to do on a later start.
        await Purging.FinishAsync(_site.Db, _site.Scrubber, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        Assert.Equal(3, await RevisionCountAsync(_site, other.Id));
    }

    [Fact]
    public async Task A_group_purge_reaches_entries_the_purging_site_never_saw()
    {
        using var beta = NewSite("beta");
        var group = await SharedGroupAsync(_site, "Lab");
        var known = await RichEntryAsync(_site, _bob, group.Id, "Known");
        await beta.PullFromAsync(_site);

        // While out of contact, beta adds an entry, and alpha deletes and purges the group.
        var unseen = await RichEntryAsync(beta, _bob, group.Id, "Added on beta");
        await _site.Groups.DeleteGroupAsync(_bob, group.Id);
        await _site.Purge.PurgeGroupAsync(_root, group.Id);

        await beta.PullFromAsync(_site, viaJson: true);
        await _site.PullFromAsync(beta, viaJson: true);

        foreach (var site in new[] { _site, beta })
        {
            AssertErased(await RawEntryAsync(site, known.Id));
            AssertErased(await RawEntryAsync(site, unseen.Id));
            Assert.Equal(0, await RevisionCountAsync(site, known.Id));
            Assert.Equal(0, await RevisionCountAsync(site, unseen.Id));
            await using var db = site.Db.CreateDbContext();
            var row = await db.Groups.AsNoTracking().SingleAsync(g => g.Id == group.Id);
            Assert.True(row.IsPurged);
            Assert.Equal("", row.Name);
            Assert.Empty((await site.Groups.GetDeletedGroupsAsync(_root)).Items);
        }
    }

    [Fact]
    public async Task A_restore_of_a_purged_group_on_another_site_loses()
    {
        using var beta = NewSite("beta");
        var group = await SharedGroupAsync(_site, "Lab");
        var entry = await RichEntryAsync(_site, _bob, group.Id);
        await _site.Groups.DeleteGroupAsync(_bob, group.Id);
        await beta.PullFromAsync(_site);

        await _site.Purge.PurgeGroupAsync(_root, group.Id);
        _clock.Advance(TimeSpan.FromMinutes(1));
        await beta.Groups.RestoreGroupAsync(_root, group.Id);

        await _site.PullFromAsync(beta);
        await beta.PullFromAsync(_site);
        await _site.PullFromAsync(beta);

        foreach (var site in new[] { _site, beta })
        {
            await using var db = site.Db.CreateDbContext();
            var row = await db.Groups.AsNoTracking().SingleAsync(g => g.Id == group.Id);
            Assert.True(row.IsPurged && row.IsDeleted);
            Assert.Equal("", row.Name);
            Assert.Empty(await site.Groups.GetMyGroupsAsync(_bob));
            AssertErased(await RawEntryAsync(site, entry.Id));
            Assert.Equal(0, await RevisionCountAsync(site, entry.Id));
        }
    }

    [Fact]
    public async Task Every_purge_that_blanks_something_here_asks_for_a_scrub()
    {
        // An empty group: nothing but its name and description to erase.
        using var beta = NewSite("beta");
        var group = await SharedGroupAsync(_site, "Secret project name");
        await _site.Groups.DeleteGroupAsync(_bob, group.Id);
        await beta.PullFromAsync(_site);
        Assert.False(await beta.Scrubber.IsPendingAsync());

        await _site.Purge.PurgeGroupAsync(_root, group.Id);
        await beta.PullFromAsync(_site);

        Assert.True(beta.Engine.LastErased > 0);
        Assert.True(await beta.Scrubber.IsPendingAsync());
        // A tombstone for a row this site never held has nothing to scrub.
        using var gamma = NewSite("gamma");
        await gamma.PullFromAsync(_site);
        Assert.False(await gamma.Scrubber.IsPendingAsync());
    }

    // ---- the bytes in the file ----

    [Fact]
    public async Task A_purge_removes_the_content_from_the_database_file_its_log_and_the_peers_file()
    {
        // Real files in the journal mode production uses. Each distinctive value
        // ends a 20 KB field, so it sits in an overflow page — in the main file,
        // since every connection here closes after use and the last close
        // checkpoints the log, which makes the baseline below deterministic. (A
        // value inline in a table page could survive only as an old page image in
        // the log, which a checkpoint may drop at any moment.) A personal vault,
        // because the audit trail — never purged — names the entries of a shared
        // group when they are deleted.
        var dir = Directory.CreateTempSubdirectory("harpo-purge-").FullName;
        var alphaDir = Directory.CreateDirectory(Path.Combine(dir, "alpha")).FullName;
        var betaDir = Directory.CreateDirectory(Path.Combine(dir, "beta")).FullName;
        try
        {
            using var alpha = NewSite("alpha", Path.Combine(alphaDir, "harpo.db"));
            using var beta = NewSite("beta", Path.Combine(betaDir, "harpo.db"));
            var padding = new string('.', 20_000);
            var vault = await alpha.Groups.EnsurePersonalVaultAsync(_carol);
            var entry = await alpha.Vault.CreateEntryAsync(_carol, vault.Id,
                padding + "NAME-MARKER-7Q2", "🔐", "https://example.com/" + padding + "URL-MARKER-3K8",
                padding + "USER-MARKER-9V4", padding + "NOTES-MARKER-5T1", padding + "PASSWORD-MARKER-2W6");
            await alpha.Vault.ChangePasswordAsync(_carol, entry.Id, padding + "OLD-PASSWORD-MARKER-8M3");
            await beta.PullFromAsync(alpha);

            // Notes and passwords are ciphertext in the file: their markers are the
            // tails of the stored ciphertext.
            string[] markers;
            await using (var db = alpha.Db.CreateDbContext())
            {
                var row = await db.PasswordEntries.AsNoTracking().SingleAsync(e => e.Id == entry.Id);
                var blobs = await db.PasswordRevisions.Where(r => r.EntryId == entry.Id).Select(r => r.EncryptedPassword).ToListAsync();
                markers =
                [
                    "NAME-MARKER-7Q2", "URL-MARKER-3K8", "USER-MARKER-9V4",
                    row.EncryptedNotes[^40..], blobs[0][^40..], blobs[1][^40..],
                ];
            }
            foreach (var siteDir in new[] { alphaDir, betaDir })
            {
                var text = FileText(siteDir);
                foreach (var marker in markers)
                {
                    Assert.True(text.Contains(marker), $"baseline: {marker} missing in {Describe(siteDir, markers)}");
                }
            }

            await alpha.Vault.DeleteEntryAsync(_carol, entry.Id);
            await alpha.Purge.PurgeEntryAsync(_carol, entry.Id);
            await beta.PullFromAsync(alpha);

            // alpha scrubbed as part of the purge; beta has erased the rows and asked
            // for a scrub. Its engine zeroes freed pages as it goes (secure_delete,
            // since 0.8), so its main file may already be clean, but old page images
            // can sit in the log, and a file written by 0.7 kept its freed pages: the
            // scrub still has to run, and nothing may be left after it.
            AssertNone(alphaDir, markers);
            Assert.True(await beta.Scrubber.ScrubIfPendingAsync());
            AssertNone(betaDir, markers);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, recursive: true);
        }

        static void AssertNone(string siteDir, string[] markers)
        {
            var files = Directory.GetFiles(siteDir).Select(Path.GetFileName).ToList();
            Assert.Contains("harpo.db", files);
            var text = FileText(siteDir);
            foreach (var marker in markers)
            {
                Assert.False(text.Contains(marker), $"{marker} survived: {Describe(siteDir, markers)}");
            }
        }
    }

    // Everything SQLite keeps for a database (main file, -wal, -shm), read as one
    // snapshot: when a file vanishes mid-read (the last connection's close
    // checkpoints the log and deletes it), the whole set is read again — its
    // content is in the main file by then. As in NotesEncryptionTests.
    private static string FileText(string directory)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return string.Concat(Directory.GetFiles(directory).OrderBy(f => f).Select(ReadOne));
            }
            catch (Exception ex) when (attempt < 5 && ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(50);
            }
        }
    }

    private static string ReadOne(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return System.Text.Encoding.Latin1.GetString(memory.ToArray());
    }

    private static string Describe(string directory, string[] markers) => string.Join(" | ",
        Directory.GetFiles(directory).OrderBy(f => f).Select(f =>
        {
            string text;
            try
            {
                text = ReadOne(f);
            }
            catch (Exception ex)
            {
                return $"{Path.GetFileName(f)}: {ex.GetType().Name}";
            }
            return $"{Path.GetFileName(f)}: {text.Length} bytes [" +
                string.Join(",", markers.Where(text.Contains).Select(m => m.Length > 20 ? m[..8] + "…" : m)) + "]";
        }));
}
