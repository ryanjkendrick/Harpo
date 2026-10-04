using Harpo.Data;
using Harpo.Replication;
using Harpo.Services;
using Microsoft.Data.Sqlite;

namespace Harpo.Tests;

/// <summary>
/// Races between concurrent readers and writers. These run against real
/// WAL-mode database files (every context on its own connection, as in
/// production) and use <see cref="CommandHook"/> to interleave a competing
/// write at an exact SQL statement, so each race is reproduced deterministically
/// rather than by hoping two threads collide.
/// </summary>
public class ConcurrencyTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("harpo-race-").FullName;
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _root = TestSite.User("root", siteAdmin: true);

    private string DbPath(string name) => Path.Combine(_dir, name + ".db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    /// <summary>The per-origin delta read of one table inside BuildResponseAsync.</summary>
    private static Func<string, bool> DeltaReadOf(string table) =>
        sql => sql.Contains($"FROM \"{table}\"") && sql.Contains("\"OriginSeq\" >");

    // ---- Replication: a response must be one consistent snapshot ----

    [Fact]
    public async Task Pull_built_while_a_membership_is_revoked_never_skips_the_revocation()
    {
        var time = new ManualTime();
        var hook = new CommandHook();
        using var a = new TestSite("a", time, databasePath: DbPath("a"), interceptors: hook);
        using var b = new TestSite("b", time);

        var group = await a.Groups.CreateGroupAsync(_alice, "Infra", "");
        time.Advance(TimeSpan.FromSeconds(1));
        await a.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Member);
        await b.PullFromAsync(a);
        Assert.Equal(GroupRole.Member, await b.Groups.GetMyRoleAsync(_bob, group.Id));

        // While A is assembling the next response — memberships already read, the
        // audit trail not yet — bob's membership is revoked. That commits a
        // tombstone (lower sequence, in a table already read) and then its audit
        // event (higher sequence, in a table still to be read).
        time.Advance(TimeSpan.FromSeconds(1));
        hook.Before(DeltaReadOf("AuditEvents"), () => a.Groups.RemoveMemberAsync(_alice, group.Id, "bob"));
        await b.PullFromAsync(a);
        await b.PullFromAsync(a); // a later, quiet pull

        // If the first response carried the audit event without the tombstone, B's
        // watermark moved past both and the revocation would never arrive.
        Assert.Null(await b.Groups.GetMyRoleAsync(_bob, group.Id));
    }

    [Fact]
    public async Task Pull_built_while_an_entry_is_created_never_skips_the_entry()
    {
        var time = new ManualTime();
        var hook = new CommandHook();
        using var a = new TestSite("a", time, databasePath: DbPath("a"), interceptors: hook);
        using var b = new TestSite("b", time);

        var group = await a.Groups.CreateGroupAsync(_alice, "Infra", "");
        await b.PullFromAsync(a);

        // One commit writes the entry and its first revision. It lands after the
        // entries table was read but before the revisions table is.
        time.Advance(TimeSpan.FromSeconds(1));
        hook.Before(DeltaReadOf("PasswordRevisions"),
            () => a.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "admin", "", "pw1"));
        await b.PullFromAsync(a);
        await b.PullFromAsync(a);

        var entry = Assert.Single(await b.Vault.GetEntriesAsync(_alice, group.Id));
        Assert.Equal("Router", entry.Entry.Name);
        Assert.Equal("pw1", await b.Vault.RevealPasswordAsync(_alice, entry.Entry.Id));
    }

    [Fact]
    public async Task A_local_edit_racing_a_replication_apply_is_not_lost()
    {
        var time = new ManualTime();
        var hook = new CommandHook();
        using var a = new TestSite("a", time, databasePath: DbPath("a"), interceptors: hook);
        using var b = new TestSite("b", time);

        var group = await a.Groups.CreateGroupAsync(_alice, "Infra", "");
        var entry = await a.Vault.CreateEntryAsync(_alice, group.Id, "Router", "🌐", "", "admin", "", "pw1");
        await b.PullFromAsync(a);

        // B renames the entry…
        time.Advance(TimeSpan.FromSeconds(10));
        await b.Vault.UpdateEntryAsync(_alice, entry.Id, "renamed on b", "🌐", "", "admin", "");
        var request = new PullRequest { SiteId = "a", Vector = await a.Engine.GetVectorAsync() };
        var response = await b.Engine.BuildResponseAsync(request);

        // …and A applies that — but is held just after deciding the incoming row
        // wins and just before saving, while a user on A makes a LATER edit.
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        hook.Before(sql => sql.Contains("FROM \"PeerCursors\""), async () =>
        {
            reached.SetResult();
            await release.Task;
        });
        var apply = Task.Run(() => a.Engine.ApplyAsync(response));
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));

        time.Advance(TimeSpan.FromSeconds(10));
        var localEdit = Task.Run(() => a.Vault.UpdateEntryAsync(_alice, entry.Id, "renamed on a (later)", "🌐", "", "admin", ""));
        await Task.Delay(500); // let the edit commit (unfixed) or queue behind the apply (fixed)
        release.SetResult();
        await apply;
        await localEdit;

        // Last writer wins: the later local edit must survive, here and on B.
        Assert.Equal("renamed on a (later)", Assert.Single(await a.Vault.GetEntriesAsync(_alice, group.Id)).Entry.Name);
        await b.PullFromAsync(a);
        Assert.Equal("renamed on a (later)", Assert.Single(await b.Vault.GetEntriesAsync(_alice, group.Id)).Entry.Name);
    }

    // ---- Groups: "at least one admin" must hold under concurrency ----

    [Fact]
    public async Task Concurrent_demotions_cannot_leave_a_group_without_an_admin()
    {
        var hook = new CommandHook();
        using var site = new TestSite("a", databasePath: DbPath("a"), interceptors: hook);
        var group = await site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await site.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Admin);

        var outcomes = await RaceAsync(hook,
            () => site.Groups.SetMemberRoleAsync(_alice, group.Id, "bob", GroupRole.Member),
            () => site.Groups.SetMemberRoleAsync(_bob, group.Id, "alice", GroupRole.Member));

        var members = await site.Groups.GetMembersAsync(_root, group.Id);
        Assert.Contains(members, m => m.Role == GroupRole.Admin);
        Assert.Equal(1, outcomes.Count(rejected => rejected));
    }

    [Fact]
    public async Task Concurrent_removals_cannot_leave_a_group_without_an_admin()
    {
        var hook = new CommandHook();
        using var site = new TestSite("a", databasePath: DbPath("a"), interceptors: hook);
        var group = await site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await site.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Admin);

        var outcomes = await RaceAsync(hook,
            () => site.Groups.RemoveMemberAsync(_alice, group.Id, "bob"),
            () => site.Groups.RemoveMemberAsync(_bob, group.Id, "alice"));

        var members = await site.Groups.GetMembersAsync(_root, group.Id);
        Assert.Contains(members, m => m.Role == GroupRole.Admin);
        Assert.Equal(1, outcomes.Count(rejected => rejected));
    }

    [Fact]
    public async Task Concurrent_adds_of_the_same_member_end_in_one_membership_and_one_plain_refusal()
    {
        var hook = new CommandHook();
        using var site = new TestSite("a", databasePath: DbPath("a"), interceptors: hook);
        var group = await site.Groups.CreateGroupAsync(_alice, "Infra", "");

        // Two admins add bob at the same moment. Unguarded, both find nobody
        // there and the second insert dies on the membership's key — which would
        // escape RaceAsync as a DbUpdateException and fail this test.
        var outcomes = await RaceAsync(hook,
            () => site.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Member),
            () => site.Groups.AddMemberAsync(_root, group.Id, "bob", "Bob", GroupRole.Viewer),
            pauseBefore: "INSERT INTO \"GroupMembers\"");

        Assert.Equal(1, outcomes.Count(rejected => rejected));
        var bob = Assert.Single(await site.Groups.GetMembersAsync(_root, group.Id), m => m.Username == "bob");
        Assert.Equal(GroupRole.Member, bob.Role); // the first call's, not a blend of the two
    }

    [Fact]
    public async Task Demotions_on_disconnected_sites_are_surfaced_for_a_site_admin_to_repair()
    {
        var time = new ManualTime();
        using var a = new TestSite("a", time);
        using var b = new TestSite("b", time);
        var group = await a.Groups.CreateGroupAsync(_alice, "Infra", "");
        time.Advance(TimeSpan.FromSeconds(1));
        await a.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Admin);
        await b.PullFromAsync(a);

        // While the sites can't reach each other, each admin demotes the other.
        // Both changes are valid where they were made…
        time.Advance(TimeSpan.FromSeconds(1));
        await a.Groups.SetMemberRoleAsync(_alice, group.Id, "bob", GroupRole.Member);
        time.Advance(TimeSpan.FromSeconds(1));
        await b.Groups.SetMemberRoleAsync(_bob, group.Id, "alice", GroupRole.Member);
        await a.PullFromAsync(b);
        await b.PullFromAsync(a);

        // …and the merge keeps both (they touch different rows): no admin is left
        // on either site. No lock can prevent that, so the policy is to surface it
        // to site administrators rather than promote someone automatically.
        foreach (var site in new[] { a, b })
        {
            Assert.DoesNotContain(await site.Groups.GetMembersAsync(_root, group.Id), m => m.Role == GroupRole.Admin);
            Assert.Equal(group.Id, Assert.Single(await site.Groups.GetGroupsWithoutAdminAsync(_root)).Id);
        }
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => a.Groups.GetGroupsWithoutAdminAsync(_alice));

        // A site administrator appoints an admin; that replicates like any change.
        time.Advance(TimeSpan.FromSeconds(1));
        await b.Groups.SetMemberRoleAsync(_root, group.Id, "alice", GroupRole.Admin);
        await a.PullFromAsync(b);
        foreach (var site in new[] { a, b })
        {
            Assert.Empty(await site.Groups.GetGroupsWithoutAdminAsync(_root));
        }
    }

    /// <summary>
    /// Runs <paramref name="first"/> until its membership write (an UPDATE unless
    /// <paramref name="pauseBefore"/> says otherwise) is about to be sent — its
    /// check has passed, its write has not landed — then starts
    /// <paramref name="second"/> and lets both finish. Returns, per call, whether
    /// it was rejected.
    /// </summary>
    private static async Task<bool[]> RaceAsync(
        CommandHook hook, Func<Task> first, Func<Task> second, string pauseBefore = "UPDATE \"GroupMembers\"")
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        hook.Before(sql => sql.Contains(pauseBefore), async () =>
        {
            reached.SetResult();
            await release.Task;
        });

        var firstTask = Task.Run(first);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var secondTask = Task.Run(second);
        await Task.Delay(500); // let the second call run its own check (unfixed) or queue (fixed)
        release.SetResult();

        var rejected = new bool[2];
        var tasks = new[] { firstTask, secondTask };
        for (var i = 0; i < tasks.Length; i++)
        {
            try
            {
                await tasks[i];
            }
            catch (Exception ex) when (ex is VaultValidationException or VaultAccessDeniedException)
            {
                rejected[i] = true;
            }
        }
        return rejected;
    }
}
