using System.Security.Claims;
using Harpo.Security;
using Harpo.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// Server-side sessions: signing out, a disabled account and a changed admin
/// role end access for callers that already hold a <see cref="UserContext"/> —
/// which is what an open interactive page is — and the time bounds hold
/// against a controllable clock.
/// </summary>
public class SessionTests : IDisposable
{
    private readonly TestSite _site = new("s1");

    public void Dispose() => _site.Dispose();

    private static async Task AssertSessionEndedAsync(Func<Task> call)
    {
        var ex = await Assert.ThrowsAsync<VaultAccessDeniedException>(call);
        Assert.Equal(SessionService.SessionEndedMessage, ex.Message);
    }

    private async Task<(UserContext User, Guid GroupId, Guid EntryId)> AliceWithAnEntryAsync()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await _site.Groups.CreateGroupAsync(alice, "Infra", "");
        var entry = await _site.Vault.CreateEntryAsync(alice, group.Id, "Router", "", "", "admin", "", "hunter2");
        return (alice, group.Id, entry.Id);
    }

    // ---- sign-out ----

    [Fact]
    public async Task Signing_out_ends_the_session()
    {
        var alice = await _site.SignInAsync("alice");
        Assert.False(string.IsNullOrEmpty(alice.SessionId));
        Assert.True(await _site.Sessions.IsLiveAsync(alice.SessionId));

        await _site.Sessions.EndAsync(alice.SessionId);

        Assert.False(await _site.Sessions.IsLiveAsync(alice.SessionId));
    }

    [Fact]
    public async Task A_page_holding_the_user_cannot_reveal_or_write_after_sign_out_elsewhere()
    {
        // The reviewer's reproduction: a page that loaded (and revealed) before
        // the sign-out keeps its UserContext; a fresh reveal must still fail.
        var (alice, groupId, entryId) = await AliceWithAnEntryAsync();
        Assert.Equal("hunter2", await _site.Vault.RevealPasswordAsync(alice, entryId));

        await _site.Sessions.EndAsync(alice.SessionId); // "sign out" in another tab

        await AssertSessionEndedAsync(() => _site.Vault.RevealPasswordAsync(alice, entryId));
        await AssertSessionEndedAsync(() => _site.Vault.RevealPasswordAsync(alice, entryId, RevealPurpose.Copy));
        await AssertSessionEndedAsync(() => _site.Vault.GetEntriesAsync(alice, groupId));
        await AssertSessionEndedAsync(() => _site.Vault.GetTotpCodeAsync(alice, entryId));
        await AssertSessionEndedAsync(() => _site.Vault.GetHistoryAsync(alice, entryId));
        await AssertSessionEndedAsync(() => _site.Vault.CreateEntryAsync(alice, groupId, "New", "", "", "", "", "pw"));
        await AssertSessionEndedAsync(() => _site.Vault.UpdateEntryAsync(alice, entryId, "Renamed", "", "", "", ""));
        await AssertSessionEndedAsync(() => _site.Vault.ChangePasswordAsync(alice, entryId, "new"));
        await AssertSessionEndedAsync(() => _site.Vault.DeleteEntryAsync(alice, entryId));
        await AssertSessionEndedAsync(() => _site.Vault.GetOfflineDataAsync(alice));
        await AssertSessionEndedAsync(() => _site.Groups.GetMyGroupsAsync(alice));
        await AssertSessionEndedAsync(() => _site.Groups.AddMemberAsync(alice, groupId, "bob", "Bob", Harpo.Data.GroupRole.Member));
        await AssertSessionEndedAsync(() => _site.Groups.UpdateGroupAsync(alice, groupId, "X", ""));
        await AssertSessionEndedAsync(() => _site.Groups.DeleteGroupAsync(alice, groupId));
        await AssertSessionEndedAsync(() => _site.Groups.CreateGroupAsync(alice, "Another", ""));
        await AssertSessionEndedAsync(() => _site.Groups.EnsurePersonalVaultAsync(alice));
        await AssertSessionEndedAsync(() => _site.Audit.GetEventsAsync(alice));
        await AssertSessionEndedAsync(() => _site.Health.GetReportAsync(alice));

        // Nothing was changed by the refused writes.
        var owner = TestSite.User("alice", siteAdmin: true);
        var entry = (await _site.Vault.GetEntriesAsync(owner, groupId)).Single();
        Assert.Equal("Router", entry.Entry.Name);
        Assert.Equal("hunter2", await _site.Vault.RevealPasswordAsync(owner, entryId));
    }

    [Fact]
    public async Task Signing_out_one_session_leaves_the_users_other_sessions_alone()
    {
        var (laptop, _, entryId) = await AliceWithAnEntryAsync();
        var phone = await _site.SignInAsync("alice");

        await _site.Sessions.EndAsync(laptop.SessionId);

        await AssertSessionEndedAsync(() => _site.Vault.RevealPasswordAsync(laptop, entryId));
        Assert.Equal("hunter2", await _site.Vault.RevealPasswordAsync(phone, entryId));
    }

    [Fact]
    public async Task A_principal_without_a_session_claim_is_refused_not_exempt()
    {
        // A cookie issued before sessions existed carries no session id.
        var legacy = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "alice"), new Claim(ClaimTypes.Role, HarpoClaims.SiteAdminRole)], "Harpo"));
        var user = UserContext.FromPrincipal(legacy);

        Assert.Equal("", user.SessionId);
        await AssertSessionEndedAsync(() => _site.Groups.GetMyGroupsAsync(user));
    }

    [Fact]
    public async Task A_session_id_only_works_for_the_account_it_was_issued_to()
    {
        var alice = await _site.SignInAsync("alice");
        var forged = TestSite.User("bob") with { SessionId = alice.SessionId };

        await AssertSessionEndedAsync(() => _site.Groups.GetMyGroupsAsync(forged));
    }

    // ---- expiry ----

    [Fact]
    public async Task A_sliding_session_lives_while_used_and_ends_after_SessionHours_idle()
    {
        var alice = await _site.SignInAsync("alice");

        for (var i = 0; i < 3; i++)
        {
            _site.Time.Advance(TimeSpan.FromHours(7.9));
            await _site.Sessions.RevalidateDueAsync(); // the directory still knows alice
            await _site.Groups.GetMyGroupsAsync(alice); // activity slides it
        }

        _site.Time.Advance(TimeSpan.FromHours(8));
        await AssertSessionEndedAsync(() => _site.Groups.GetMyGroupsAsync(alice));
    }

    [Fact]
    public async Task A_page_checking_its_session_does_not_keep_an_idle_session_alive()
    {
        var alice = await _site.SignInAsync("alice");
        for (var i = 0; i < 9; i++)
        {
            _site.Time.Advance(TimeSpan.FromHours(1));
            await _site.Sessions.RevalidateDueAsync();
            // The open page's periodic check is not activity.
            var live = await _site.Sessions.IsLiveAsync(alice.SessionId, touch: false);
            Assert.Equal(i < 7, live);
        }
    }

    [Fact]
    public async Task A_non_sliding_session_ends_SessionHours_after_sign_in_however_busy()
    {
        _site.SessionOptions.SlidingExpiration = false;
        _site.SessionOptions.SessionHours = 2;
        var alice = await _site.SignInAsync("alice");

        _site.Time.Advance(TimeSpan.FromMinutes(119));
        await _site.Groups.GetMyGroupsAsync(alice);
        _site.Time.Advance(TimeSpan.FromMinutes(1));

        await AssertSessionEndedAsync(() => _site.Groups.GetMyGroupsAsync(alice));
    }

    [Fact]
    public async Task Purge_removes_expired_sessions_only()
    {
        var alice = await _site.SignInAsync("alice");
        _site.Time.Advance(TimeSpan.FromHours(5));
        var bob = await _site.SignInAsync("bob");
        _site.Time.Advance(TimeSpan.FromHours(3));

        Assert.Equal(1, await _site.Sessions.PurgeExpiredAsync());
        Assert.False(await _site.Sessions.IsLiveAsync(alice.SessionId, touch: false));
        Assert.True(await _site.Sessions.IsLiveAsync(bob.SessionId, touch: false));
    }

    // ---- directory revalidation ----

    [Fact]
    public async Task A_disabled_account_loses_every_session_at_the_first_revalidation_after_the_interval()
    {
        var (alice, groupId, entryId) = await AliceWithAnEntryAsync();
        await _site.Groups.AddMemberAsync(alice, groupId, "bob", "Bob", Harpo.Data.GroupRole.Member);
        var bob = await _site.SignInAsync("bob");
        var bobsOtherTab = await _site.SignInAsync("bob");
        Assert.Equal("hunter2", await _site.Vault.RevealPasswordAsync(bob, entryId));

        _site.DevDirectory.DevUsers.RemoveAll(u => u.Username == "bob"); // disabled in the directory

        // Not before the interval: the sweep has nothing due yet.
        _site.Time.Advance(TimeSpan.FromMinutes(14));
        Assert.Equal(0, await _site.Sessions.RevalidateDueAsync());
        Assert.Equal("hunter2", await _site.Vault.RevealPasswordAsync(bob, entryId));

        // At the interval: both of bob's sessions end; alice's is untouched.
        _site.Time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(2, await _site.Sessions.RevalidateDueAsync());
        await AssertSessionEndedAsync(() => _site.Vault.RevealPasswordAsync(bob, entryId));
        await AssertSessionEndedAsync(() => _site.Vault.GetOfflineDataAsync(bobsOtherTab));
        Assert.Equal("hunter2", await _site.Vault.RevealPasswordAsync(alice, entryId));
    }

    [Fact]
    public async Task Losing_site_admin_in_the_directory_ends_the_session_so_the_role_is_not_kept()
    {
        var alice = await _site.SignInAsync("alice");
        Assert.True(alice.IsSiteAdmin);
        _site.DevDirectory.DevUsers.Single(u => u.Username == "alice").IsSiteAdmin = false;

        _site.Time.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(1, await _site.Sessions.RevalidateDueAsync());

        await AssertSessionEndedAsync(() => _site.Audit.GetEventsAsync(alice));
        await AssertSessionEndedAsync(() => _site.Groups.GetPersonalVaultsAsync(alice));
    }

    [Fact]
    public async Task An_unchanged_account_is_revalidated_and_not_due_again_for_another_interval()
    {
        var alice = await _site.SignInAsync("alice");
        _site.Time.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(0, await _site.Sessions.RevalidateDueAsync());

        // Re-checked at minute 15, so a directory change right after it is
        // picked up at minute 30, not before.
        _site.DevDirectory.DevUsers.RemoveAll(u => u.Username == "alice");
        _site.Time.Advance(TimeSpan.FromMinutes(14));
        Assert.Equal(0, await _site.Sessions.RevalidateDueAsync());
        await _site.Groups.GetMyGroupsAsync(alice);

        _site.Time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, await _site.Sessions.RevalidateDueAsync());
        await AssertSessionEndedAsync(() => _site.Groups.GetMyGroupsAsync(alice));
    }

    [Fact]
    public async Task Revalidation_can_be_turned_off()
    {
        _site.SessionOptions.RevalidateMinutes = 0;
        var bob = await _site.SignInAsync("bob");
        _site.DevDirectory.DevUsers.RemoveAll(u => u.Username == "bob");

        _site.Time.Advance(TimeSpan.FromHours(7));
        Assert.Equal(0, await _site.Sessions.RevalidateDueAsync());
        await _site.Groups.GetMyGroupsAsync(bob); // bounded only by its lifetime now
    }

    /// <summary>A directory whose answer the test sets.</summary>
    private sealed class ScriptedDirectory : IAuthenticator
    {
        public RevalidationResult Answer { get; set; } = RevalidationResult.Active(false);
        public int Calls { get; private set; }

        public Task<AuthResult?> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            Task.FromResult<AuthResult?>(new AuthResult(username, username, false));

        public Task<RevalidationResult> RevalidateAsync(string username, CancellationToken ct)
        {
            Calls++;
            return Answer == RevalidationResult.Unavailable && Calls % 2 == 0
                ? throw new InvalidOperationException("an authenticator that throws counts as unavailable")
                : Task.FromResult(Answer);
        }
    }

    private SessionService SessionsOver(IAuthenticator directory, AuthSessionOptions options) =>
        new(_site.Db, directory, Options.Create(options), _site.Time, NullLogger<SessionService>.Instance);

    [Fact]
    public async Task An_unreachable_directory_keeps_sessions_for_the_grace_period_then_ends_them()
    {
        var directory = new ScriptedDirectory();
        var sessions = SessionsOver(directory, new AuthSessionOptions { RevalidateMinutes = 15, RevalidateGraceMinutes = 60 });
        var id = await sessions.CreateAsync(new AuthResult("carol", "Carol", false));

        directory.Answer = RevalidationResult.Unavailable;
        // Sweeps every 30 s from the moment it falls due until just before the
        // grace runs out: retried each time, the session survives.
        _site.Time.Advance(TimeSpan.FromMinutes(15));
        for (var elapsed = TimeSpan.Zero; elapsed < TimeSpan.FromMinutes(60); elapsed += SessionService.SweepInterval)
        {
            Assert.Equal(0, await sessions.RevalidateDueAsync());
            Assert.True(await sessions.IsLiveAsync(id));
            _site.Time.Advance(SessionService.SweepInterval);
        }
        Assert.True(directory.Calls > 100);

        // 15 + 60 minutes without the directory vouching for the account: over.
        Assert.False(await sessions.IsLiveAsync(id, touch: false));
        Assert.Equal(0, await sessions.RevalidateDueAsync()); // already gone
    }

    [Fact]
    public async Task A_directory_back_within_the_grace_period_resumes_normal_revalidation()
    {
        var directory = new ScriptedDirectory { Answer = RevalidationResult.Unavailable };
        var sessions = SessionsOver(directory, new AuthSessionOptions { RevalidateMinutes = 15, RevalidateGraceMinutes = 60 });
        var id = await sessions.CreateAsync(new AuthResult("carol", "Carol", false));

        _site.Time.Advance(TimeSpan.FromMinutes(70));
        await sessions.RevalidateDueAsync();
        Assert.True(await sessions.IsLiveAsync(id));

        directory.Answer = RevalidationResult.Active(false);
        await sessions.RevalidateDueAsync();
        _site.Time.Advance(TimeSpan.FromMinutes(10)); // past the old grace end
        Assert.True(await sessions.IsLiveAsync(id));
    }

    [Fact]
    public async Task Without_a_way_to_ask_the_directory_sessions_run_to_their_lifetime()
    {
        // LDAP without Auth:Ldap:ServiceUser answers Unknown.
        var directory = new ScriptedDirectory { Answer = RevalidationResult.Unknown };
        var sessions = SessionsOver(directory, new AuthSessionOptions());
        var id = await sessions.CreateAsync(new AuthResult("carol", "Carol", false));

        for (var i = 0; i < 7 * 4; i++) // seven hours of 15-minute sweeps
        {
            _site.Time.Advance(TimeSpan.FromMinutes(15));
            Assert.Equal(0, await sessions.RevalidateDueAsync());
        }
        Assert.True(await sessions.IsLiveAsync(id, touch: false));
        _site.Time.Advance(TimeSpan.FromHours(1));
        Assert.False(await sessions.IsLiveAsync(id, touch: false));
    }

    // ---- authenticators ----

    [Fact]
    public async Task Dev_authenticator_revalidates_from_its_user_list()
    {
        var dev = new DevAuthenticator(Options.Create(_site.DevDirectory));
        Assert.Equal(RevalidationResult.Active(true), await dev.RevalidateAsync("Alice", default));
        Assert.Equal(RevalidationResult.Active(false), await dev.RevalidateAsync("bob", default));
        Assert.Equal(RevalidationResult.Disabled, await dev.RevalidateAsync("mallory", default));
    }

    [Fact]
    public async Task Ldap_without_a_service_account_cannot_revalidate_and_says_so()
    {
        var ldap = new LdapAuthenticator(
            Options.Create(new LdapOptions { Server = "dc.invalid", SearchBase = "DC=corp,DC=example" }),
            NullLogger<LdapAuthenticator>.Instance);
        Assert.Equal(RevalidationResult.Unknown, await ldap.RevalidateAsync("alice", default));
    }

    [Fact]
    public void Ldap_refuses_a_service_account_without_a_password()
    {
        // An empty-password bind is an anonymous bind in AD.
        Assert.Throws<InvalidOperationException>(() => new LdapAuthenticator(
            Options.Create(new LdapOptions { Server = "dc.invalid", SearchBase = "DC=corp,DC=example", ServiceUser = "svc" }),
            NullLogger<LdapAuthenticator>.Instance));
    }

    [Fact]
    public async Task Ldap_with_an_unreachable_server_reports_unavailable_not_disabled()
    {
        var ldap = new LdapAuthenticator(
            Options.Create(new LdapOptions
            {
                Server = "127.0.0.1", Port = 1, UseSsl = false, TimeoutSeconds = 2,
                SearchBase = "DC=corp,DC=example", ServiceUser = "svc@corp.example", ServicePassword = "x",
            }),
            NullLogger<LdapAuthenticator>.Instance);
        Assert.Equal(RevalidationResult.Unavailable, await ldap.RevalidateAsync("alice", default));
    }
}
