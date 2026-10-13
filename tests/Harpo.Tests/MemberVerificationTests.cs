using Harpo.Data;
using Harpo.Security;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// Adding a member asks the directory who that is first: an unknown or
/// disabled name is refused, a known one is stored with the directory's own
/// name, and when the directory cannot be asked the membership is made but
/// marked (row, audit, result) as not checked.
/// </summary>
public class MemberVerificationTests : IDisposable
{
    private readonly TestSite _site = new("s1");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");

    public MemberVerificationTests()
    {
        _site.DevDirectory.DevUsers.Single(u => u.Username == "bob").DisplayName = "Bob Loblaw";
    }

    public void Dispose() => _site.Dispose();

    private async Task<GroupMember?> MemberAsync(Guid groupId, string username)
    {
        await using var db = _site.Db.CreateDbContext();
        return await db.GroupMembers.SingleOrDefaultAsync(m => m.GroupId == groupId && m.Username == username && !m.IsDeleted);
    }

    private async Task<List<string>> MemberAddDetailsAsync()
    {
        await using var db = _site.Db.CreateDbContext();
        return await db.AuditEvents.Where(e => e.Action == AuditActions.MemberAdd)
            .OrderBy(e => e.OriginSeq).Select(e => e.Detail).ToListAsync();
    }

    [Fact]
    public async Task A_directory_account_is_stored_with_the_directorys_name_not_the_typed_one()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");

        var added = await _site.Groups.AddMemberAsync(_alice, group.Id, " BOB ", "Robert Typo", GroupRole.Member);

        Assert.Equal(new MemberAdded("bob", "Bob Loblaw", true), added);
        var row = await MemberAsync(group.Id, "bob");
        Assert.NotNull(row);
        Assert.Equal("Bob Loblaw", row.DisplayName);
        Assert.True(row.Verified);
        Assert.Equal(["bob as Member"], await MemberAddDetailsAsync());
        // The creator's own row came from a sign-in, which the directory vouched for.
        Assert.True((await MemberAsync(group.Id, "alice"))!.Verified);
    }

    [Fact]
    public async Task A_disabled_account_is_refused()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        _site.DevDirectory.DevUsers.Single(u => u.Username == "carol").Disabled = true;

        var ex = await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Groups.AddMemberAsync(_alice, group.Id, "carol", "", GroupRole.Member));

        Assert.Equal("'carol' is disabled in the directory.", ex.Message);
        Assert.Null(await MemberAsync(group.Id, "carol"));
        Assert.Empty(await MemberAddDetailsAsync());
    }

    [Fact]
    public async Task An_account_the_directory_does_not_know_is_refused()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");

        var ex = await Assert.ThrowsAsync<VaultValidationException>(
            () => _site.Groups.AddMemberAsync(_alice, group.Id, "Nobody", "No One", GroupRole.Member));

        Assert.Equal("No account named 'nobody' in the directory.", ex.Message);
        Assert.Null(await MemberAsync(group.Id, "nobody"));
        Assert.Empty(await MemberAddDetailsAsync());
    }

    [Fact]
    public async Task Only_group_admins_learn_whether_an_account_exists()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);

        // Not "no account named …": the rights check comes before the lookup.
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Groups.AddMemberAsync(_bob, group.Id, "nobody", "", GroupRole.Member));
        await Assert.ThrowsAsync<VaultAccessDeniedException>(
            () => _site.Groups.SearchAccountsAsync(_bob, group.Id, "ca"));
    }

    [Fact]
    public async Task Without_a_directory_the_member_is_added_as_typed_and_marked_unverified()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        _site.Directory.Unavailable = true;

        var typed = await _site.Groups.AddMemberAsync(_alice, group.Id, "Bob", "Bobby", GroupRole.Viewer);
        var bare = await _site.Groups.AddMemberAsync(_alice, group.Id, "nobody", "", GroupRole.Member);

        Assert.Equal(new MemberAdded("bob", "Bobby", false), typed);
        Assert.Equal(new MemberAdded("nobody", "nobody", false), bare);
        var row = await MemberAsync(group.Id, "bob");
        Assert.Equal("Bobby", row!.DisplayName);
        Assert.False(row.Verified);
        Assert.False((await MemberAsync(group.Id, "nobody"))!.Verified);
        Assert.Equal(
            ["bob as Viewer (unverified: directory not available)", "nobody as Member (unverified: directory not available)"],
            await MemberAddDetailsAsync());
        // Access works as before: being unverified is information, not a restriction.
        Assert.Empty(await _site.Vault.GetEntriesAsync(_bob, group.Id));
    }

    [Fact]
    public async Task Re_adding_an_unverified_member_once_the_directory_answers_verifies_it()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        _site.Directory.Unavailable = true;
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bobby", GroupRole.Member);
        await _site.Groups.RemoveMemberAsync(_alice, group.Id, "bob");

        _site.Directory.Unavailable = false;
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);

        var row = await MemberAsync(group.Id, "bob");
        Assert.True(row!.Verified);
        Assert.Equal("Bob Loblaw", row.DisplayName);
    }

    [Fact]
    public async Task The_verified_flag_replicates()
    {
        using var beta = new TestSite("s2", _site.Time);
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);
        _site.Directory.Unavailable = true;
        await _site.Groups.AddMemberAsync(_alice, group.Id, "carol", "", GroupRole.Member);

        await beta.PullFromAsync(_site, viaJson: true);

        var members = await beta.Groups.GetMembersAsync(TestSite.User("root", siteAdmin: true), group.Id);
        Assert.True(members.Single(m => m.Username == "bob").Verified);
        Assert.False(members.Single(m => m.Username == "carol").Verified);
    }

    // ---- searching ----

    [Fact]
    public async Task Search_matches_account_prefix_and_display_name_substring_up_to_the_limit()
    {
        _site.DevDirectory.DevUsers.Add(new DevAuthOptions.DevUser { Username = "grace", DisplayName = "Grace Hopper" });
        _site.DevDirectory.DevUsers.Add(new DevAuthOptions.DevUser { Username = "ghopper2", DisplayName = "G. Hopper", Disabled = true });
        var dev = new DevAuthenticator(Options.Create(_site.DevDirectory));

        var byPrefix = await dev.SearchAccountsAsync("GR", 10, default);
        Assert.True(byPrefix.Available);
        Assert.Equal([new DirectoryAccount("grace", "Grace Hopper", false)], byPrefix.Accounts);

        var byDisplayName = await dev.SearchAccountsAsync("hopper", 10, default);
        Assert.Equal(["ghopper2", "grace"], byDisplayName.Accounts.Select(a => a.Username));
        Assert.True(byDisplayName.Accounts[0].Disabled);

        // "o" is in Bob Loblaw, Grace Hopper and G. Hopper; the limit keeps two.
        var limited = await dev.SearchAccountsAsync("o", 2, default);
        Assert.Equal(2, limited.Accounts.Count);

        Assert.Empty((await dev.SearchAccountsAsync("zz", 10, default)).Accounts);
        Assert.True((await dev.SearchAccountsAsync("zz", 10, default)).Available);
    }

    [Fact]
    public async Task Group_admins_search_through_the_service_and_learn_when_the_directory_is_unavailable()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        for (var i = 0; i < 15; i++)
        {
            _site.DevDirectory.DevUsers.Add(new DevAuthOptions.DevUser { Username = $"user{i:00}" });
        }

        var many = await _site.Groups.SearchAccountsAsync(_alice, group.Id, "user");
        Assert.True(many.Available);
        Assert.Equal(GroupService.AccountSuggestionLimit, many.Accounts.Count);

        var bob = await _site.Groups.SearchAccountsAsync(_alice, group.Id, "loblaw");
        Assert.Equal([new DirectoryAccount("bob", "Bob Loblaw", false)], bob.Accounts);

        _site.Directory.Unavailable = true;
        var unavailable = await _site.Groups.SearchAccountsAsync(_alice, group.Id, "bob");
        Assert.False(unavailable.Available);
        Assert.Empty(unavailable.Accounts);
    }

    [Fact]
    public async Task Dev_directory_looks_accounts_up_exactly()
    {
        var dev = new DevAuthenticator(Options.Create(_site.DevDirectory));
        Assert.Equal(DirectoryLookup.Found(new DirectoryAccount("bob", "Bob Loblaw", false)), await dev.LookupAccountAsync("BOB", default));
        Assert.Equal(DirectoryLookup.NotFound, await dev.LookupAccountAsync("bo", default));
    }

    [Fact]
    public async Task A_disabled_dev_user_cannot_sign_in_and_revalidates_as_disabled()
    {
        _site.DevDirectory.DevUsers.Single(u => u.Username == "carol").Disabled = true;
        var dev = new DevAuthenticator(Options.Create(_site.DevDirectory));
        Assert.Null(await dev.AuthenticateAsync("carol", "carol", default));
        Assert.Equal(RevalidationResult.Disabled, await dev.RevalidateAsync("carol", default));
    }

    // ---- LDAP ----

    [Fact]
    public async Task Ldap_without_a_service_account_reports_unavailable_and_never_throws()
    {
        var ldap = new LdapAuthenticator(
            Options.Create(new LdapOptions { Server = "dc.invalid", SearchBase = "DC=corp,DC=example" }),
            NullLogger<LdapAuthenticator>.Instance);

        Assert.Equal(DirectoryLookup.Unavailable, await ldap.LookupAccountAsync("alice", default));
        var search = await ldap.SearchAccountsAsync("al", 10, default);
        Assert.False(search.Available);
        Assert.Empty(search.Accounts);
    }

    [Fact]
    public async Task Ldap_with_an_unreachable_server_reports_unavailable_and_never_throws()
    {
        var ldap = new LdapAuthenticator(
            Options.Create(new LdapOptions
            {
                Server = "127.0.0.1", Port = 1, UseSsl = false, TimeoutSeconds = 2,
                SearchBase = "DC=corp,DC=example", ServiceUser = "svc@corp.example", ServicePassword = "x",
            }),
            NullLogger<LdapAuthenticator>.Instance);

        Assert.Equal(DirectoryLookup.Unavailable, await ldap.LookupAccountAsync("alice", default));
        Assert.False((await ldap.SearchAccountsAsync("al", 10, default)).Available);
    }
}
