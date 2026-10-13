using Harpo.Data;
using Harpo.Services;

namespace Harpo.Tests;

/// <summary>
/// Global search: finding an entry by name, URL or username across every vault
/// the user can see, with the vault named in the result — and never reaching a
/// group, or a personal vault, the group listing would not show.
/// </summary>
public class SearchTests : IDisposable
{
    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _root = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    private Task<PasswordEntry> AddAsync(
        UserContext user, Guid groupId, string name, string url = "", string username = "") =>
        _site.Vault.CreateEntryAsync(user, groupId, name, "🔐", url, username, "", "pw");

    [Fact]
    public async Task Finds_matches_across_every_group_the_user_is_in_with_the_group_named()
    {
        var infra = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var marketing = await _site.Groups.CreateGroupAsync(_alice, "Marketing", "");
        await AddAsync(_alice, infra.Id, "Router admin");
        await AddAsync(_alice, marketing.Id, "Corporate Twitter", username: "router-bot");
        await AddAsync(_alice, marketing.Id, "Unrelated");

        var hits = await _site.Vault.SearchEntriesAsync(_alice, "router");

        Assert.Equal(["Corporate Twitter", "Router admin"], hits.Select(h => h.Name));
        var twitter = hits[0];
        Assert.Equal(marketing.Id, twitter.GroupId);
        Assert.Equal("Marketing", twitter.GroupName);
        Assert.False(twitter.GroupIsPersonal);
        Assert.Equal("router-bot", twitter.Username);
        Assert.Equal(infra.Id, hits[1].GroupId);
    }

    [Fact]
    public async Task Does_not_look_in_groups_the_user_is_not_a_member_of()
    {
        var mine = await _site.Groups.CreateGroupAsync(_alice, "Mine", "");
        var theirs = await _site.Groups.CreateGroupAsync(_bob, "Theirs", "");
        await AddAsync(_alice, mine.Id, "Shared secret one");
        await AddAsync(_bob, theirs.Id, "Shared secret two");

        var hits = await _site.Vault.SearchEntriesAsync(_alice, "shared secret");

        Assert.Equal("Shared secret one", Assert.Single(hits).Name);

        // Removed from a group, the user stops finding what is in it.
        await _site.Groups.AddMemberAsync(_bob, theirs.Id, "alice", "", GroupRole.Member);
        Assert.Equal(2, (await _site.Vault.SearchEntriesAsync(_alice, "shared secret")).Count);
        await _site.Groups.RemoveMemberAsync(_bob, theirs.Id, "alice");
        Assert.Single(await _site.Vault.SearchEntriesAsync(_alice, "shared secret"));
    }

    [Fact]
    public async Task Skips_deleted_entries_and_deleted_groups()
    {
        var live = await _site.Groups.CreateGroupAsync(_alice, "Live", "");
        var doomed = await _site.Groups.CreateGroupAsync(_alice, "Doomed", "");
        var trashed = await AddAsync(_alice, live.Id, "Old login");
        await AddAsync(_alice, live.Id, "Old login kept");
        await AddAsync(_alice, doomed.Id, "Old login in a doomed group");
        await _site.Vault.DeleteEntryAsync(_alice, trashed.Id);
        await _site.Groups.DeleteGroupAsync(_alice, doomed.Id);

        var hits = await _site.Vault.SearchEntriesAsync(_alice, "old login");

        Assert.Equal("Old login kept", Assert.Single(hits).Name);
    }

    [Fact]
    public async Task A_site_admin_finds_shared_groups_but_not_someone_elses_personal_vault()
    {
        var shared = await _site.Groups.CreateGroupAsync(_alice, "Infra", ""); // root is not a member
        await AddAsync(_alice, shared.Id, "Bank (shared)");
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(_bob);
        await AddAsync(_bob, bobsVault.Id, "Bank (bob private)");

        var hits = await _site.Vault.SearchEntriesAsync(_root, "bank");

        var hit = Assert.Single(hits);
        Assert.Equal("Bank (shared)", hit.Name);
        Assert.Equal(shared.Id, hit.GroupId);
    }

    [Fact]
    public async Task The_owner_finds_their_own_personal_entry_labelled_with_the_vault()
    {
        var vault = await _site.Groups.EnsurePersonalVaultAsync(_alice);
        await AddAsync(_alice, vault.Id, "Tax portal");
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(_bob);
        await AddAsync(_bob, bobsVault.Id, "Tax portal (bob)");

        var hit = Assert.Single(await _site.Vault.SearchEntriesAsync(_alice, "tax"));

        Assert.Equal("Tax portal", hit.Name);
        Assert.Equal(vault.Id, hit.GroupId);
        Assert.Equal(GroupService.PersonalVaultName, hit.GroupName);
        Assert.True(hit.GroupIsPersonal);

        // Bob sees his own and nothing of alice's.
        Assert.Equal("Tax portal (bob)", Assert.Single(await _site.Vault.SearchEntriesAsync(_bob, "tax")).Name);
    }

    [Fact]
    public async Task A_membership_row_does_not_open_someone_elses_personal_vault_to_search()
    {
        // Mirrors the group listing, which refuses the same thing.
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(_bob);
        await AddAsync(_bob, bobsVault.Id, "Diary login");
        await using (var db = _site.Db.CreateDbContext())
        {
            db.GroupMembers.Add(new GroupMember
            {
                Id = Guid.NewGuid(), GroupId = bobsVault.Id, Username = "alice", DisplayName = "Alice", Role = GroupRole.Admin,
            });
            await db.SaveChangesAsync();
        }

        Assert.Empty(await _site.Vault.SearchEntriesAsync(_alice, "diary"));
        Assert.Empty(await _site.Vault.SearchEntriesAsync(_root, "diary"));
    }

    [Theory]
    [InlineData("GITLAB.COM")]
    [InlineData("gitlab")]
    [InlineData("DEPLOY-BOT")]
    [InlineData("  deploy-bot  ")]
    public async Task Matching_is_case_insensitive_on_url_and_username_and_the_term_is_trimmed(string term)
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Dev", "");
        await AddAsync(_alice, group.Id, "CI", url: "https://gitlab.com/admin", username: "Deploy-Bot");

        Assert.Equal("CI", Assert.Single(await _site.Vault.SearchEntriesAsync(_alice, term)).Name);
    }

    [Fact]
    public async Task Matching_ignores_case_beyond_ascii_like_the_vault_page_does()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Dev", "");
        await AddAsync(_alice, group.Id, "Éclair shop");

        Assert.Single(await _site.Vault.SearchEntriesAsync(_alice, "éclair"));
    }

    [Fact]
    public async Task Notes_and_passwords_are_not_searched()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Dev", "");
        await _site.Vault.CreateEntryAsync(
            _alice, group.Id, "Vault door", "🔐", "", "", "recovery code zebra-9", "pw-quokka");

        Assert.Empty(await _site.Vault.SearchEntriesAsync(_alice, "zebra"));
        Assert.Empty(await _site.Vault.SearchEntriesAsync(_alice, "quokka"));
        Assert.Single(await _site.Vault.SearchEntriesAsync(_alice, "door"));
    }

    [Fact]
    public async Task The_limit_caps_the_result_after_ordering_by_name_then_group()
    {
        var zed = await _site.Groups.CreateGroupAsync(_alice, "Zed", "");
        var amy = await _site.Groups.CreateGroupAsync(_alice, "Amy", "");
        for (var i = 1; i <= 4; i++)
        {
            await AddAsync(_alice, zed.Id, $"Login {i}");
        }
        await AddAsync(_alice, amy.Id, "Login 1");

        var hits = await _site.Vault.SearchEntriesAsync(_alice, "login", limit: 3);

        Assert.Equal(3, hits.Count);
        Assert.Equal(["Login 1", "Login 1", "Login 2"], hits.Select(h => h.Name));
        Assert.Equal(["Amy", "Zed", "Zed"], hits.Select(h => h.GroupName));
        Assert.Equal(5, (await _site.Vault.SearchEntriesAsync(_alice, "login")).Count);
        Assert.Empty(await _site.Vault.SearchEntriesAsync(_alice, "login", limit: 0));
    }

    [Fact]
    public async Task One_vault_can_be_left_out_so_its_hits_do_not_use_up_the_limit()
    {
        var open = await _site.Groups.CreateGroupAsync(_alice, "Open", "");
        var other = await _site.Groups.CreateGroupAsync(_alice, "Other", "");
        for (var i = 1; i <= 3; i++)
        {
            await AddAsync(_alice, open.Id, $"Login {i}");
        }
        await AddAsync(_alice, other.Id, "Login elsewhere");

        var hits = await _site.Vault.SearchEntriesAsync(_alice, "login", limit: 2, excludeGroupId: open.Id);

        Assert.Equal("Login elsewhere", Assert.Single(hits).Name);
        Assert.Equal(2, (await _site.Vault.SearchEntriesAsync(_alice, "login", limit: 2)).Count);
    }

    [Fact]
    public async Task A_viewer_finds_entries_in_their_viewer_group()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Finance", "");
        await AddAsync(_alice, group.Id, "Payroll");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "Bob", GroupRole.Viewer);

        var hit = Assert.Single(await _site.Vault.SearchEntriesAsync(_bob, "payroll"));

        Assert.Equal(group.Id, hit.GroupId);
        Assert.Equal("Finance", hit.GroupName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task An_empty_term_finds_nothing(string term)
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Dev", "");
        await AddAsync(_alice, group.Id, "Something");

        Assert.Empty(await _site.Vault.SearchEntriesAsync(_alice, term));
    }

    [Fact]
    public async Task A_search_from_an_ended_session_is_refused()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await _site.Groups.CreateGroupAsync(alice, "Dev", "");
        await AddAsync(alice, group.Id, "Something");
        Assert.Single(await _site.Vault.SearchEntriesAsync(alice, "some"));

        await _site.Sessions.EndAsync(alice.SessionId);

        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.SearchEntriesAsync(alice, "some"));
        // Even an empty term: the session check comes first, as for every other call.
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.SearchEntriesAsync(alice, ""));
    }
}
