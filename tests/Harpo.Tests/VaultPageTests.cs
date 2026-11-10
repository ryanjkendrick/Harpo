using Harpo.Data;
using Harpo.Services;

namespace Harpo.Tests;

/// <summary>
/// The vault page loads one page of entries at a time (VaultService.GetEntryPageAsync):
/// the same entries, order and search as loading the whole vault, a page at a time.
/// </summary>
public class VaultPageTests : IDisposable
{
    private readonly TestSite _site = new("alpha");

    public void Dispose() => _site.Dispose();

    private async Task<Group> GroupWithEntriesAsync(UserContext admin, int count, params (string User, GroupRole Role)[] members)
    {
        var group = await _site.Groups.CreateGroupAsync(admin, "Ops", "");
        foreach (var (member, role) in members)
        {
            await _site.Groups.AddMemberAsync(admin, group.Id, member, "", role);
        }
        for (var i = 0; i < count; i++)
        {
            await _site.Vault.CreateEntryAsync(admin, group.Id, $"Entry {i:000}", "🔐", $"https://host{i % 7}.example.com",
                i % 2 == 0 ? "admin" : $"user{i}", i % 3 == 0 ? $"note {i}" : "", $"pw-{i}");
        }
        return group;
    }

    [Fact]
    public async Task Pages_cover_the_vault_in_the_same_order_as_loading_it_whole()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 23);
        var whole = await _site.Vault.GetEntriesAsync(alice, group.Id);

        var paged = new List<EntryView>();
        for (var page = 1; page <= 3; page++)
        {
            var result = await _site.Vault.GetEntryPageAsync(alice, group.Id, null, page, 10);
            Assert.Equal((page, 3, 23, 23), (result.Page, result.PageCount, result.Matching, result.InVault));
            paged.AddRange(result.Items);
        }

        Assert.Equal(new[] { 10, 10, 3 }.Sum(), paged.Count);
        Assert.Equal(whole.Select(v => v.Entry.Id), paged.Select(v => v.Entry.Id));
        // Each item is complete: notes decrypted, who last changed the password.
        Assert.Equal(whole.Select(v => (v.Notes, v.PasswordUpdatedBy)), paged.Select(v => (v.Notes, v.PasswordUpdatedBy)));
        Assert.Contains(paged, v => v.Notes == "note 3");
    }

    [Fact]
    public async Task A_page_past_the_end_comes_back_as_the_last_page()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 12);

        var result = await _site.Vault.GetEntryPageAsync(alice, group.Id, null, 99, 5);
        Assert.Equal((3, 3), (result.Page, result.PageCount));
        Assert.Equal(new[] { "Entry 010", "Entry 011" }, result.Items.Select(v => v.Entry.Name));

        var empty = await _site.Vault.GetEntryPageAsync(alice, (await _site.Groups.CreateGroupAsync(alice, "Empty", "")).Id, null, 4, 5);
        Assert.Equal((1, 1, 0, 0), (empty.Page, empty.PageCount, empty.Matching, empty.InVault));
        Assert.Empty(empty.Items);
    }

    [Fact]
    public async Task Search_matches_name_url_or_username_ignoring_case_in_any_alphabet()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 10);
        await _site.Vault.CreateEntryAsync(alice, group.Id, "Ünïcödé Bank", "🏦", "", "", "", "pw");
        await _site.Vault.CreateEntryAsync(alice, group.Id, "Router", "🛠️", "https://ROUTER.corp.example", "", "", "pw");

        async Task<string[]> Names(string term) =>
            (await _site.Vault.GetEntryPageAsync(alice, group.Id, term, 1, 50)).Items.Select(v => v.Entry.Name).ToArray();

        Assert.Equal(new[] { "Ünïcödé Bank" }, await Names("üNÏ"));        // not just ASCII
        Assert.Equal(new[] { "Router" }, await Names("router.CORP"));       // the URL
        Assert.Equal(new[] { "Entry 003" }, await Names("USER3"));          // the username
        Assert.Equal(5, (await _site.Vault.GetEntryPageAsync(alice, group.Id, "  admin  ", 1, 50)).Matching); // trimmed
        Assert.Empty(await Names("nothing like this"));

        var searched = await _site.Vault.GetEntryPageAsync(alice, group.Id, "entry", 2, 4);
        Assert.Equal((2, 3, 10, 12), (searched.Page, searched.PageCount, searched.Matching, searched.InVault));
        Assert.Equal(new[] { "Entry 004", "Entry 005", "Entry 006", "Entry 007" }, searched.Items.Select(v => v.Entry.Name));
    }

    [Fact]
    public async Task Deleted_entries_are_not_on_any_page()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 6);
        var victim = (await _site.Vault.GetEntriesAsync(alice, group.Id)).First(v => v.Entry.Name == "Entry 002");
        await _site.Vault.DeleteEntryAsync(alice, victim.Entry.Id);

        var result = await _site.Vault.GetEntryPageAsync(alice, group.Id, null, 1, 50);
        Assert.Equal(5, result.InVault);
        Assert.DoesNotContain(result.Items, v => v.Entry.Id == victim.Entry.Id);
    }

    [Fact]
    public async Task The_same_rights_as_loading_the_whole_vault()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 3, ("bob", GroupRole.Viewer));
        var bob = await _site.SignInAsync("bob");
        var carol = await _site.SignInAsync("carol");

        Assert.Equal(3, (await _site.Vault.GetEntryPageAsync(bob, group.Id, null, 1, 50)).Items.Count); // a viewer reads
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Vault.GetEntryPageAsync(carol, group.Id, null, 1, 50));

        // Nobody else reads a personal vault, site admins included.
        var bobsVault = await _site.Groups.EnsurePersonalVaultAsync(bob);
        await _site.Vault.CreateEntryAsync(bob, bobsVault.Id, "Mine", "🔐", "", "", "", "pw");
        await Assert.ThrowsAnyAsync<Exception>(() => _site.Vault.GetEntryPageAsync(alice, bobsVault.Id, null, 1, 50));
        Assert.Single((await _site.Vault.GetEntryPageAsync(bob, bobsVault.Id, null, 1, 50)).Items);

        // An ended session reads nothing.
        await _site.Sessions.EndAsync(bob.SessionId);
        await Assert.ThrowsAnyAsync<Exception>(() => _site.Vault.GetEntryPageAsync(bob, group.Id, null, 1, 50));
    }

    [Fact]
    public async Task Paging_without_a_search_agrees_with_a_search_that_matches_everything()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 0);
        var names = new[] { "zebra x", "Apple x", "apple x", "Ünï x", "éa x", "Same x", "Same x", "Same x", "10 x", "9 x", "_ x" };
        foreach (var name in names)
        {
            await _site.Vault.CreateEntryAsync(alice, group.Id, name, "🔑", "", "", "", "pw");
        }
        var deleted = await _site.Vault.CreateEntryAsync(alice, group.Id, "Deleted x", "🔑", "", "", "", "pw");
        await _site.Vault.DeleteEntryAsync(alice, deleted.Id);

        async Task<(List<Guid> Ids, List<EntryPage> Pages)> Walk(string? term)
        {
            var pages = new List<EntryPage>();
            for (var page = 1; page <= 4; page++)
            {
                pages.Add(await _site.Vault.GetEntryPageAsync(alice, group.Id, term, page, 3));
            }
            return (pages.SelectMany(p => p.Items).Select(v => v.Entry.Id).ToList(), pages);
        }

        var (paged, pagedPages) = await Walk(null);
        var (searched, searchedPages) = await Walk("x");

        Assert.Equal(names.Length, paged.Distinct().Count());
        Assert.Equal(searched, paged);
        Assert.Equal(
            searchedPages.Select(p => (p.Page, p.PageCount, p.Matching, p.InVault)),
            pagedPages.Select(p => (p.Page, p.PageCount, p.Matching, p.InVault)));
        Assert.Equal(paged, (await Walk("   ")).Ids); // blank is no search
    }

    [Fact]
    public async Task A_page_size_below_one_is_refused()
    {
        var alice = await _site.SignInAsync("alice");
        var group = await GroupWithEntriesAsync(alice, 1);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _site.Vault.GetEntryPageAsync(alice, group.Id, null, 1, 0));
    }
}
