using Harpo.Components.Shared;
using Harpo.Data;
using Harpo.Services;

namespace Harpo.Tests;

/// <summary>The audit log's numbered pages, and the page arithmetic the other admin lists share.</summary>
public class AuditPageTests : IDisposable
{
    private readonly TestSite _site = new("test");
    private readonly UserContext _admin = TestSite.User("root", siteAdmin: true);
    private readonly DateTime _start = new(2026, 11, 1, 9, 0, 0, DateTimeKind.Utc);

    public void Dispose() => _site.Dispose();

    /// <summary>Events one minute apart, oldest first, as (username, action, target, detail).</summary>
    private async Task SeedAsync(params (string User, string Action, string Target, string Detail)[] events)
    {
        await using var db = _site.Db.CreateDbContext();
        for (var i = 0; i < events.Length; i++)
        {
            var (user, action, target, detail) = events[i];
            db.AuditEvents.Add(new AuditEvent
            {
                Id = Guid.NewGuid(), OccurredAtUtc = _start.AddMinutes(i), Username = user, Action = action,
                Target = target, Detail = detail, OriginSiteId = "test", OriginSeq = i + 1, UpdatedAtUtc = _start.AddMinutes(i),
            });
        }
        await db.SaveChangesAsync();
    }

    private Task SeedRevealsAsync(int count) =>
        SeedAsync([.. Enumerable.Range(1, count).Select(i => ("alice", AuditActions.PasswordReveal, $"Entry {i:00} (Infra)", ""))]);

    [Fact]
    public async Task Pages_are_numbered_newest_first_with_a_total()
    {
        await SeedRevealsAsync(23);

        var first = await _site.Audit.GetEventPageAsync(_admin, page: 1, pageSize: 10);
        Assert.Equal((1, 3, 23), (first.Page, first.PageCount, first.Total));
        Assert.Equal("Entry 23 (Infra)", first.Items[0].Target);
        Assert.Equal(10, first.Items.Count);

        var last = await _site.Audit.GetEventPageAsync(_admin, page: 3, pageSize: 10);
        Assert.Equal(["Entry 03 (Infra)", "Entry 02 (Infra)", "Entry 01 (Infra)"], last.Items.Select(e => e.Target));

        // Every event on exactly one page.
        var all = new List<Guid>();
        for (var p = 1; p <= 3; p++)
        {
            all.AddRange((await _site.Audit.GetEventPageAsync(_admin, page: p, pageSize: 10)).Items.Select(e => e.Id));
        }
        Assert.Equal(23, all.Distinct().Count());
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(99, 3)] // a page that no longer exists (events expired, a filter narrowed it) gives the last one
    public async Task A_page_out_of_range_is_pulled_back(int asked, int given)
    {
        await SeedRevealsAsync(23);
        var page = await _site.Audit.GetEventPageAsync(_admin, page: asked, pageSize: 10);
        Assert.Equal(given, page.Page);
        Assert.NotEmpty(page.Items);
    }

    [Fact]
    public async Task An_empty_trail_is_one_empty_page()
    {
        var page = await _site.Audit.GetEventPageAsync(_admin);
        Assert.Equal((1, 1, 0), (page.Page, page.PageCount, page.Total));
        Assert.Empty(page.Items);
    }

    [Fact]
    public async Task Search_covers_every_event_not_just_one_page_and_combines_with_the_category()
    {
        // The match for "router" is the oldest event: on the last page of an unfiltered list.
        await SeedAsync(
            ("bob", AuditActions.PasswordCopy, "Core Router (Infra)", ""),
            ("bob", AuditActions.MemberAdd, "Infra", "carol as member"));
        await SeedRevealsAsync(60);

        var byTarget = await _site.Audit.GetEventPageAsync(_admin, search: "ROUTER", pageSize: 10);
        Assert.Equal("Core Router (Infra)", Assert.Single(byTarget.Items).Target);
        Assert.Equal(1, byTarget.Total);

        var byUser = await _site.Audit.GetEventPageAsync(_admin, search: "bob");
        Assert.Equal(2, byUser.Total);
        var byDetail = await _site.Audit.GetEventPageAsync(_admin, search: "carol");
        Assert.Equal(AuditActions.MemberAdd, Assert.Single(byDetail.Items).Action);
        var byAction = await _site.Audit.GetEventPageAsync(_admin, search: "password.copy");
        Assert.Equal(1, byAction.Total);

        var bobsReveals = await _site.Audit.GetEventPageAsync(_admin, AuditCategory.Reveals, search: "bob");
        Assert.Equal(AuditActions.PasswordCopy, Assert.Single(bobsReveals.Items).Action);
        var revealsTotal = await _site.Audit.GetEventPageAsync(_admin, AuditCategory.Reveals, pageSize: 10);
        Assert.Equal((61, 7), (revealsTotal.Total, revealsTotal.PageCount));
    }

    [Theory]
    [InlineData("50%", "Discount 50% (Sales)")]
    [InlineData("a_b", "svc a_b (Infra)")]
    [InlineData(@"corp\svc", @"corp\svc (Infra)")]
    public async Task Search_takes_wildcard_characters_literally(string term, string only)
    {
        await SeedAsync(
            ("alice", AuditActions.PasswordReveal, "Discount 50% (Sales)", ""),
            ("alice", AuditActions.PasswordReveal, "Discount 500 (Sales)", ""),
            ("alice", AuditActions.PasswordReveal, "svc a_b (Infra)", ""),
            ("alice", AuditActions.PasswordReveal, "svc axb (Infra)", ""),
            ("alice", AuditActions.PasswordReveal, @"corp\svc (Infra)", ""),
            ("alice", AuditActions.PasswordReveal, "corpsvc (Infra)", ""));

        var page = await _site.Audit.GetEventPageAsync(_admin, search: term);
        Assert.Equal(only, Assert.Single(page.Items).Target);
    }

    [Fact]
    public async Task Only_site_admins_can_page_the_trail()
    {
        await Assert.ThrowsAsync<VaultAccessDeniedException>(() => _site.Audit.GetEventPageAsync(TestSite.User("alice")));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(25, 1)]
    [InlineData(26, 2)]
    [InlineData(100, 4)]
    public void Page_count_rounds_up_and_is_never_zero(int total, int pages)
    {
        Assert.Equal(pages, Paging.PageCount(total, 25));
    }

    [Fact]
    public void A_slice_pulls_its_page_back_inside_a_shorter_list()
    {
        var items = Enumerable.Range(1, 30).ToList();
        var page = 2;
        Assert.Equal(Enumerable.Range(26, 5), Paging.Slice(items, ref page, 25));

        // The list shrank (a filter, a removal) while page 2 was shown.
        page = 2;
        Assert.Equal(Enumerable.Range(1, 10), Paging.Slice(items.Take(10).ToList(), ref page, 25));
        Assert.Equal(1, page);

        page = 5;
        Assert.Empty(Paging.Slice(new List<int>(), ref page, 25));
        Assert.Equal(1, page);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(24, 1)]
    [InlineData(25, 2)]
    [InlineData(-1, 1)] // not in the list
    public void The_page_of_an_item_follows_its_position(int index, int page)
    {
        Assert.Equal(page, Paging.PageOf(index, 25));
    }
}
