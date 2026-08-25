using Harpo.Data;
using Harpo.Security;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

public class PasswordStrengthTests
{
    [Theory]
    [InlineData("password", 0)]
    [InlineData("Password2024!", 0)]   // common word with decoration
    [InlineData("12345678", 0)]
    [InlineData("qwerty", 0)]
    [InlineData("aaaaaaaaaaaa", 0)]    // two-ish distinct chars
    public void Terrible_passwords_score_zero(string password, int expected) =>
        Assert.Equal(expected, PasswordStrength.Score(password));

    [Fact]
    public void Short_but_varied_beats_long_but_lazy()
    {
        Assert.True(PasswordStrength.Score("kX9$mQ2v") >= 2);
        Assert.True(PasswordStrength.Score("abcdefghijkl") <= 1); // sequential run penalty
    }

    [Fact]
    public void Generated_passwords_score_strong()
    {
        for (var i = 0; i < 10; i++)
        {
            Assert.Equal(4, PasswordStrength.Score(PasswordGenerator.Generate()));
        }
    }

    [Fact]
    public void Labels_cover_all_buckets()
    {
        Assert.Equal("terrible", PasswordStrength.Label(0));
        Assert.Equal("strong", PasswordStrength.Label(4));
        Assert.Equal("unscored", PasswordStrength.Label(null));
    }
}

public class FingerprintTests
{
    [Fact]
    public void Fingerprints_are_deterministic_per_master_key()
    {
        var a = new CryptoService("shared key");
        var b = new CryptoService("shared key");
        var other = new CryptoService("different key");

        Assert.Equal(a.Fingerprint("hunter2"), b.Fingerprint("hunter2"));
        Assert.NotEqual(a.Fingerprint("hunter2"), a.Fingerprint("hunter3"));
        Assert.NotEqual(a.Fingerprint("hunter2"), other.Fingerprint("hunter2"));
        // Fingerprints must never equal the ciphertext or leak structure.
        Assert.NotEqual(a.Fingerprint("hunter2"), a.Encrypt("hunter2"));
    }
}

public class HealthServiceTests : IDisposable
{
    private readonly TestSite _site = new("test");
    private readonly UserContext _alice = TestSite.User("alice");
    private readonly UserContext _bob = TestSite.User("bob");
    private readonly UserContext _admin = TestSite.User("root", siteAdmin: true);

    public void Dispose() => _site.Dispose();

    [Fact]
    public async Task Report_finds_weak_reused_and_stale_passwords()
    {
        var infra = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Old Switch", "🌐", "", "", "", "Zx9$Qm2vTr8&Lp4!");
        _site.Time.Advance(TimeSpan.FromDays(400)); // ages the first entry past staleness
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Router A", "🌐", "", "", "", "shared-secret-99");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Router B", "🌐", "", "", "", "shared-secret-99");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Bad Wifi", "📶", "", "", "", "password");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Fine", "🔐", "", "", "", PasswordGenerator.Generate());

        var report = await _site.Health.GetReportAsync(_admin);

        Assert.NotNull(report);
        Assert.Equal(5, report.Analyzed);
        Assert.Equal("Bad Wifi", Assert.Single(report.Weak).Name);
        var cluster = Assert.Single(report.Reused);
        Assert.Equal(new[] { "Router A", "Router B" }, cluster.Entries.Select(e => e.Name));
        Assert.Equal(0, cluster.HiddenCount);
        Assert.Equal("Old Switch", Assert.Single(report.Stale).Name);
        // Weak (Bad Wifi) + reused (Router A, B) + stale (Old Switch) = 4 findings → only "Fine" is healthy.
        Assert.Equal(1, report.HealthyCount);
    }

    [Fact]
    public async Task Group_admin_sees_own_names_and_only_counts_for_external_reuse()
    {
        var infra = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        var hr = await _site.Groups.CreateGroupAsync(_alice, "HR", "");
        await _site.Vault.CreateEntryAsync(_alice, infra.Id, "Router", "🌐", "", "", "", "same-everywhere-1");
        await _site.Vault.CreateEntryAsync(_alice, hr.Id, "Payroll", "💳", "", "", "", "same-everywhere-1");
        // bob administers Infra only.
        await _site.Groups.AddMemberAsync(_alice, infra.Id, "bob", "", GroupRole.Admin);

        var report = await _site.Health.GetReportAsync(_bob);

        Assert.NotNull(report);
        Assert.Equal(1, report.Analyzed); // only Infra is in bob's scope
        var cluster = Assert.Single(report.Reused);
        Assert.Equal("Router", Assert.Single(cluster.Entries).Name); // HR's entry name never leaks
        Assert.Equal(1, cluster.HiddenCount);
    }

    [Fact]
    public async Task Members_and_viewers_get_no_report()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Groups.AddMemberAsync(_alice, group.Id, "bob", "", GroupRole.Member);

        Assert.Null(await _site.Health.GetReportAsync(_bob));
    }

    [Fact]
    public async Task Pre_upgrade_rows_are_healed_without_touching_replication_stamps()
    {
        var group = await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Vault.CreateEntryAsync(_alice, group.Id, "A", "🌐", "", "", "", "same-pass-both-1");
        await _site.Vault.CreateEntryAsync(_alice, group.Id, "B", "🌐", "", "", "", "same-pass-both-1");

        // Simulate rows written before the health feature existed.
        long seqBefore;
        await using (var db = _site.Db.CreateDbContext())
        {
            db.SuppressReplicationStamping = true;
            foreach (var r in db.PasswordRevisions.ToList())
            {
                r.Fingerprint = null;
                r.Strength = null;
            }
            await db.SaveChangesAsync();
            seqBefore = db.PasswordRevisions.Max(r => r.OriginSeq);
        }

        var report = await _site.Health.GetReportAsync(_admin);
        Assert.NotNull(report);
        Assert.Single(report.Reused); // healing recomputed fingerprints

        await using (var check = _site.Db.CreateDbContext())
        {
            Assert.Equal(0, await check.PasswordRevisions.CountAsync(r => r.Fingerprint == null));
            // Healing must not restamp: sequences unchanged, so nothing re-replicates.
            Assert.Equal(seqBefore, await check.PasswordRevisions.MaxAsync(r => r.OriginSeq));
        }
    }

    [Fact]
    public async Task Fingerprints_replicate_so_cross_site_reuse_is_visible()
    {
        var clock = new ManualTime();
        using var alpha = new TestSite("alpha", clock);
        using var beta = new TestSite("beta", clock);
        var alice = TestSite.User("alice");
        var admin = TestSite.User("root", siteAdmin: true);

        var groupA = await alpha.Groups.CreateGroupAsync(alice, "Alpha Group", "");
        await alpha.Vault.CreateEntryAsync(alice, groupA.Id, "Alpha Entry", "🌐", "", "", "", "cross-site-same-1");
        await beta.PullFromAsync(alpha, viaJson: true);

        var groupB = await beta.Groups.CreateGroupAsync(alice, "Beta Group", "");
        await beta.Vault.CreateEntryAsync(alice, groupB.Id, "Beta Entry", "🌐", "", "", "", "cross-site-same-1");

        var report = await beta.Health.GetReportAsync(admin);
        Assert.NotNull(report);
        var cluster = Assert.Single(report.Reused);
        Assert.Equal(2, cluster.Entries.Count); // reuse across sites detected from replicated fingerprints
    }

    [Fact]
    public async Task Report_is_audited()
    {
        await _site.Groups.CreateGroupAsync(_alice, "Infra", "");
        await _site.Health.GetReportAsync(_admin);
        Assert.Contains(await _site.Audit.GetEventsAsync(_admin), e => e.Action == AuditActions.HealthReport);
    }
}
