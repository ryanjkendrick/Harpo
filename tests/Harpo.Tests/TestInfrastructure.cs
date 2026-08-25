using Harpo.Data;
using Harpo.Replication;
using Harpo.Security;
using Harpo.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>Controllable clock so tests can order writes deterministically.</summary>
public sealed class ManualTime : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

public sealed class TestDbFactory : IDbContextFactory<HarpoDbContext>
{
    private readonly DbContextOptions<HarpoDbContext> _options;
    private readonly TimeProvider _time;
    private readonly string _siteId;

    public TestDbFactory(DbContextOptions<HarpoDbContext> options, TimeProvider time, string siteId)
    {
        _options = options;
        _time = time;
        _siteId = siteId;
    }

    public HarpoDbContext CreateDbContext() =>
        new(_options, _time, Options.Create(new SiteOptions { SiteId = _siteId }));
}

/// <summary>
/// A complete in-memory Harpo "site": its own SQLite database, clock, and service
/// instances. Replication tests wire several of these together.
/// </summary>
public sealed class TestSite : IDisposable
{
    public const string MasterKey = "shared-test-master-key";

    public string SiteId { get; }
    public ManualTime Time { get; }
    public TestDbFactory Db { get; }
    public CryptoService Crypto { get; }
    public AuditService Audit { get; }
    public GroupService Groups { get; }
    public VaultService Vault { get; }
    public HealthService Health { get; }
    public IconService Icons { get; }
    public ReplicationEngine Engine { get; }

    private readonly SqliteConnection _connection;

    public TestSite(string siteId, ManualTime? time = null)
    {
        SiteId = siteId;
        Time = time ?? new ManualTime();
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        var options = new DbContextOptionsBuilder<HarpoDbContext>()
            .UseSqlite(_connection)
            .Options;
        Db = new TestDbFactory(options, Time, siteId);
        using (var context = Db.CreateDbContext())
        {
            context.Database.EnsureCreated();
        }

        Crypto = new CryptoService(MasterKey);
        Audit = new AuditService(Db, Options.Create(new AuditOptions()), Time, NullLogger<AuditService>.Instance);
        Groups = new GroupService(Db, Time, Audit);
        Vault = new VaultService(Db, Crypto, Time, NullLogger<VaultService>.Instance, Audit,
            Options.Create(new HealthOptions()));
        Health = new HealthService(Db, Crypto, Options.Create(new HealthOptions()), Time, Audit,
            NullLogger<HealthService>.Instance);
        Icons = new IconService(Db, Time, Audit);
        Engine = new ReplicationEngine(
            Db,
            Options.Create(new ReplicationOptions { Key = "test-key", BatchSize = 100 }),
            Options.Create(new SiteOptions { SiteId = siteId }),
            NullLogger<ReplicationEngine>.Instance);
    }

    /// <summary>Pulls everything this site is missing from <paramref name="source"/> (loops through HasMore batches).</summary>
    public async Task PullFromAsync(TestSite source, bool viaJson = false)
    {
        for (var round = 0; round < 100; round++)
        {
            var request = new PullRequest { SiteId = SiteId, Vector = await Engine.GetVectorAsync() };
            var response = await source.Engine.BuildResponseAsync(request);
            if (viaJson)
            {
                // Exercise the real wire format.
                var json = System.Text.Json.JsonSerializer.Serialize(response, JsonOptions);
                response = System.Text.Json.JsonSerializer.Deserialize<PullResponse>(json, JsonOptions)!;
            }
            if (response.RowCount > 0)
            {
                await Engine.ApplyAsync(response);
            }
            if (!response.HasMore)
            {
                return;
            }
        }
        throw new InvalidOperationException("Replication did not converge within 100 rounds.");
    }

    private static readonly System.Text.Json.JsonSerializerOptions JsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    public void Dispose() => _connection.Dispose();

    public static UserContext User(string username, bool siteAdmin = false) =>
        new(username, char.ToUpperInvariant(username[0]) + username[1..], siteAdmin);
}
