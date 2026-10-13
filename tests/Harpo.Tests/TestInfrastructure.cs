using System.Data.Common;
using Harpo.Data;
using Harpo.Replication;
using Harpo.Security;
using Harpo.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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
/// Lets a test run code at the exact moment a chosen SQL statement is about to
/// execute — to commit a competing write between two reads, or to hold a write
/// open while another caller races it. One-shot: the hook disarms itself before
/// running, so the statements it issues are not intercepted again.
/// </summary>
public sealed class CommandHook : DbCommandInterceptor
{
    private Func<string, bool>? _match;
    private Func<Task>? _action;

    public void Before(Func<string, bool> match, Func<Task> action)
    {
        _match = match;
        _action = action;
    }

    public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result,
        CancellationToken cancellationToken = default)
    {
        await FireAsync(command.CommandText);
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        await FireAsync(command.CommandText);
        return result;
    }

    public override async ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<object> result,
        CancellationToken cancellationToken = default)
    {
        await FireAsync(command.CommandText);
        return result;
    }

    private async Task FireAsync(string sql)
    {
        var match = _match;
        if (match is null || !match(sql))
        {
            return;
        }
        _match = null;
        var action = Interlocked.Exchange(ref _action, null);
        if (action is not null)
        {
            await action();
        }
    }
}

/// <summary>
/// A directory that answers from <paramref name="inner"/> until a test sets
/// <see cref="Unavailable"/> — then it behaves like LDAP without a service
/// account (or with the DC down): every lookup and search is Unavailable.
/// </summary>
public sealed class SwitchableDirectory(IDirectory inner) : IDirectory
{
    public bool Unavailable { get; set; }

    public Task<DirectoryLookup> LookupAccountAsync(string username, CancellationToken cancellationToken) =>
        Unavailable ? Task.FromResult(DirectoryLookup.Unavailable) : inner.LookupAccountAsync(username, cancellationToken);

    public Task<DirectorySearchResult> SearchAccountsAsync(string term, int limit, CancellationToken cancellationToken) =>
        Unavailable ? Task.FromResult(DirectorySearchResult.Unavailable) : inner.SearchAccountsAsync(term, limit, cancellationToken);
}

/// <summary>
/// A complete Harpo "site": its own SQLite database, clock, and service
/// instances. Replication tests wire several of these together. In-memory by
/// default; pass <c>databasePath</c> for a real WAL-mode file where every
/// context gets its own connection, as in production — which concurrency tests
/// need (the in-memory mode shares one connection between all contexts).
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

    /// <summary>
    /// The site's "directory" (Development-mode users): alice, a site admin, bob
    /// and carol. Sessions revalidate against it — remove a user to disable
    /// them — and group admins' member lookups ask it (through <see cref="Directory"/>).
    /// </summary>
    public DevAuthOptions DevDirectory { get; } = new()
    {
        DevUsers =
        {
            new DevAuthOptions.DevUser { Username = "alice", Password = "alice", IsSiteAdmin = true },
            new DevAuthOptions.DevUser { Username = "bob", Password = "bob" },
            new DevAuthOptions.DevUser { Username = "carol", Password = "carol" },
        },
    };

    /// <summary>What <see cref="Groups"/> asks about new members: <see cref="DevDirectory"/>, unless switched off.</summary>
    public SwitchableDirectory Directory { get; }

    /// <summary>Session settings, read live by <see cref="Sessions"/> — tests may change them.</summary>
    public AuthSessionOptions SessionOptions { get; } = new();

    public SessionService Sessions { get; }

    private readonly SqliteConnection? _connection;
    private readonly bool _fileBacked;

    public TestSite(string siteId, ManualTime? time = null,
        string masterKey = MasterKey, string[]? previousMasterKeys = null,
        string? databasePath = null, params IInterceptor[] interceptors)
    {
        SiteId = siteId;
        Time = time ?? new ManualTime();
        var builder = new DbContextOptionsBuilder<HarpoDbContext>();
        if (databasePath is null)
        {
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();
            builder.UseSqlite(_connection);
        }
        else
        {
            _fileBacked = true;
            builder.UseSqlite(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        }
        if (interceptors.Length > 0)
        {
            builder.AddInterceptors(interceptors);
        }
        Db = new TestDbFactory(builder.Options, Time, siteId);
        using (var context = Db.CreateDbContext())
        {
            context.Database.EnsureCreated();
            if (_fileBacked)
            {
                // Same journal mode as production (DbInitializer): readers keep a
                // stable snapshot while a writer commits.
                context.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
            }
        }

        Crypto = new CryptoService(masterKey, previousMasterKeys);
        Sessions = new SessionService(Db, new DevAuthenticator(Options.Create(DevDirectory)), Options.Create(SessionOptions),
            Time, NullLogger<SessionService>.Instance);
        Audit = new AuditService(Db, Options.Create(new AuditOptions()), Time, NullLogger<AuditService>.Instance, Sessions);
        Directory = new SwitchableDirectory(new DevAuthenticator(Options.Create(DevDirectory)));
        Groups = new GroupService(Db, Time, Audit, Sessions, Directory);
        Vault = new VaultService(Db, Crypto, Time, NullLogger<VaultService>.Instance, Audit,
            Options.Create(new HealthOptions()), Sessions);
        Health = new HealthService(Db, Crypto, Options.Create(new HealthOptions()), Time, Audit,
            NullLogger<HealthService>.Instance, Sessions);
        Icons = new IconService(Db, Time, Audit, Options.Create(new IconOptions()),
            NullLogger<IconService>.Instance, Sessions);
        Engine = new ReplicationEngine(
            Db,
            Options.Create(new ReplicationOptions { Key = "test-key", BatchSize = 100 }),
            Options.Create(new SiteOptions { SiteId = siteId }),
            NullLogger<ReplicationEngine>.Instance,
            Crypto);
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

    public void Dispose()
    {
        _connection?.Dispose();
        if (_fileBacked)
        {
            SqliteConnection.ClearAllPools(); // release the file so the test can delete it
        }
    }

    /// <summary>
    /// An in-process caller with no session (like the startup icon import): the
    /// services skip the session check for it. For a signed-in caller whose
    /// session can end, use <see cref="SignInAsync"/>.
    /// </summary>
    public static UserContext User(string username, bool siteAdmin = false) =>
        new(username, char.ToUpperInvariant(username[0]) + username[1..], siteAdmin);

    /// <summary>
    /// Signs <paramref name="username"/> in against <see cref="DevDirectory"/> as the
    /// login page does, and returns the caller exactly as an interactive page
    /// would hold it: built from the cookie's principal, session id included.
    /// </summary>
    public async Task<UserContext> SignInAsync(string username)
    {
        var dev = DevDirectory.DevUsers.Single(u => u.Username == username);
        var result = await new DevAuthenticator(Options.Create(DevDirectory))
            .AuthenticateAsync(dev.Username, dev.Password, CancellationToken.None)
            ?? throw new InvalidOperationException($"{username} could not sign in");
        var sessionId = await Sessions.CreateAsync(result);
        return UserContext.FromPrincipal(HarpoClaims.CreatePrincipal(result, sessionId));
    }
}
