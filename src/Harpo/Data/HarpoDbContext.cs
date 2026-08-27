using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.Extensions.Options;

namespace Harpo.Data;

public class SiteOptions
{
    /// <summary>Unique, stable identifier for this site (e.g. "london", "sydney").</summary>
    public string SiteId { get; set; } = "default";
}

public class HarpoDbContext : DbContext
{
    // SQLite allows a single writer; one Harpo instance owns each database file.
    // Serializing writes in-process both avoids SQLITE_BUSY churn and makes the
    // read-increment of the site sequence counter race-free.
    private static readonly SemaphoreSlim WriteGate = new(1, 1);

    private readonly TimeProvider _time;
    private readonly string _siteId;

    public HarpoDbContext(DbContextOptions<HarpoDbContext> options, TimeProvider time, IOptions<SiteOptions> site)
        : base(options)
    {
        _time = time;
        _siteId = site.Value.SiteId;
    }

    public DbSet<Group> Groups => Set<Group>();
    public DbSet<GroupMember> GroupMembers => Set<GroupMember>();
    public DbSet<PasswordEntry> PasswordEntries => Set<PasswordEntry>();
    public DbSet<PasswordRevision> PasswordRevisions => Set<PasswordRevision>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<CustomIcon> CustomIcons => Set<CustomIcon>();
    public DbSet<SiteCounter> SiteCounters => Set<SiteCounter>();
    public DbSet<PeerCursor> PeerCursors => Set<PeerCursor>();
    public DbSet<SiteSetting> SiteSettings => Set<SiteSetting>();

    /// <summary>
    /// Set by the replication engine while applying rows received from a peer, so
    /// their origin stamps are preserved instead of being overwritten with ours.
    /// </summary>
    public bool SuppressReplicationStamping { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Relationships are deliberately not modeled: replication delivers rows in
        // arbitrary order across tables, so the store must tolerate a child row
        // arriving before its parent. Services join explicitly and treat the data
        // as eventually consistent.
        modelBuilder.Entity<Group>(b =>
        {
            b.HasIndex(x => new { x.OriginSiteId, x.OriginSeq });
        });

        modelBuilder.Entity<GroupMember>(b =>
        {
            b.HasIndex(x => new { x.GroupId, x.Username }).IsUnique();
            b.HasIndex(x => x.Username);
            b.HasIndex(x => new { x.OriginSiteId, x.OriginSeq });
        });

        modelBuilder.Entity<PasswordEntry>(b =>
        {
            b.HasIndex(x => x.GroupId);
            b.HasIndex(x => new { x.OriginSiteId, x.OriginSeq });
        });

        modelBuilder.Entity<PasswordRevision>(b =>
        {
            b.HasIndex(x => x.EntryId);
            b.HasIndex(x => x.Fingerprint);
            b.HasIndex(x => new { x.OriginSiteId, x.OriginSeq });
        });

        modelBuilder.Entity<AuditEvent>(b =>
        {
            b.HasIndex(x => x.OccurredAtUtc);
            b.HasIndex(x => new { x.OriginSiteId, x.OriginSeq });
        });

        modelBuilder.Entity<CustomIcon>(b =>
        {
            b.HasIndex(x => new { x.OriginSiteId, x.OriginSeq });
        });

        modelBuilder.Entity<PeerCursor>(b =>
        {
            b.HasKey(x => x.OriginSiteId);
        });

        modelBuilder.Entity<SiteSetting>(b =>
        {
            b.HasKey(x => x.Id);
        });
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        await WriteGate.WaitAsync(cancellationToken);
        try
        {
            if (!SuppressReplicationStamping)
            {
                await StampLocalWritesAsync(cancellationToken);
            }
            return await base.SaveChangesAsync(cancellationToken);
        }
        finally
        {
            WriteGate.Release();
        }
    }

    public override int SaveChanges()
    {
        WriteGate.Wait();
        try
        {
            if (!SuppressReplicationStamping)
            {
                StampLocalWritesAsync(CancellationToken.None).GetAwaiter().GetResult();
            }
            return base.SaveChanges();
        }
        finally
        {
            WriteGate.Release();
        }
    }

    private async Task StampLocalWritesAsync(CancellationToken cancellationToken)
    {
        var rows = ChangeTracker.Entries()
            .Where(e => e.Entity is IReplicatedRow && e.State is EntityState.Added or EntityState.Modified)
            .Select(e => (IReplicatedRow)e.Entity)
            .ToList();
        if (rows.Count == 0)
        {
            return;
        }

        var counter = await SiteCounters.SingleOrDefaultAsync(cancellationToken);
        if (counter is null)
        {
            counter = new SiteCounter { Id = 1, NextSeq = 1 };
            SiteCounters.Add(counter);
        }

        var now = _time.GetUtcNow().UtcDateTime;
        foreach (var row in rows)
        {
            row.OriginSiteId = _siteId;
            row.OriginSeq = counter.NextSeq++;
            row.UpdatedAtUtc = now;
        }
    }
}
