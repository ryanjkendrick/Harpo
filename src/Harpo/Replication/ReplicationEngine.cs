using Harpo.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Harpo.Replication;

/// <summary>
/// Core replication logic, used by both sides of a sync:
///  - <see cref="BuildResponseAsync"/> answers a peer's pull (server side);
///  - <see cref="ApplyAsync"/> merges a peer's response into the local store (client side).
///
/// Rows are state-based: each carries (OriginSiteId, OriginSeq, UpdatedAtUtc). Conflicts
/// resolve last-writer-wins on UpdatedAtUtc with a deterministic tie-break, so any two
/// sites that have seen the same set of writes converge to identical data. Password
/// revisions are append-only and merge as a simple union — concurrent password changes
/// on different sites both survive in history.
/// </summary>
public class ReplicationEngine
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly ReplicationOptions _options;
    private readonly string _siteId;
    private readonly ILogger<ReplicationEngine> _logger;

    public ReplicationEngine(
        IDbContextFactory<HarpoDbContext> dbFactory,
        IOptions<ReplicationOptions> options,
        IOptions<SiteOptions> site,
        ILogger<ReplicationEngine> logger)
    {
        _dbFactory = dbFactory;
        _options = options.Value;
        _siteId = site.Value.SiteId;
        _logger = logger;
    }

    public string SiteId => _siteId;

    /// <summary>The high-watermark vector this site advertises when pulling from peers.</summary>
    public async Task<Dictionary<string, long>> GetVectorAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var vector = await db.PeerCursors.ToDictionaryAsync(c => c.OriginSiteId, c => c.LastSeq, ct);
        var counter = await db.SiteCounters.SingleOrDefaultAsync(ct);
        vector[_siteId] = counter is null ? 0 : counter.NextSeq - 1;
        return vector;
    }

    public async Task<PullResponse> BuildResponseAsync(PullRequest request, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var response = new PullResponse { SiteId = _siteId };
        var limit = Math.Max(100, _options.BatchSize);

        var origins = new HashSet<string>();
        origins.UnionWith(await db.Groups.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.GroupMembers.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.PasswordEntries.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.PasswordRevisions.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.AuditEvents.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.Remove("");

        foreach (var origin in origins.OrderBy(o => o, StringComparer.Ordinal))
        {
            var since = request.Vector.GetValueOrDefault(origin, 0);

            var groups = await db.Groups.AsNoTracking()
                .Where(x => x.OriginSiteId == origin && x.OriginSeq > since)
                .OrderBy(x => x.OriginSeq).Take(limit + 1).ToListAsync(ct);
            var members = await db.GroupMembers.AsNoTracking()
                .Where(x => x.OriginSiteId == origin && x.OriginSeq > since)
                .OrderBy(x => x.OriginSeq).Take(limit + 1).ToListAsync(ct);
            var entries = await db.PasswordEntries.AsNoTracking()
                .Where(x => x.OriginSiteId == origin && x.OriginSeq > since)
                .OrderBy(x => x.OriginSeq).Take(limit + 1).ToListAsync(ct);
            var revisions = await db.PasswordRevisions.AsNoTracking()
                .Where(x => x.OriginSiteId == origin && x.OriginSeq > since)
                .OrderBy(x => x.OriginSeq).Take(limit + 1).ToListAsync(ct);
            var audits = await db.AuditEvents.AsNoTracking()
                .Where(x => x.OriginSiteId == origin && x.OriginSeq > since)
                .OrderBy(x => x.OriginSeq).Take(limit + 1).ToListAsync(ct);

            var merged = groups.Cast<IReplicatedRow>()
                .Concat(members)
                .Concat(entries)
                .Concat(revisions)
                .Concat(audits)
                .OrderBy(r => r.OriginSeq)
                .ToList();

            if (merged.Count > limit)
            {
                // Truncate at a sequence cutoff so the included window is contiguous:
                // every row of this origin with seq <= cutoff is present in the batch.
                response.HasMore = true;
                var cutoff = merged[limit - 1].OriginSeq;
                merged = merged.Where(r => r.OriginSeq <= cutoff).ToList();
            }

            foreach (var row in merged)
            {
                switch (row)
                {
                    case Group g: response.Groups.Add(g); break;
                    case GroupMember m: response.Members.Add(m); break;
                    case PasswordEntry e: response.Entries.Add(e); break;
                    case PasswordRevision r: response.Revisions.Add(r); break;
                    case AuditEvent a: response.Audits.Add(a); break;
                }
            }
        }

        return response;
    }

    /// <summary>Merges a peer's response into the local store. Returns the number of rows accepted.</summary>
    public async Task<int> ApplyAsync(PullResponse response, CancellationToken ct = default)
    {
        if (response.RowCount == 0)
        {
            return 0;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        db.SuppressReplicationStamping = true;

        var accepted = 0;
        var highWater = new Dictionary<string, long>(StringComparer.Ordinal);

        foreach (var incoming in response.Groups)
        {
            Track(highWater, incoming);
            var local = await db.Groups.SingleOrDefaultAsync(x => x.Id == incoming.Id, ct);
            if (local is null)
            {
                db.Groups.Add(incoming);
                accepted++;
            }
            else if (IncomingWins(incoming, local))
            {
                local.Name = incoming.Name;
                local.Description = incoming.Description;
                local.CreatedBy = incoming.CreatedBy;
                local.CreatedAtUtc = incoming.CreatedAtUtc;
                CopyStamps(incoming, local);
                accepted++;
            }
        }

        foreach (var incoming in response.Members)
        {
            Track(highWater, incoming);
            var local = await db.GroupMembers.SingleOrDefaultAsync(x => x.Id == incoming.Id, ct);
            if (local is null)
            {
                db.GroupMembers.Add(incoming);
                accepted++;
            }
            else if (IncomingWins(incoming, local))
            {
                local.GroupId = incoming.GroupId;
                local.Username = incoming.Username;
                local.DisplayName = incoming.DisplayName;
                local.Role = incoming.Role;
                local.AddedBy = incoming.AddedBy;
                local.CreatedAtUtc = incoming.CreatedAtUtc;
                CopyStamps(incoming, local);
                accepted++;
            }
        }

        foreach (var incoming in response.Entries)
        {
            Track(highWater, incoming);
            var local = await db.PasswordEntries.SingleOrDefaultAsync(x => x.Id == incoming.Id, ct);
            if (local is null)
            {
                db.PasswordEntries.Add(incoming);
                accepted++;
            }
            else if (IncomingWins(incoming, local))
            {
                local.GroupId = incoming.GroupId;
                local.Name = incoming.Name;
                local.Icon = incoming.Icon;
                local.Url = incoming.Url;
                local.Username = incoming.Username;
                local.Notes = incoming.Notes;
                local.CreatedBy = incoming.CreatedBy;
                local.CreatedAtUtc = incoming.CreatedAtUtc;
                local.UpdatedBy = incoming.UpdatedBy;
                CopyStamps(incoming, local);
                accepted++;
            }
        }

        foreach (var incoming in response.Revisions)
        {
            Track(highWater, incoming);
            // Revisions are immutable: union by Id, never update.
            var exists = await db.PasswordRevisions.AnyAsync(x => x.Id == incoming.Id, ct);
            if (!exists)
            {
                db.PasswordRevisions.Add(incoming);
                accepted++;
            }
        }

        foreach (var incoming in response.Audits)
        {
            Track(highWater, incoming);
            // Audit events are immutable too: union by Id.
            var exists = await db.AuditEvents.AnyAsync(x => x.Id == incoming.Id, ct);
            if (!exists)
            {
                db.AuditEvents.Add(incoming);
                accepted++;
            }
        }

        // Advance high-watermarks for every origin seen, whether or not each row won
        // its merge — losers must not be re-offered forever.
        foreach (var (origin, seq) in highWater)
        {
            if (origin == _siteId)
            {
                // Rows we authored coming back (e.g. after a database restore): make sure
                // the local counter never re-issues sequence numbers already in the mesh.
                var counter = await db.SiteCounters.SingleOrDefaultAsync(ct);
                if (counter is null)
                {
                    db.SiteCounters.Add(new SiteCounter { Id = 1, NextSeq = seq + 1 });
                }
                else if (counter.NextSeq <= seq)
                {
                    counter.NextSeq = seq + 1;
                }
                continue;
            }
            var cursor = await db.PeerCursors.SingleOrDefaultAsync(c => c.OriginSiteId == origin, ct);
            if (cursor is null)
            {
                db.PeerCursors.Add(new PeerCursor { OriginSiteId = origin, LastSeq = seq });
            }
            else if (cursor.LastSeq < seq)
            {
                cursor.LastSeq = seq;
            }
        }

        await db.SaveChangesAsync(ct);
        if (accepted > 0)
        {
            _logger.LogInformation("Applied {Accepted} of {Total} replicated rows from {Peer}",
                accepted, response.RowCount, response.SiteId);
        }
        return accepted;
    }

    public async Task<ReplicationStatusResponse> GetStatusAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var liveGroupIds = db.Groups.Where(g => !g.IsDeleted).Select(g => g.Id);
        return new ReplicationStatusResponse
        {
            SiteId = _siteId,
            Vector = await GetVectorAsync(ct),
            Groups = await db.Groups.CountAsync(g => !g.IsDeleted, ct),
            // Entries inside tombstoned groups linger in the database by design;
            // don't count them as live passwords.
            Entries = await db.PasswordEntries.CountAsync(
                e => !e.IsDeleted && liveGroupIds.Contains(e.GroupId), ct),
            UtcNow = DateTime.UtcNow,
        };
    }

    private static void Track(Dictionary<string, long> highWater, IReplicatedRow row)
    {
        if (!highWater.TryGetValue(row.OriginSiteId, out var seq) || seq < row.OriginSeq)
        {
            highWater[row.OriginSiteId] = row.OriginSeq;
        }
    }

    /// <summary>Last-writer-wins with a total order: timestamp, then origin site, then sequence.</summary>
    internal static bool IncomingWins(IReplicatedRow incoming, IReplicatedRow local)
    {
        if (incoming.OriginSiteId == local.OriginSiteId && incoming.OriginSeq == local.OriginSeq)
        {
            return false; // identical version
        }
        var byTime = incoming.UpdatedAtUtc.CompareTo(local.UpdatedAtUtc);
        if (byTime != 0)
        {
            return byTime > 0;
        }
        var bySite = string.CompareOrdinal(incoming.OriginSiteId, local.OriginSiteId);
        if (bySite != 0)
        {
            return bySite > 0;
        }
        return incoming.OriginSeq > local.OriginSeq;
    }

    private static void CopyStamps(IReplicatedRow incoming, IReplicatedRow local)
    {
        local.OriginSiteId = incoming.OriginSiteId;
        local.OriginSeq = incoming.OriginSeq;
        local.UpdatedAtUtc = incoming.UpdatedAtUtc;
        local.IsDeleted = incoming.IsDeleted;
    }
}
