using Harpo.Data;
using Harpo.Security;
using Microsoft.Data.Sqlite;
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
    private readonly CryptoService _crypto;

    public ReplicationEngine(
        IDbContextFactory<HarpoDbContext> dbFactory,
        IOptions<ReplicationOptions> options,
        IOptions<SiteOptions> site,
        ILogger<ReplicationEngine> logger,
        CryptoService crypto)
    {
        _dbFactory = dbFactory;
        _options = options.Value;
        _siteId = site.Value.SiteId;
        _logger = logger;
        _crypto = crypto;
    }

    /// <summary>
    /// During a master key rotation, rows from not-yet-rotated peers arrive
    /// encrypted under a previous key. Re-encrypt them under the active key on
    /// the way in (stamps are untouched, so this never re-replicates as an
    /// edit) — that way the store converges to active-key-only ciphertext
    /// without waiting for the next restart's sweep. Blobs matching no
    /// configured key are stored as received.
    /// </summary>
    private bool TryHeal(string encrypted, out string healed, out string plaintext)
    {
        healed = encrypted;
        plaintext = "";
        if (!_crypto.HasPreviousKeys)
        {
            return false;
        }
        if (!_crypto.TryDecrypt(encrypted, out plaintext, out var underActiveKey) || underActiveKey)
        {
            return false;
        }
        healed = _crypto.Encrypt(plaintext);
        return true;
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

        // Every query below must see the SAME database snapshot. The response is
        // assembled from one read per table; if a write committed between two of
        // those reads, the response could carry a row with a higher sequence
        // (from a table read later) while missing a lower-sequenced sibling (in a
        // table already read). The peer advances its watermark to the highest
        // sequence it receives, so the missing row would never be asked for
        // again — a revoked membership, or an entry whose revision did arrive,
        // lost for good. A deferred transaction pins one WAL snapshot for all
        // the reads without blocking writers.
        await db.Database.OpenConnectionAsync(ct);
        await using var snapshot = ((SqliteConnection)db.Database.GetDbConnection()).BeginTransaction(deferred: true);
        await db.Database.UseTransactionAsync(snapshot, ct);

        var response = new PullResponse { SiteId = _siteId, UtcNow = DateTime.UtcNow };
        var limit = Math.Max(100, _options.BatchSize);

        var origins = new HashSet<string>();
        origins.UnionWith(await db.Groups.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.GroupMembers.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.PasswordEntries.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.PasswordRevisions.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.AuditEvents.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
        origins.UnionWith(await db.CustomIcons.Select(x => x.OriginSiteId).Distinct().ToListAsync(ct));
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
            var icons = await db.CustomIcons.AsNoTracking()
                .Where(x => x.OriginSiteId == origin && x.OriginSeq > since)
                .OrderBy(x => x.OriginSeq).Take(limit + 1).ToListAsync(ct);

            var merged = groups.Cast<IReplicatedRow>()
                .Concat(members)
                .Concat(entries)
                .Concat(revisions)
                .Concat(audits)
                .Concat(icons)
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
                    case CustomIcon i: response.Icons.Add(i); break;
                }
            }
        }

        await snapshot.CommitAsync(ct);
        return response;
    }

    /// <summary>Merges a peer's response into the local store. Returns the number of rows accepted.</summary>
    public async Task<int> ApplyAsync(PullResponse response, CancellationToken ct = default)
    {
        if (response.RowCount == 0)
        {
            return 0;
        }

        // Pre-flight: a replicated row dated absurdly far in the future would win
        // last-writer-wins over every honest edit until the clock caught up — a
        // tampering peer (or one with a broken clock) could pin a membership or an
        // entry that nothing can overwrite. We can't accept just the sane rows:
        // the watermark advances to the highest sequence received, so skipping one
        // row while taking a later one from the same origin would lose it for good
        // (the gap the single-snapshot read on the server side exists to prevent).
        // So reject the whole response and leave the watermark where it is; the
        // peer is retried next cycle. Honest, NTP-synced sites never come close.
        var maxAcceptableUtc = DateTime.UtcNow + _options.MaxFutureSkew;
        var fromTheFuture = AllRows(response).Where(r => r.UpdatedAtUtc > maxAcceptableUtc).ToList();
        if (fromTheFuture.Count > 0)
        {
            throw new InvalidOperationException(
                $"Peer {response.SiteId} sent {fromTheFuture.Count} row(s) dated more than "
                + $"{_options.MaxFutureSkew.TotalMinutes:0} minutes ahead of this site's clock "
                + $"(the furthest is {fromTheFuture.Max(r => r.UpdatedAtUtc):u}); refusing the whole response. "
                + "Check that every site's clock is NTP-synced; raise Replication:MaxFutureSkewSeconds only if "
                + "you understand why a peer is this far ahead.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        db.SuppressReplicationStamping = true;

        // A merge is read-decide-write per row, so it holds the write gate from
        // the first read to the save. Otherwise a local edit could commit after
        // "the incoming row wins" was decided against the OLD local row, and the
        // save would overwrite that newer edit with the older incoming one —
        // last-writer-wins silently broken, the user's change gone on every site.
        using var gate = await db.BeginExclusiveWriteAsync(ct);

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
            if (incoming.EncryptedTotpSecret is { } totpBlob && TryHeal(totpBlob, out var healedTotp, out _))
            {
                incoming.EncryptedTotpSecret = healedTotp;
            }
            // Notes arrive as plain text from a peer that predates encrypted notes,
            // or under a previous master key mid-rotation. Either way this site's
            // copy is held encrypted under its active key. Like the heal above,
            // that changes the stored bytes and none of the row's stamps, so it
            // never travels back out as an edit.
            if (ProtectedNotes.TryBringUpToDate(_crypto, incoming.EncryptedNotes, out var notes, out _))
            {
                incoming.EncryptedNotes = notes;
            }
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
                local.EncryptedNotes = incoming.EncryptedNotes;
                local.EncryptedTotpSecret = incoming.EncryptedTotpSecret;
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
                if (TryHeal(incoming.EncryptedPassword, out var healedPassword, out var plaintext))
                {
                    incoming.EncryptedPassword = healedPassword;
                    incoming.Fingerprint = _crypto.Fingerprint(plaintext);
                }
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

        foreach (var incoming in response.Icons)
        {
            Track(highWater, incoming);
            var local = await db.CustomIcons.SingleOrDefaultAsync(x => x.Id == incoming.Id, ct);
            if (local is null)
            {
                db.CustomIcons.Add(incoming);
                accepted++;
            }
            else if (IncomingWins(incoming, local))
            {
                local.Name = incoming.Name;
                local.ContentType = incoming.ContentType;
                local.Data = incoming.Data;
                local.MatchUrls = incoming.MatchUrls;
                local.CreatedBy = incoming.CreatedBy;
                local.CreatedAtUtc = incoming.CreatedAtUtc;
                CopyStamps(incoming, local);
                accepted++;
            }
        }

        // A site that started with an empty vault planted no master-key canary
        // (see KeyRotation): this is where its key is first proven against real
        // cluster data, or the mismatch is caught before the store fills with
        // ciphertext this site can never read. Throws (halting this sync) on a
        // wrong key; established sites, with a canary already, are untouched.
        await KeyRotation.ValidateFirstSyncAsync(
            db, _crypto, response.Revisions.Select(r => r.EncryptedPassword).ToList(), ct);

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

    private static IEnumerable<IReplicatedRow> AllRows(PullResponse r) =>
        r.Groups.Cast<IReplicatedRow>()
            .Concat(r.Members)
            .Concat(r.Entries)
            .Concat(r.Revisions)
            .Concat(r.Audits)
            .Concat(r.Icons);

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
