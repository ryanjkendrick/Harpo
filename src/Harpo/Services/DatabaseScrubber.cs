using Harpo.Data;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Services;

/// <summary>
/// Removes what a purge leaves in the database file itself. Deleting or
/// blanking a row does not remove its bytes: SQLite leaves them in the pages it
/// freed, and older copies of the pages in its write-ahead log, until something
/// overwrites them. So after a purge commits, the file is rewritten (VACUUM) and
/// the log emptied, as <see cref="Security.KeyRotation"/> does after encrypting
/// notes: checkpoint, VACUUM, checkpoint, each checkpoint in TRUNCATE mode.
///
/// <c>PRAGMA secure_delete</c> is not used instead: it zeroes the space of
/// deleted cells in the main file, but must be on for every connection, and does
/// nothing about the old page images in the write-ahead log, which are the
/// copies that last longest. The log has to be emptied either way, and VACUUM
/// with it gives one guarantee for every kind of leftover.
///
/// A purge commits a site-local "scrub pending" marker in its own transaction,
/// and the marker is removed only once the scrub has completed: a crash, a full
/// disk or a reader that keeps the log busy leaves it in place, and the scrub is
/// retried (by <see cref="PurgeScrubService"/>, and at the next start). Purges
/// that arrive by replication only ask for a scrub, which the service runs a
/// moment later — so a large purge arriving in many batches costs one VACUUM.
/// </summary>
public sealed class DatabaseScrubber
{
    public const string PendingId = "purge-scrub-pending";

    private readonly IDbContextFactory<HarpoDbContext> _factory;
    private readonly ILogger<DatabaseScrubber> _logger;
    private readonly SemaphoreSlim _running = new(1, 1);
    private readonly SemaphoreSlim _requested = new(0, 1);

    public DatabaseScrubber(IDbContextFactory<HarpoDbContext> factory, ILogger<DatabaseScrubber> logger)
    {
        _factory = factory;
        _logger = logger;
    }

    /// <summary>How long the final checkpoint keeps retrying while a reader holds the log.</summary>
    internal TimeSpan CheckpointPatience { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Adds the "scrub pending" marker in <paramref name="db"/>'s pending changes (saved by the caller).</summary>
    internal static async Task MarkPendingAsync(HarpoDbContext db, CancellationToken ct)
    {
        if (db.SiteSettings.Local.Any(s => s.Id == PendingId) || await db.SiteSettings.AnyAsync(s => s.Id == PendingId, ct))
        {
            return;
        }
        db.SiteSettings.Add(new SiteSetting { Id = PendingId, Value = "v1" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Asks <see cref="PurgeScrubService"/> to scrub soon (a purge arrived by replication).</summary>
    public void Request()
    {
        try
        {
            if (_requested.CurrentCount == 0)
            {
                _requested.Release();
            }
        }
        catch (SemaphoreFullException)
        {
            // Already requested.
        }
    }

    internal Task<bool> WaitForRequestAsync(TimeSpan timeout, CancellationToken ct) => _requested.WaitAsync(timeout, ct);

    public async Task<bool> IsPendingAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.SiteSettings.AnyAsync(s => s.Id == PendingId, ct);
    }

    /// <summary>Scrubs if a purge is waiting for it. True when nothing is left to do.</summary>
    public async Task<bool> ScrubIfPendingAsync(CancellationToken ct = default) =>
        !await IsPendingAsync(ct) || await ScrubAsync(ct);

    /// <summary>
    /// Rewrites the database file and empties its write-ahead log. Holds the
    /// write gate throughout, so no write of this process lands in between.
    /// True when done; false (logged, marker kept, retried later) when the log
    /// could not be emptied or the rewrite failed.
    /// </summary>
    public async Task<bool> ScrubAsync(CancellationToken ct = default)
    {
        await _running.WaitAsync(ct);
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            db.Database.SetCommandTimeout(TimeSpan.FromMinutes(10));
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            await db.Database.OpenConnectionAsync(ct);
            var started = DateTime.UtcNow;
            try
            {
                // The first checkpoint only keeps the log from growing by a whole
                // copy of the database; a reader may make it partial, harmlessly.
                await CheckpointAsync(db, ct);
                await db.Database.ExecuteSqlRawAsync("VACUUM;", ct);
                // Cleared before the last checkpoint, so that the log is empty at
                // the end. Put back below if that checkpoint cannot complete.
                await db.Database.ExecuteSqlAsync($"DELETE FROM SiteSettings WHERE Id = {PendingId}", ct);
                var deadline = DateTime.UtcNow + CheckpointPatience;
                var delay = TimeSpan.FromMilliseconds(50);
                while (!await CheckpointAsync(db, ct))
                {
                    if (DateTime.UtcNow >= deadline)
                    {
                        await db.Database.ExecuteSqlAsync(
                            $"INSERT OR IGNORE INTO SiteSettings (Id, Value) VALUES ({PendingId}, 'v1')", ct);
                        _logger.LogWarning(
                            "A purge was committed, but the database's write-ahead log could not be emptied: a reader " +
                            "kept it busy. The erased content may remain in the log file until this is retried.");
                        return false;
                    }
                    await Task.Delay(delay, ct);
                    delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 1000));
                }
                _logger.LogInformation("Database file rewritten after a purge in {Elapsed} ms.",
                    (int)(DateTime.UtcNow - started).TotalMilliseconds);
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex,
                    "A purge was committed, but the database file could not be rewritten to remove what it erased " +
                    "(the bytes stay in freed pages until then). This will be retried.");
                try
                {
                    await db.Database.ExecuteSqlAsync(
                        $"INSERT OR IGNORE INTO SiteSettings (Id, Value) VALUES ({PendingId}, 'v1')", ct);
                }
                catch (Exception again) when (again is not OperationCanceledException)
                {
                    _logger.LogWarning(again, "Could not record that the scrub is still pending.");
                }
                return false;
            }
        }
        finally
        {
            _running.Release();
        }
    }

    /// <summary>One TRUNCATE checkpoint; true when it completed (no reader in the way) and the log is now empty.</summary>
    private static async Task<bool> CheckpointAsync(HarpoDbContext db, CancellationToken ct)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
        await using var reader = await command.ExecuteReaderAsync(ct);
        // (busy, frames in the log, frames checkpointed); busy = 0 means it ran to completion.
        return !await reader.ReadAsync(ct) || reader.GetInt64(0) == 0;
    }
}

/// <summary>
/// Runs the scrubs that purges arriving by replication ask for, a few seconds
/// after the last request (so a purge spread over many replication batches is
/// scrubbed once), and retries any scrub left pending every few minutes.
/// </summary>
public sealed class PurgeScrubService(DatabaseScrubber scrubber, ILogger<PurgeScrubService> logger) : BackgroundService
{
    internal static readonly TimeSpan Settle = TimeSpan.FromSeconds(3);
    internal static readonly TimeSpan Retry = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (await scrubber.WaitForRequestAsync(Retry, stoppingToken))
                {
                    // Let the rest of a burst of batches land first.
                    while (await scrubber.WaitForRequestAsync(Settle, stoppingToken))
                    {
                    }
                }
                await scrubber.ScrubIfPendingAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Scrubbing the database after a purge failed; it will be retried.");
            }
        }
    }
}
