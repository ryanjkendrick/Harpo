using System.Collections.Concurrent;

namespace Harpo.Offline;

/// <summary>
/// Policy for the offline (PWA) vault. Admins control this from configuration /
/// Docker environment: set <c>Harpo__Offline__Enabled=false</c> to forbid offline
/// password storage org-wide. Disabling stops new snapshots immediately and makes
/// online devices wipe their local copy at next contact; a device that never comes
/// back online keeps its copy until the snapshot expires — the server cannot reach
/// out and erase it, which is inherent to any offline feature.
/// </summary>
public class OfflineOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>How long a device may keep using a snapshot without refreshing from the server.</summary>
    public int SnapshotMaxAgeDays { get; set; } = 7;

    /// <summary>Minimum seconds between snapshot downloads per user (each one bulk-decrypts their vault).</summary>
    public int MinSecondsBetweenSnapshots { get; set; } = 30;
}

/// <summary>What a device stores (re-encrypted client-side under the user's offline passphrase).</summary>
public sealed record OfflineSnapshot(
    string Username,
    string DisplayName,
    string SiteId,
    DateTime GeneratedAtUtc,
    int MaxAgeDays,
    List<OfflineGroup> Groups,
    List<OfflineEntry> Entries);

public sealed record OfflineGroup(Guid Id, string Name, string Description);

public sealed record OfflineEntry(
    Guid Id,
    Guid GroupId,
    string Name,
    string Icon,
    string Url,
    string Username,
    string Notes,
    string? Password,
    string PasswordUpdatedBy,
    DateTime? PasswordUpdatedAtUtc);

/// <summary>
/// Per-user cooldown for snapshot downloads. A snapshot decrypts the user's whole
/// accessible vault in one request, so it must not be hammerable.
/// </summary>
public class OfflineSnapshotThrottle
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastByUser = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public OfflineSnapshotThrottle(TimeProvider time)
    {
        _time = time;
    }

    public bool TryAcquire(string username, TimeSpan minInterval, out TimeSpan retryAfter)
    {
        var now = _time.GetUtcNow();
        var granted = false;
        var updated = _lastByUser.AddOrUpdate(
            username,
            _ => { granted = true; return now; },
            (_, last) =>
            {
                if (now - last >= minInterval)
                {
                    granted = true;
                    return now;
                }
                return last;
            });
        retryAfter = granted ? TimeSpan.Zero : minInterval - (now - updated);
        return granted;
    }
}
