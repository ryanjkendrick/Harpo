using System.Collections.Concurrent;

namespace Harpo.Replication;

public sealed class PeerSyncStatus
{
    public string Name { get; init; } = "";
    public string Url { get; init; } = "";
    public DateTime? LastAttemptUtc { get; set; }
    public DateTime? LastSuccessUtc { get; set; }
    public string? LastError { get; set; }
    public int LastPulledRows { get; set; }
    public long TotalPulledRows { get; set; }
    /// <summary>Peer clock minus ours at the last sync (positive = peer ahead). Includes network latency, so treat as coarse.</summary>
    public TimeSpan? ClockSkew { get; set; }
}

/// <summary>In-memory sync health per configured peer, shown on the admin page.</summary>
public class ReplicationStatusTracker
{
    private readonly ConcurrentDictionary<string, PeerSyncStatus> _peers = new();

    public PeerSyncStatus GetOrAdd(string name, string url) =>
        _peers.GetOrAdd(name, _ => new PeerSyncStatus { Name = name, Url = url });

    public IReadOnlyList<PeerSyncStatus> All =>
        _peers.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
}
