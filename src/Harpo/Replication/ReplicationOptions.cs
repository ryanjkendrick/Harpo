namespace Harpo.Replication;

public class ReplicationOptions
{
    /// <summary>Shared secret presented by peers in the X-Harpo-Replication-Key header. Replication is disabled while empty.</summary>
    public string Key { get; set; } = "";
    public int IntervalSeconds { get; set; } = 15;
    /// <summary>Max rows pulled per origin site per request.</summary>
    public int BatchSize { get; set; } = 2000;
    /// <summary>
    /// A replicated row dated more than this far in the future (relative to this
    /// site's clock) causes the whole pull response to be rejected — a guard
    /// against a tampering or badly clock-skewed peer dating a change so far ahead
    /// that it always wins last-writer-wins. With clocks NTP-synced (required —
    /// see the README) no honest row ever approaches this. Floored at 60s.
    /// </summary>
    public int MaxFutureSkewSeconds { get; set; } = 3600;
    public List<Peer> Peers { get; set; } = new();

    public TimeSpan MaxFutureSkew => TimeSpan.FromSeconds(Math.Max(60, MaxFutureSkewSeconds));

    public class Peer
    {
        public string Name { get; set; } = "";
        /// <summary>Base URL of the peer site, e.g. "https://harpo.branch.example.com".</summary>
        public string Url { get; set; } = "";
    }

    public bool Enabled => !string.IsNullOrWhiteSpace(Key);
}
