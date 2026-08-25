namespace Harpo.Replication;

public class ReplicationOptions
{
    /// <summary>Shared secret presented by peers in the X-Harpo-Replication-Key header. Replication is disabled while empty.</summary>
    public string Key { get; set; } = "";
    public int IntervalSeconds { get; set; } = 15;
    /// <summary>Max rows pulled per origin site per request.</summary>
    public int BatchSize { get; set; } = 2000;
    public List<Peer> Peers { get; set; } = new();

    public class Peer
    {
        public string Name { get; set; } = "";
        /// <summary>Base URL of the peer site, e.g. "https://harpo.branch.example.com".</summary>
        public string Url { get; set; } = "";
    }

    public bool Enabled => !string.IsNullOrWhiteSpace(Key);
}
