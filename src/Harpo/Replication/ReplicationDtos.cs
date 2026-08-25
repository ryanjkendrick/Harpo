using Harpo.Data;

namespace Harpo.Replication;

/// <summary>
/// "Send me everything newer than this." The vector maps origin site id → highest
/// sequence number the caller has already received from that origin — the same
/// high-watermark scheme Active Directory replication uses with USNs.
/// </summary>
public sealed class PullRequest
{
    public string SiteId { get; set; } = "";
    public Dictionary<string, long> Vector { get; set; } = new();
}

public sealed class PullResponse
{
    public string SiteId { get; set; } = "";
    public List<Group> Groups { get; set; } = new();
    public List<GroupMember> Members { get; set; } = new();
    public List<PasswordEntry> Entries { get; set; } = new();
    public List<PasswordRevision> Revisions { get; set; } = new();
    public List<AuditEvent> Audits { get; set; } = new();
    /// <summary>True when at least one origin was truncated at the batch limit — pull again.</summary>
    public bool HasMore { get; set; }
    /// <summary>The responding site's clock, for skew detection (last-writer-wins needs synced clocks).</summary>
    public DateTime UtcNow { get; set; }

    public int RowCount => Groups.Count + Members.Count + Entries.Count + Revisions.Count + Audits.Count;
}

public sealed class ReplicationStatusResponse
{
    public string SiteId { get; set; } = "";
    public Dictionary<string, long> Vector { get; set; } = new();
    public int Groups { get; set; }
    public int Entries { get; set; }
    public DateTime UtcNow { get; set; }
}
