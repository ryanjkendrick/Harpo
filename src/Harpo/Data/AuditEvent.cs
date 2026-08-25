namespace Harpo.Data;

/// <summary>
/// Append-only audit trail. Rows replicate between sites like password revisions
/// (union by Id, never updated), so every site eventually sees the whole
/// organisation's trail; <see cref="IReplicatedRow.OriginSiteId"/> records where
/// an event happened. Retention hard-deletes old rows — safe under replication
/// because peers never re-offer rows below the high-watermark vector.
/// </summary>
public class AuditEvent : IReplicatedRow
{
    public Guid Id { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    /// <summary>Who did it (normalized account name).</summary>
    public string Username { get; set; } = "";
    /// <summary>One of the <see cref="AuditActions"/> constants.</summary>
    public string Action { get; set; } = "";
    public Guid? GroupId { get; set; }
    public Guid? EntryId { get; set; }
    /// <summary>Human-readable object, denormalized so the trail outlives renames and deletions.</summary>
    public string Target { get; set; } = "";
    public string Detail { get; set; } = "";
    /// <summary>Best-effort client address (empty when unknown).</summary>
    public string ClientAddress { get; set; } = "";

    public string OriginSiteId { get; set; } = "";
    public long OriginSeq { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public bool IsDeleted { get; set; }
}

public static class AuditActions
{
    public const string PasswordReveal = "password.reveal";
    public const string PasswordCopy = "password.copy";
    public const string RevisionReveal = "revision.reveal";
    public const string OfflineSync = "offline.sync";
    public const string EntryDelete = "entry.delete";
    public const string EntryRestore = "entry.restore";
    public const string GroupDelete = "group.delete";
    public const string GroupRestore = "group.restore";
    public const string MemberAdd = "member.add";
    public const string MemberRemove = "member.remove";
    public const string MemberRole = "member.role";
    public const string HealthReport = "health.report";
    public const string TotpReveal = "totp.reveal";
    public const string TotpChange = "totp.change";
    public const string IconAdd = "icon.add";
    public const string IconDelete = "icon.delete";
}
