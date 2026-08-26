namespace Harpo.Data;

/// <summary>
/// Every replicated row carries the identity of the site that last wrote it and a
/// per-site monotonic sequence number (the same idea as Active Directory's USNs).
/// Deletes are tombstones (IsDeleted = true) so they replicate like any other write.
/// </summary>
public interface IReplicatedRow
{
    Guid Id { get; set; }
    string OriginSiteId { get; set; }
    long OriginSeq { get; set; }
    DateTime UpdatedAtUtc { get; set; }
    bool IsDeleted { get; set; }
}

/// <summary>A vault group. Users must be members to see the passwords inside.</summary>
public class Group : IReplicatedRow
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }

    public string OriginSiteId { get; set; } = "";
    public long OriginSeq { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public bool IsDeleted { get; set; }
}

public enum GroupRole
{
    /// <summary>Full access to the group's passwords: read, create, edit, delete.</summary>
    Member = 0,
    /// <summary>Member rights plus managing the group itself and its membership.</summary>
    Admin = 1,
    /// <summary>Read-only: can see, reveal, and copy passwords but change nothing.</summary>
    Viewer = 2,
}

public static class GroupRoleExtensions
{
    /// <summary>Whether this role may create, edit, restore, or delete entries.</summary>
    public static bool CanWrite(this GroupRole role) => role is GroupRole.Member or GroupRole.Admin;
}

/// <summary>
/// Membership of an AD account in a group. The row Id is derived deterministically
/// from (GroupId, Username) so that two sites concurrently adding the same user
/// produce the same row and merge cleanly instead of colliding.
/// </summary>
public class GroupMember : IReplicatedRow
{
    public Guid Id { get; set; }
    public Guid GroupId { get; set; }
    /// <summary>Normalized (lower-case) AD account name, e.g. "jsmith".</summary>
    public string Username { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public GroupRole Role { get; set; }
    public string AddedBy { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }

    public string OriginSiteId { get; set; } = "";
    public long OriginSeq { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public bool IsDeleted { get; set; }
}

/// <summary>
/// A named secret. Metadata lives here; the password value itself only ever lives in
/// <see cref="PasswordRevision"/> rows — the current password is the newest revision.
/// </summary>
public class PasswordEntry : IReplicatedRow
{
    public Guid Id { get; set; }
    public Guid GroupId { get; set; }
    public string Name { get; set; } = "";
    /// <summary>Display icon (an emoji, e.g. "🔐").</summary>
    public string Icon { get; set; } = "";
    public string Url { get; set; } = "";
    /// <summary>The account/login name this password belongs to (not an AD user).</summary>
    public string Username { get; set; } = "";
    public string Notes { get; set; } = "";
    /// <summary>
    /// Optional TOTP (2FA) secret — a base32 seed or full otpauth:// URI —
    /// AES-256-GCM encrypted like passwords. Entry-level rather than versioned:
    /// unlike an old password, an old TOTP seed is worthless the moment the
    /// provider re-enrolls, so there is no history worth keeping.
    /// </summary>
    public string? EncryptedTotpSecret { get; set; }
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Who last edited the metadata (password changes are tracked on revisions).</summary>
    public string UpdatedBy { get; set; } = "";

    public string OriginSiteId { get; set; } = "";
    public long OriginSeq { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public bool IsDeleted { get; set; }
}

/// <summary>
/// Append-only password history. Never updated after creation, so replication is a
/// simple union of rows and concurrent password changes on two sites both survive
/// in history (the newest one wins as "current").
/// </summary>
public class PasswordRevision : IReplicatedRow
{
    public Guid Id { get; set; }
    public Guid EntryId { get; set; }
    /// <summary>AES-256-GCM ciphertext, base64( nonce || tag || ct ).</summary>
    public string EncryptedPassword { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// Keyed HMAC of the plaintext (key derived from the master key), letting the
    /// health report detect reuse by equality without decrypting anything. Null on
    /// rows written before this feature (or with health disabled) — healed lazily.
    /// </summary>
    public string? Fingerprint { get; set; }

    /// <summary>Heuristic strength 0 (terrible) … 4 (strong), computed at write time. Null = not yet computed.</summary>
    public int? Strength { get; set; }

    public string OriginSiteId { get; set; } = "";
    public long OriginSeq { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public bool IsDeleted { get; set; }
}

/// <summary>
/// Site-local key/value settings; never replicated. Holds the master-key canary
/// (an encrypted known value that turns a misconfigured key into a loud startup
/// failure instead of a silently unreadable vault).
/// </summary>
public class SiteSetting
{
    public string Id { get; set; } = "";
    public string Value { get; set; } = "";
}

/// <summary>Single-row table holding this site's next replication sequence number.</summary>
public class SiteCounter
{
    public int Id { get; set; }
    public long NextSeq { get; set; }
}

/// <summary>
/// High-watermark per origin site: the highest OriginSeq this site has already
/// received (whether or not the row won its last-writer-wins merge).
/// </summary>
public class PeerCursor
{
    public string OriginSiteId { get; set; } = "";
    public long LastSeq { get; set; }
}
