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

/// <summary>
/// A vault group. Users must be members to see the passwords inside. A group
/// with an <see cref="OwnerUsername"/> is one person's <b>personal vault</b>:
/// it has that one member, no settings to manage, and — unlike every other
/// group — site administrators cannot open it (they can only convert it into
/// an ordinary group, which is audited and visible to its owner).
/// </summary>
public class Group : IReplicatedRow
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>
    /// Normalized AD account name of the one person who can see this group, or
    /// empty for an ordinary (shared) group. Set only when the vault is created
    /// and cleared only by a site admin's takeover; never edited otherwise.
    /// </summary>
    public string OwnerUsername { get; set; } = "";

    /// <summary>Whether this group is somebody's personal vault.</summary>
    public bool IsPersonal => OwnerUsername.Length > 0;

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
    /// <summary>
    /// Free-text notes, encrypted like passwords — people keep recovery codes and
    /// security answers here. Empty, or <see cref="Security.ProtectedNotes"/>'s
    /// marker followed by ciphertext; read and written only through that class.
    /// It was a plain-text column called Notes before notes were encrypted, and
    /// both the column and the name on the wire stay "notes": sites still on an
    /// older version keep replicating with this one (they see the ciphertext as
    /// text; their own plain-text notes are encrypted here as they arrive).
    /// </summary>
    [System.Text.Json.Serialization.JsonPropertyName("notes")]
    public string EncryptedNotes { get; set; } = "";
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

/// <summary>
/// One sign-in, server-side. The auth cookie carries <see cref="Id"/>; the
/// cookie (and every open page that signed in with it) is honoured only while
/// this row exists. Signing out, the account being disabled in the directory,
/// a change of site-admin role, and expiry all delete the row. Site-local and
/// never replicated: a session belongs to the site that issued the cookie.
/// </summary>
public class UserSession
{
    /// <summary>256 random bits, base64url.</summary>
    public string Id { get; set; } = "";
    /// <summary>Normalized account name, as in <see cref="GroupMember.Username"/>.</summary>
    public string Username { get; set; } = "";
    /// <summary>The site-admin flag the cookie was issued with.</summary>
    public bool IsSiteAdmin { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Last request or interactive action using the session (updated at most once a minute).</summary>
    public DateTime LastSeenAtUtc { get; set; }
    /// <summary>When the directory last vouched for the account (sign-in, or a successful revalidation).</summary>
    public DateTime LastValidatedAtUtc { get; set; }
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
