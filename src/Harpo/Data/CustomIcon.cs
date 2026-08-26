namespace Harpo.Data;

/// <summary>
/// An uploaded icon in the org-wide catalogue (tool logos and the like).
/// Entries reference one by storing "icon:{Id}" in their Icon field — emoji and
/// catalogue references share the same column, so nothing else changed shape.
/// Icons replicate like every other row; deletion is a tombstone.
/// </summary>
public class CustomIcon : IReplicatedRow
{
    public const int MaxBytes = 64 * 1024;
    public const string ReferencePrefix = "icon:";

    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    /// <summary>One of the allow-listed image types (validated with magic bytes on upload).</summary>
    public string ContentType { get; set; } = "";
    public byte[] Data { get; set; } = [];
    /// <summary>
    /// Space-separated, normalized hostnames this icon represents (e.g.
    /// "gitlab.com git.corp.example.com"). When a user types a matching URL on
    /// an entry, the icon is suggested automatically. Empty = no attribution.
    /// </summary>
    public string MatchUrls { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }

    public string OriginSiteId { get; set; } = "";
    public long OriginSeq { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public bool IsDeleted { get; set; }

    public string Reference => ReferencePrefix + Id.ToString("N");

    public static Guid? ParseReference(string? icon) =>
        icon is not null
        && icon.StartsWith(ReferencePrefix, StringComparison.Ordinal)
        && Guid.TryParse(icon.AsSpan(ReferencePrefix.Length), out var id)
            ? id
            : null;
}
