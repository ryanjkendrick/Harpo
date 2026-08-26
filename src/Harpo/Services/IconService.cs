using Harpo.Data;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Services;

public sealed record IconSummary(Guid Id, string Name, string CreatedBy, int SizeBytes, string ContentType, string MatchUrls)
{
    public string Reference => CustomIcon.ReferencePrefix + Id.ToString("N");
}

/// <summary>
/// The custom icon catalogue. Any authenticated user may add icons (like
/// creating groups); site admins curate. Uploads are strictly validated:
/// size-capped, content-type allow-listed, and magic-byte checked, because
/// these bytes are later served back to every user's browser.
/// </summary>
public class IconService
{
    private static readonly Dictionary<string, byte[][]> AllowedTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["image/png"] = [[0x89, 0x50, 0x4E, 0x47]],
        ["image/jpeg"] = [[0xFF, 0xD8, 0xFF]],
        ["image/gif"] = ["GIF8"u8.ToArray()],
        ["image/webp"] = ["RIFF"u8.ToArray()],
        ["image/svg+xml"] = [], // textual; checked separately
    };

    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly TimeProvider _time;
    private readonly AuditService _audit;

    public IconService(IDbContextFactory<HarpoDbContext> dbFactory, TimeProvider time, AuditService audit)
    {
        _dbFactory = dbFactory;
        _time = time;
        _audit = audit;
    }

    /// <summary>Catalogue listing without image bytes (they load via the /api/icons endpoint).</summary>
    public async Task<List<IconSummary>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CustomIcons
            .Where(i => !i.IsDeleted)
            .OrderBy(i => i.Name)
            .Select(i => new IconSummary(i.Id, i.Name, i.CreatedBy, i.Data.Length, i.ContentType, i.MatchUrls))
            .ToListAsync(ct);
    }

    public async Task<(byte[] Data, string ContentType)?> GetDataAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var icon = await db.CustomIcons.SingleOrDefaultAsync(i => i.Id == id && !i.IsDeleted, ct);
        return icon is null ? null : (icon.Data, icon.ContentType);
    }

    public async Task<CustomIcon> AddAsync(
        UserContext user, string name, string contentType, byte[] data, string matchUrls = "", CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("The icon needs a name.");
        }
        if (name.Length > 50)
        {
            name = name[..50];
        }
        if (data.Length == 0)
        {
            throw new VaultValidationException("The icon file is empty.");
        }
        if (data.Length > CustomIcon.MaxBytes)
        {
            throw new VaultValidationException(
                $"Icons are capped at {CustomIcon.MaxBytes / 1024} KB — resize the image (small squares around 128px work best).");
        }
        ValidateImage(contentType, data);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var icon = new CustomIcon
        {
            Id = Guid.NewGuid(),
            Name = name,
            ContentType = contentType.ToLowerInvariant(),
            Data = data,
            MatchUrls = IconUrlMatcher.NormalizeHostList(matchUrls),
            CreatedBy = user.Username,
            CreatedAtUtc = _time.GetUtcNow().UtcDateTime,
        };
        db.CustomIcons.Add(icon);
        await db.SaveChangesAsync(ct);
        await _audit.RecordAsync(user, AuditActions.IconAdd, name, detail: $"{data.Length / 1024.0:0.#} KB {contentType}");
        return icon;
    }

    /// <summary>Sets the URLs an icon represents (site admins). Free-form input is normalized to hostnames.</summary>
    public async Task SetMatchUrlsAsync(UserContext user, Guid id, string matchUrls, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site admins can edit icon attributions.");
        }
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var icon = await db.CustomIcons.SingleOrDefaultAsync(i => i.Id == id && !i.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Icon not found.");
        var normalized = IconUrlMatcher.NormalizeHostList(matchUrls);
        if (icon.MatchUrls == normalized)
        {
            return;
        }
        icon.MatchUrls = normalized;
        await db.SaveChangesAsync(ct);
        await _audit.RecordAsync(user, AuditActions.IconUpdate, icon.Name,
            detail: normalized.Length == 0 ? "URL attribution cleared" : $"matches: {normalized}");
    }

    /// <summary>Site admins curate the catalogue. Entries referencing a deleted icon fall back to the default glyph.</summary>
    public async Task DeleteAsync(UserContext user, Guid id, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site admins can remove catalogue icons.");
        }
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var icon = await db.CustomIcons.SingleOrDefaultAsync(i => i.Id == id && !i.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Icon not found.");
        icon.IsDeleted = true;
        await db.SaveChangesAsync(ct);
        await _audit.RecordAsync(user, AuditActions.IconDelete, icon.Name);
    }

    /// <summary>How many live entries use each icon (shown before an admin deletes one).</summary>
    public async Task<Dictionary<Guid, int>> GetUsageAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var refs = await db.PasswordEntries
            .Where(e => !e.IsDeleted && e.Icon.StartsWith(CustomIcon.ReferencePrefix))
            .Select(e => e.Icon)
            .ToListAsync(ct);
        return refs
            .Select(CustomIcon.ParseReference)
            .Where(id => id is not null)
            .GroupBy(id => id!.Value)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    private static void ValidateImage(string contentType, byte[] data)
    {
        if (!AllowedTypes.TryGetValue(contentType, out var signatures))
        {
            throw new VaultValidationException(
                "Unsupported image type — use PNG, JPEG, GIF, WebP, or SVG.");
        }
        if (contentType.Equals("image/svg+xml", StringComparison.OrdinalIgnoreCase))
        {
            var head = System.Text.Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 512));
            if (!head.Contains("<svg", StringComparison.OrdinalIgnoreCase))
            {
                throw new VaultValidationException("That file does not look like an SVG image.");
            }
            return;
        }
        if (!signatures.Any(sig => data.Length >= sig.Length && data.AsSpan(0, sig.Length).SequenceEqual(sig)))
        {
            throw new VaultValidationException("The file's content does not match its image type.");
        }
    }
}
