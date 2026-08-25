using Harpo.Data;
using Harpo.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Harpo.Services;

/// <summary>A password entry plus the who/when of its newest revision.</summary>
public sealed record EntryView(PasswordEntry Entry, string PasswordUpdatedBy, DateTime? PasswordUpdatedAtUtc);

public sealed record RevisionView(Guid RevisionId, string CreatedBy, DateTime CreatedAtUtc, bool IsCurrent);

public enum RevealPurpose
{
    View,
    Copy,
}

/// <summary>
/// Password entry CRUD, revealing, and history. Every operation checks group
/// membership; passwords are decrypted only on explicit reveal/copy calls.
/// </summary>
public class VaultService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly CryptoService _crypto;
    private readonly TimeProvider _time;
    private readonly ILogger<VaultService> _logger;
    private readonly AuditService _audit;
    private readonly HealthOptions _health;

    public VaultService(
        IDbContextFactory<HarpoDbContext> dbFactory, CryptoService crypto, TimeProvider time,
        ILogger<VaultService> logger, AuditService audit, IOptions<HealthOptions> health)
    {
        _dbFactory = dbFactory;
        _crypto = crypto;
        _time = time;
        _logger = logger;
        _audit = audit;
        _health = health.Value;
    }

    public async Task<List<EntryView>> GetEntriesAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct);

        var entries = await db.PasswordEntries
            .Where(e => e.GroupId == groupId && !e.IsDeleted)
            .OrderBy(e => e.Name)
            .ToListAsync(ct);

        var entryIds = entries.Select(e => e.Id).ToList();
        var revisions = await db.PasswordRevisions
            .Where(r => entryIds.Contains(r.EntryId))
            .Select(r => new { r.EntryId, r.CreatedBy, r.CreatedAtUtc, r.OriginSiteId, r.Id })
            .ToListAsync(ct);
        var latestByEntry = revisions
            .GroupBy(r => r.EntryId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.CreatedAtUtc)
                      .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
                      .ThenByDescending(r => r.Id)
                      .First());

        return entries
            .Select(e => latestByEntry.TryGetValue(e.Id, out var latest)
                ? new EntryView(e, latest.CreatedBy, latest.CreatedAtUtc)
                : new EntryView(e, e.CreatedBy, null))
            .ToList();
    }

    public async Task<PasswordEntry> CreateEntryAsync(
        UserContext user, Guid groupId, string name, string icon, string url, string username, string notes, string password,
        CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Name is required.");
        }
        if (password.Length == 0)
        {
            throw new VaultValidationException("Password is required.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct, requireWrite: true);

        var now = _time.GetUtcNow().UtcDateTime;
        var entry = new PasswordEntry
        {
            Id = Guid.NewGuid(),
            GroupId = groupId,
            Name = name,
            Icon = icon.Trim(),
            Url = url.Trim(),
            Username = username.Trim(),
            Notes = notes.Trim(),
            CreatedBy = user.Username,
            CreatedAtUtc = now,
            UpdatedBy = user.Username,
        };
        db.PasswordEntries.Add(entry);
        db.PasswordRevisions.Add(NewRevision(entry.Id, password, user, now));
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} created entry {Entry} in group {Group}", user.Username, entry.Id, groupId);
        return entry;
    }

    public async Task UpdateEntryAsync(
        UserContext user, Guid entryId, string name, string icon, string url, string username, string notes,
        CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Name is required.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct, requireWrite: true);
        entry.Name = name;
        entry.Icon = icon.Trim();
        entry.Url = url.Trim();
        entry.Username = username.Trim();
        entry.Notes = notes.Trim();
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
    }

    public async Task ChangePasswordAsync(UserContext user, Guid entryId, string newPassword, CancellationToken ct = default)
    {
        if (newPassword.Length == 0)
        {
            throw new VaultValidationException("Password is required.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct, requireWrite: true);
        var now = _time.GetUtcNow().UtcDateTime;
        db.PasswordRevisions.Add(NewRevision(entry.Id, newPassword, user, now));
        // Touch the entry so list views (and replication consumers) see it moved.
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} changed the password of entry {Entry}", user.Username, entryId);
    }

    public async Task DeleteEntryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct, requireWrite: true);
        entry.IsDeleted = true;
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} deleted entry {Entry}", user.Username, entryId);
        await _audit.RecordAsync(
            user, AuditActions.EntryDelete, await DescribeEntryAsync(db, entry, ct),
            groupId: entry.GroupId, entryId: entry.Id);
    }

    /// <summary>Tombstoned entries of a live group, newest first. Requires write rights (viewers have no trash).</summary>
    public async Task<List<PasswordEntry>> GetDeletedEntriesAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireMemberAsync(db, user, groupId, ct, requireWrite: true);
        return await db.PasswordEntries
            .Where(e => e.GroupId == groupId && e.IsDeleted)
            .OrderByDescending(e => e.UpdatedAtUtc)
            .Take(50)
            .ToListAsync(ct);
    }

    /// <summary>Undoes a delete — tombstones replicate, so this works on any site and syncs everywhere.</summary>
    public async Task RestoreEntryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await db.PasswordEntries.SingleOrDefaultAsync(e => e.Id == entryId && e.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Deleted entry not found.");
        await RequireMemberAsync(db, user, entry.GroupId, ct, requireWrite: true);
        entry.IsDeleted = false;
        entry.UpdatedBy = user.Username;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{User} restored entry {Entry}", user.Username, entryId);
        await _audit.RecordAsync(
            user, AuditActions.EntryRestore, await DescribeEntryAsync(db, entry, ct),
            groupId: entry.GroupId, entryId: entry.Id);
    }

    /// <summary>Decrypts the current password of an entry (and audits the access).</summary>
    public async Task<string> RevealPasswordAsync(
        UserContext user, Guid entryId, RevealPurpose purpose = RevealPurpose.View, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entry = await RequireEntryAsync(db, user, entryId, ct);
        var latest = await LatestRevisionAsync(db, entry.Id, ct)
            ?? throw new VaultNotFoundException("This entry has no password yet (it may still be replicating).");
        var plaintext = _crypto.Decrypt(latest.EncryptedPassword);
        await _audit.RecordAsync(
            user,
            purpose == RevealPurpose.Copy ? AuditActions.PasswordCopy : AuditActions.PasswordReveal,
            await DescribeEntryAsync(db, entry, ct),
            groupId: entry.GroupId, entryId: entry.Id);
        return plaintext;
    }

    public async Task<List<RevisionView>> GetHistoryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireEntryAsync(db, user, entryId, ct);
        var revisions = await db.PasswordRevisions
            .Where(r => r.EntryId == entryId)
            .ToListAsync(ct);
        var ordered = revisions
            .OrderByDescending(r => r.CreatedAtUtc)
            .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
            .ThenByDescending(r => r.Id)
            .ToList();
        return ordered
            .Select((r, i) => new RevisionView(r.Id, r.CreatedBy, r.CreatedAtUtc, i == 0))
            .ToList();
    }

    /// <summary>Decrypts a historical password revision.</summary>
    public async Task<string> RevealRevisionAsync(UserContext user, Guid entryId, Guid revisionId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireEntryAsync(db, user, entryId, ct);
        var revision = await db.PasswordRevisions
            .SingleOrDefaultAsync(r => r.Id == revisionId && r.EntryId == entryId, ct)
            ?? throw new VaultNotFoundException("Revision not found.");
        var plaintext = _crypto.Decrypt(revision.EncryptedPassword);
        var entry = await db.PasswordEntries.SingleAsync(e => e.Id == entryId, ct);
        await _audit.RecordAsync(
            user, AuditActions.RevisionReveal, await DescribeEntryAsync(db, entry, ct),
            detail: $"historical value set {revision.CreatedAtUtc:u} by {revision.CreatedBy}",
            groupId: entry.GroupId, entryId: entry.Id);
        return plaintext;
    }

    private static async Task<string> DescribeEntryAsync(HarpoDbContext db, PasswordEntry entry, CancellationToken ct)
    {
        var groupName = await db.Groups
            .Where(g => g.Id == entry.GroupId)
            .Select(g => g.Name)
            .FirstOrDefaultAsync(ct);
        return groupName is null ? entry.Name : $"{entry.Name} ({groupName})";
    }

    /// <summary>
    /// Everything the user may take offline: groups they are an explicit member of,
    /// with each entry's current password decrypted. Deliberately scoped to real
    /// memberships — site admins do not get an everything-snapshot; offline copies
    /// should carry the minimum, and admins can always reach the server online.
    /// </summary>
    public async Task<(List<Offline.OfflineGroup> Groups, List<Offline.OfflineEntry> Entries)> GetOfflineDataAsync(
        UserContext user, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var groupIds = await db.GroupMembers
            .Where(m => !m.IsDeleted && m.Username == user.Username)
            .Select(m => m.GroupId)
            .ToListAsync(ct);

        var groups = await db.Groups
            .Where(g => !g.IsDeleted && groupIds.Contains(g.Id))
            .OrderBy(g => g.Name)
            .Select(g => new Offline.OfflineGroup(g.Id, g.Name, g.Description))
            .ToListAsync(ct);

        var liveGroupIds = groups.Select(g => g.Id).ToList();
        var entries = await db.PasswordEntries
            .Where(e => !e.IsDeleted && liveGroupIds.Contains(e.GroupId))
            .OrderBy(e => e.Name)
            .ToListAsync(ct);

        var entryIds = entries.Select(e => e.Id).ToList();
        var revisions = await db.PasswordRevisions
            .Where(r => entryIds.Contains(r.EntryId))
            .ToListAsync(ct);
        var latestByEntry = revisions
            .GroupBy(r => r.EntryId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.CreatedAtUtc)
                      .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
                      .ThenByDescending(r => r.Id)
                      .First());

        var offlineEntries = entries
            .Select(e =>
            {
                latestByEntry.TryGetValue(e.Id, out var latest);
                return new Offline.OfflineEntry(
                    e.Id,
                    e.GroupId,
                    e.Name,
                    e.Icon,
                    e.Url,
                    e.Username,
                    e.Notes,
                    latest is null ? null : _crypto.Decrypt(latest.EncryptedPassword),
                    latest?.CreatedBy ?? e.CreatedBy,
                    latest?.CreatedAtUtc);
            })
            .ToList();

        return (groups, offlineEntries);
    }

    private PasswordRevision NewRevision(Guid entryId, string password, UserContext user, DateTime now) => new()
    {
        Id = Guid.NewGuid(),
        EntryId = entryId,
        EncryptedPassword = _crypto.Encrypt(password),
        CreatedBy = user.Username,
        CreatedAtUtc = now,
        // Health analysis, when enabled: an equality fingerprint (reuse
        // detection) and a strength score, so the report never needs plaintext.
        Fingerprint = _health.Enabled ? _crypto.Fingerprint(password) : null,
        Strength = _health.Enabled ? PasswordStrength.Score(password) : null,
    };

    private static async Task<PasswordRevision?> LatestRevisionAsync(HarpoDbContext db, Guid entryId, CancellationToken ct)
    {
        var revisions = await db.PasswordRevisions.Where(r => r.EntryId == entryId).ToListAsync(ct);
        return revisions
            .OrderByDescending(r => r.CreatedAtUtc)
            .ThenByDescending(r => r.OriginSiteId, StringComparer.Ordinal)
            .ThenByDescending(r => r.Id)
            .FirstOrDefault();
    }

    private static async Task RequireMemberAsync(
        HarpoDbContext db, UserContext user, Guid groupId, CancellationToken ct, bool requireWrite = false)
    {
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
        if (user.IsSiteAdmin)
        {
            return;
        }
        var role = await GroupService.GetRoleAsync(db, groupId, user.Username, ct);
        if (role is null)
        {
            throw new VaultAccessDeniedException("You are not a member of this group.");
        }
        if (requireWrite && !role.Value.CanWrite())
        {
            throw new VaultAccessDeniedException("Viewers can see passwords but not change them.");
        }
    }

    private static async Task<PasswordEntry> RequireEntryAsync(
        HarpoDbContext db, UserContext user, Guid entryId, CancellationToken ct, bool requireWrite = false)
    {
        var entry = await db.PasswordEntries.SingleOrDefaultAsync(e => e.Id == entryId && !e.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Entry not found.");
        await RequireMemberAsync(db, user, entry.GroupId, ct, requireWrite);
        return entry;
    }
}
