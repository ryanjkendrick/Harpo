using Harpo.Data;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Services;

/// <summary>
/// Purging: removing deleted entries (and deleted groups) for good — every
/// password revision, the notes, the 2FA secret, the name, URL, username and
/// icon — on every site, and from the database file itself. Deleting stays the
/// everyday, undoable operation; purge is the one that cannot be undone, for
/// a secret pasted into the wrong vault or test data that must not linger.
///
/// Who may purge: in a shared group its admins and the site administrators; in
/// a personal vault its owner, and nobody else (site administrators included,
/// as everywhere). Members and viewers can delete and restore but not purge.
/// Only what is already deleted can be purged. A deleted group is purged from
/// the Administration page, by site administrators, who alone see deleted groups.
///
/// The rows stay as blank tombstones with fresh replication stamps, so the
/// purge replicates like any other write and wins over every version of the row
/// that is not purged (<see cref="Purging"/>). The audit trail is never purged:
/// what earlier events recorded (an entry's name in a shared group's delete
/// event, say) stays there.
/// </summary>
public sealed class PurgeService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly AuditService _audit;
    private readonly SessionService _sessions;
    private readonly DatabaseScrubber _scrubber;
    private readonly ILogger<PurgeService> _logger;

    public PurgeService(IDbContextFactory<HarpoDbContext> dbFactory, AuditService audit, SessionService sessions,
        DatabaseScrubber scrubber, ILogger<PurgeService> logger)
    {
        _dbFactory = dbFactory;
        _audit = audit;
        _sessions = sessions;
        _scrubber = scrubber;
        _logger = logger;
    }

    /// <summary>Purges one deleted entry. Its group must be live; a deleted group is purged as a whole.</summary>
    public async Task PurgeEntryAsync(UserContext user, Guid entryId, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        string description;
        Guid groupId;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            // Rights, "is it deleted?" and the erasure are one step, so a restore
            // on this site cannot slip in between.
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var entry = await db.PasswordEntries.SingleOrDefaultAsync(e => e.Id == entryId && !e.IsPurged, ct)
                ?? throw new VaultNotFoundException("Deleted entry not found.");
            await RequirePurgeRightsAsync(db, user, entry.GroupId, ct);
            if (!entry.IsDeleted)
            {
                throw new VaultValidationException("Only a deleted entry can be purged. Delete it first.");
            }
            groupId = entry.GroupId;
            description = await VaultService.DescribeEntryAsync(db, entry, ct);

            Purging.Erase(entry);
            entry.UpdatedBy = user.Username;
            await db.SaveChangesAsync(ct);
            await db.PasswordRevisions.Where(r => r.EntryId == entryId).ExecuteDeleteAsync(ct);
            await DatabaseScrubber.MarkPendingAsync(db, ct);
            await transaction.CommitAsync(ct);
        }
        _logger.LogInformation("{User} purged entry {Entry}", user.Username, entryId);
        await _audit.RecordAsync(user, AuditActions.EntryPurge, description, groupId: groupId, entryId: entryId);
        await _scrubber.ScrubAsync(ct);
    }

    /// <summary>
    /// Purges every deleted entry of a vault in one go ("Empty recycle bin").
    /// Returns how many were purged. Audited once, with the count.
    /// </summary>
    public async Task<int> EmptyRecycleBinAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        Group group;
        int count;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            group = await RequirePurgeRightsAsync(db, user, groupId, ct);
            var entries = await db.PasswordEntries
                .Where(e => e.GroupId == groupId && e.IsDeleted && !e.IsPurged)
                .ToListAsync(ct);
            count = entries.Count;
            if (count == 0)
            {
                return 0;
            }
            foreach (var entry in entries)
            {
                Purging.Erase(entry);
                entry.UpdatedBy = user.Username;
            }
            await db.SaveChangesAsync(ct);
            var ids = entries.Select(e => e.Id).ToList();
            await db.PasswordRevisions.Where(r => ids.Contains(r.EntryId)).ExecuteDeleteAsync(ct);
            await DatabaseScrubber.MarkPendingAsync(db, ct);
            await transaction.CommitAsync(ct);
        }
        _logger.LogInformation("{User} emptied the recycle bin of group {Group}: {Count} entries purged",
            user.Username, groupId, count);
        await _audit.RecordAsync(user, AuditActions.BinEmpty, VaultService.DescribeVault(group),
            detail: Entries(count), groupId: groupId);
        await _scrubber.ScrubAsync(ct);
        return count;
    }

    /// <summary>
    /// Purges a deleted group: every entry in it (deleted or not — they would
    /// come back with the group) and the group's name and description. The
    /// group can no longer be restored and is no longer listed. Site
    /// administrators only, like restoring one. Returns how many entries were purged.
    /// </summary>
    public async Task<int> PurgeGroupAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site administrators can purge a deleted group.");
        }
        await _sessions.RequireLiveAsync(user, ct);
        string name;
        int count;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            // Deleted groups are always shared ones: a personal vault cannot be
            // deleted, and is never purged through here.
            var group = await db.Groups.SingleOrDefaultAsync(
                    g => g.Id == groupId && g.IsDeleted && !g.IsPurged && g.OwnerUsername == "", ct)
                ?? throw new VaultNotFoundException("Deleted group not found.");
            name = group.Name;
            var entries = await db.PasswordEntries
                .Where(e => e.GroupId == groupId && !e.IsPurged)
                .ToListAsync(ct);
            count = entries.Count;
            Purging.Erase(group);
            foreach (var entry in entries)
            {
                Purging.Erase(entry);
                entry.UpdatedBy = user.Username;
            }
            await db.SaveChangesAsync(ct);
            await db.PasswordRevisions
                .Where(r => db.PasswordEntries.Any(e => e.Id == r.EntryId && e.GroupId == groupId))
                .ExecuteDeleteAsync(ct);
            await DatabaseScrubber.MarkPendingAsync(db, ct);
            await transaction.CommitAsync(ct);
        }
        _logger.LogInformation("{User} purged deleted group {Group} with {Count} entries", user.Username, groupId, count);
        await _audit.RecordAsync(user, AuditActions.GroupPurge, name, detail: Entries(count), groupId: groupId);
        await _scrubber.ScrubAsync(ct);
        return count;
    }

    private static string Entries(int count) => count == 1 ? "1 entry" : $"{count} entries";

    /// <summary>
    /// Who may purge in a live vault: its owner for a personal vault (and nobody
    /// else — checked before anything else, so no site-admin right reaches it),
    /// and for a shared group its admins and the site administrators.
    /// </summary>
    private static async Task<Group> RequirePurgeRightsAsync(
        HarpoDbContext db, UserContext user, Guid groupId, CancellationToken ct)
    {
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
        GroupService.RequireNotSomeoneElsesPersonalVault(group, user);
        if (group.IsPersonal || user.IsSiteAdmin)
        {
            return group;
        }
        var role = await GroupService.GetRoleAsync(db, groupId, user.Username, ct);
        if (role != GroupRole.Admin)
        {
            throw new VaultAccessDeniedException(role is null
                ? "You are not a member of this group."
                : "Only the group's admins can purge deleted passwords.");
        }
        return group;
    }
}
