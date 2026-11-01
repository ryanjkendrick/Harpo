using Harpo.Data;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Services;

/// <summary>
/// The rules of a purge, shared by the sites that purge (<see cref="PurgeService"/>),
/// the sites that hear of one (<see cref="Replication.ReplicationEngine.ApplyAsync"/>)
/// and the first start after an upgrade.
///
/// A purge is final. Its tombstone — the entry or group row, kept with every
/// field that said anything about it blanked — always wins over a version of
/// the row that is not purged, whatever their timestamps, and the password
/// history of a purged entry is deleted outright on every site that holds it.
///
/// Why revision rows are deleted rather than blanked: a blanked revision is a
/// row that has to be carried, replicated and filtered out everywhere forever,
/// for nothing. Deleting is safe under the high-watermark scheme (peers never
/// re-ask for rows below their watermark, and a row simply missing from a
/// response leaves no gap that matters), and a copy of a revision that arrives
/// later — from a site that has not heard of the purge yet — is recognised by
/// its entry and never stored.
///
/// A site still on a version without the flag passes purge tombstones on with
/// the flag dropped but everything else intact. A deleted entry or group with
/// no name is therefore a tombstone too: every version of Harpo has required a
/// name for both, so nothing but a purge ever leaves one blank.
/// </summary>
public static class Purging
{
    /// <summary>Whether this entry row is a purge tombstone (flagged, or relayed by a site that dropped the flag).</summary>
    public static bool IsTombstone(PasswordEntry entry) =>
        entry.IsPurged || (entry.IsDeleted && entry.Name.Length == 0);

    /// <summary>Whether this group row is a purge tombstone (flagged, or relayed by a site that dropped the flag).</summary>
    public static bool IsTombstone(Group group) =>
        group.IsPurged || (group.IsDeleted && group.Name.Length == 0);

    /// <summary>Blanks everything the entry held and marks it purged. Its id, group and replication stamps stay.</summary>
    public static void Erase(PasswordEntry entry)
    {
        entry.Name = "";
        entry.Icon = "";
        entry.Url = "";
        entry.Username = "";
        entry.EncryptedNotes = "";
        entry.EncryptedTotpSecret = null;
        entry.IsDeleted = true;
        entry.IsPurged = true;
    }

    /// <summary>Blanks the group's name and description and marks it purged. Its id, owner mark and stamps stay.</summary>
    public static void Erase(Group group)
    {
        group.Name = "";
        group.Description = "";
        group.IsDeleted = true;
        group.IsPurged = true;
    }

    public static bool IsErased(PasswordEntry e) =>
        e.IsPurged && e.IsDeleted && e.Name.Length == 0 && e.Icon.Length == 0 && e.Url.Length == 0
        && e.Username.Length == 0 && e.EncryptedNotes.Length == 0 && e.EncryptedTotpSecret is null;

    public static bool IsErased(Group g) =>
        g.IsPurged && g.IsDeleted && g.Name.Length == 0 && g.Description.Length == 0;

    /// <summary>
    /// Brings the local store in line with the purges it holds, without touching
    /// any replication stamp: every tombstone fully blanked and flagged, every
    /// entry of a purged group purged with it, and no password revision left for
    /// a purged entry. Saves through <paramref name="db"/>, so the caller owns the
    /// write gate and any transaction. Limited to the given groups and entries
    /// (the rows a replication batch touched) or, with both null, the whole
    /// store (the first start after an upgrade). Returns how many rows it changed
    /// or deleted; when that is not zero, the caller has the file scrubbed.
    /// </summary>
    internal static async Task<int> SettleAsync(
        HarpoDbContext db, IReadOnlyCollection<Guid>? groupIds, IReadOnlyCollection<Guid>? entryIds, CancellationToken ct)
    {
        var scopedGroups = groupIds is null ? db.Groups : db.Groups.Where(g => groupIds.Contains(g.Id));
        var scopedEntries = entryIds is null ? db.PasswordEntries : db.PasswordEntries.Where(e => entryIds.Contains(e.Id));

        var purgedGroupIds = scopedGroups
            .Where(g => g.IsPurged || (g.IsDeleted && g.Name == ""))
            .Select(g => g.Id);
        var tombstoneIds = scopedEntries
            .Where(e => e.IsPurged || (e.IsDeleted && e.Name == ""))
            .Select(e => e.Id);

        var changed = 0;
        var groups = await scopedGroups
            .Where(g => g.IsPurged || (g.IsDeleted && g.Name == ""))
            .Where(g => !g.IsPurged || !g.IsDeleted || g.Name != "" || g.Description != "")
            .ToListAsync(ct);
        foreach (var group in groups)
        {
            Erase(group);
            changed++;
        }

        var entries = await db.PasswordEntries
            .Where(e => tombstoneIds.Contains(e.Id) || (!e.IsPurged && purgedGroupIds.Contains(e.GroupId)))
            .Where(e => !e.IsPurged || !e.IsDeleted || e.Name != "" || e.Icon != "" || e.Url != ""
                        || e.Username != "" || e.EncryptedNotes != "" || e.EncryptedTotpSecret != null)
            .ToListAsync(ct);
        foreach (var entry in entries)
        {
            Erase(entry);
            changed++;
        }
        if (changed > 0)
        {
            await db.SaveChangesAsync(ct);
        }

        // Every entry in scope is purged in the database now, so one statement
        // finds every revision that must go.
        var purgedEntryIds = db.PasswordEntries
            .Where(e => e.IsPurged && (tombstoneIds.Contains(e.Id) || purgedGroupIds.Contains(e.GroupId)))
            .Select(e => e.Id);
        changed += await db.PasswordRevisions
            .Where(r => purgedEntryIds.Contains(r.EntryId))
            .ExecuteDeleteAsync(ct);
        return changed;
    }

    /// <summary>
    /// The first start after an upgrade to this version (and every start after
    /// it, cheaply): a site that was on an earlier version may have received purge
    /// tombstones it could not act on — it blanked the rows but kept the entries'
    /// password history. Finish those purges here, then remove what they leave
    /// in the database file. Also completes a scrub that a crash interrupted.
    /// </summary>
    public static async Task FinishAsync(
        IDbContextFactory<HarpoDbContext> factory, DatabaseScrubber scrubber, ILogger logger, CancellationToken ct = default)
    {
        await using (var db = await factory.CreateDbContextAsync(ct))
        {
            // Local healing only: nothing here may look like a fresh edit to the mesh.
            db.SuppressReplicationStamping = true;
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var changed = await SettleAsync(db, null, null, ct);
            if (changed > 0)
            {
                await DatabaseScrubber.MarkPendingAsync(db, ct);
                logger.LogInformation(
                    "Finished purges this site had received but not yet carried out ({Count} rows erased or removed).",
                    changed);
            }
            await transaction.CommitAsync(ct);
        }
        await scrubber.ScrubIfPendingAsync(ct);
    }
}
