using Harpo.Data;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Replication;

/// <summary>
/// A one-time full re-pull from every peer, run at the first start after the
/// upgrade that introduced personal vaults.
///
/// A site on an earlier version had no column for a group's owner, so a
/// personal vault that replicated to it was stored as an ordinary group — and
/// replication never re-sends a row a site has already received. Left alone,
/// such a vault would stay an ordinary group on the upgraded site, open to its
/// site admins, with nothing ever correcting it. Forgetting the peer cursors
/// makes the next replication cycles fetch every row again: rows already held
/// at the same version are skipped as usual, except that a group whose owner
/// mark is missing takes it from the peer's copy (see
/// <see cref="ReplicationEngine.ApplyAsync"/>). The cost is one pass over the
/// peers' data, bounded by the usual batch size per cycle.
/// </summary>
public static class UpgradeResync
{
    public const string MarkerId = "resynced-for-personal-vaults";

    public static async Task EnsureAsync(
        IDbContextFactory<HarpoDbContext> factory, ILogger logger, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        if (await db.SiteSettings.AnyAsync(s => s.Id == MarkerId, ct))
        {
            return;
        }
        var cursors = await db.PeerCursors.ToListAsync(ct);
        if (cursors.Count > 0)
        {
            db.PeerCursors.RemoveRange(cursors);
            logger.LogInformation(
                "First start with personal vaults: this site will fetch every row from its {Count} peer(s) once more, " +
                "so that personal vaults it received while on an earlier version are marked as such here.",
                cursors.Count);
        }
        db.SiteSettings.Add(new SiteSetting { Id = MarkerId, Value = "v1" });
        await db.SaveChangesAsync(ct);
    }
}
