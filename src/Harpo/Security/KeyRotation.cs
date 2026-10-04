using Harpo.Data;
using Harpo.Services;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Security;

/// <summary>
/// Reconciles stored ciphertext with the configured master key at startup.
///
/// Rotation model: ciphertext replicates between sites as-is, but password
/// revisions merge append-only (an updated row never re-replicates), so a
/// central re-encryption could not propagate — instead EVERY site re-encrypts
/// its own local copy when it starts with the new key active and the old key in
/// <c>Harpo:PreviousMasterKeys</c>. Sites share the same keys and fingerprints
/// are deterministic HMACs, so the independent sweeps converge: fingerprints
/// come out identical everywhere, while ciphertext bytes differ per site
/// (GCM nonces are random) — harmless, because revisions never replicate as
/// updates. Rows arriving from not-yet-rotated peers keep working through the
/// decrypt fallback chain and are re-encrypted on arrival by the replication
/// engine.
///
/// A site-local "canary" (a known value encrypted under the active key) makes a
/// misconfigured master key a loud startup failure instead of a silently
/// unreadable vault.
///
/// The same pass encrypts entry notes that an earlier version stored as plain
/// text (see <see cref="ProtectedNotes"/>) — on every start, rotation or not,
/// and like rotation, locally and without touching replication stamps.
/// </summary>
public static class KeyRotation
{
    public const string CanaryId = "master-key-canary";
    public const string CanaryPlaintext = "Harpo master key canary v1";
    /// <summary>Site-local marker: this database file has been rewritten since notes became encrypted.</summary>
    public const string NotesScrubbedId = "plain-text-notes-scrubbed";
    private const int BatchSize = 500;

    private static readonly UserContext ServerUser = new("server", "Server", IsSiteAdmin: true);

    public static async Task EnsureMasterKeyStateAsync(
        IDbContextFactory<HarpoDbContext> factory,
        CryptoService crypto,
        AuditService audit,
        ILogger logger,
        CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        // Local healing only: nothing this class writes may bump replication
        // stamps, or rotation would masquerade as fresh edits to the mesh.
        db.SuppressReplicationStamping = true;

        var canary = await db.SiteSettings.SingleOrDefaultAsync(x => x.Id == CanaryId, ct);
        if (canary is null)
        {
            // Databases from before this feature (or brand-new ones) have no
            // canary yet. Before trusting the configured key, validate it
            // against real data if there is any.
            var samples = await db.PasswordRevisions.AsNoTracking()
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(5)
                .Select(x => x.EncryptedPassword)
                .ToListAsync(ct);
            if (samples.Count == 0)
            {
                // An empty vault proves nothing about the configured key. Planting
                // a canary now would bless whatever was set — a typo included — and
                // let a mis-keyed site join a cluster and silently diverge (it would
                // store peer rows it cannot read, and write its own secrets under a
                // key no peer can read). Plant nothing: the canary is established
                // either on a later start once real data exists, or by the
                // replication engine on the first sync that proves the key against a
                // peer's data (see ValidateFirstSyncAsync). Nothing to sweep either.
                return;
            }
            if (!samples.Any(s => crypto.TryDecrypt(s, out _, out _)))
            {
                throw WrongKey(crypto);
            }
            db.SiteSettings.Add(new SiteSetting { Id = CanaryId, Value = crypto.Encrypt(CanaryPlaintext) });
            await db.SaveChangesAsync(ct);
        }
        else if (!crypto.TryDecrypt(canary.Value, out var canaryPlain, out _) || canaryPlain != CanaryPlaintext)
        {
            throw WrongKey(crypto);
        }

        // The key is proven from here on, so it is safe to encrypt with it. Notes
        // were plain text before they were encrypted; whatever an upgrade left
        // behind is converted now, before the site serves a request.
        var legacyNotes = await EncryptPlainTextNotesAsync(db, crypto, ct);
        if (legacyNotes > 0)
        {
            logger.LogInformation(
                "Encrypted the notes of {Count} entr{Plural} that an earlier version had stored as plain text.",
                legacyNotes, legacyNotes == 1 ? "y" : "ies");
        }
        await ScrubPlainTextRemnantsAsync(db, rowsWereConverted: legacyNotes > 0, logger, ct);

        if (!crypto.HasPreviousKeys)
        {
            return;
        }

        logger.LogWarning(
            "Master key rotation: {Count} previous master key(s) configured. Local data is being " +
            "re-encrypted under the active key; remove Harpo:PreviousMasterKeys (and restart) once " +
            "every replicated site has been rotated and replication has caught up.",
            crypto.PreviousKeyCount);

        var (revisions, totpSecrets, notes, undecryptable) = await SweepAsync(db, crypto, ct);

        // The canary follows the data: once the sweep ran, it must live under
        // the active key so a later start without the previous keys succeeds.
        canary = await db.SiteSettings.SingleAsync(x => x.Id == CanaryId, ct);
        if (!(crypto.TryDecrypt(canary.Value, out _, out var underActive) && underActive))
        {
            canary.Value = crypto.Encrypt(CanaryPlaintext);
            await db.SaveChangesAsync(ct);
        }

        if (undecryptable > 0)
        {
            logger.LogWarning(
                "Master key rotation: {Count} value(s) could not be decrypted with any configured key " +
                "and were left untouched. They may belong to a peer whose key was never shared here; " +
                "revealing them will fail until a matching key is configured.",
                undecryptable);
        }
        if (revisions > 0 || totpSecrets > 0 || notes > 0)
        {
            logger.LogInformation(
                "Master key rotation: re-encrypted {Revisions} password revision(s), {Totp} 2FA secret(s) and " +
                "the notes of {Notes} entr(ies) under the active key.",
                revisions, totpSecrets, notes);
            await audit.RecordAsync(
                ServerUser, AuditActions.KeyRotate, "master-key",
                $"re-encrypted {revisions} password revision(s), {totpSecrets} 2FA secret(s) and "
                + $"the notes of {notes} entr{(notes == 1 ? "y" : "ies")} under the active key"
                + (undecryptable > 0 ? $"; {undecryptable} value(s) matched no configured key" : ""));
        }
    }

    /// <summary>
    /// Encrypts notes still held as plain text. Each converted row drops out of
    /// the filter, so the loop simply asks for "the next batch" until none is left;
    /// tombstoned entries are included, since an entry restored from the trash
    /// brings its notes back with it.
    /// </summary>
    private static async Task<int> EncryptPlainTextNotesAsync(HarpoDbContext db, CryptoService crypto, CancellationToken ct)
    {
        var converted = 0;
        while (true)
        {
            // GLOB, not StartsWith: that becomes LIKE, which SQLite matches without
            // regard to case, and the marker is case-sensitive everywhere else.
            var page = await db.PasswordEntries
                .Where(x => x.EncryptedNotes != "" && !EF.Functions.Glob(x.EncryptedNotes, ProtectedNotes.Marker + "*"))
                .OrderBy(x => x.Id)
                .Take(BatchSize)
                .ToListAsync(ct);
            if (page.Count == 0)
            {
                return converted;
            }
            foreach (var entry in page)
            {
                entry.EncryptedNotes = ProtectedNotes.Protect(crypto, entry.EncryptedNotes);
                converted++;
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
    }

    /// <summary>
    /// Encrypting a row does not remove what the row used to say. SQLite leaves
    /// the old bytes in the pages it freed and in its write-ahead log until
    /// something overwrites them, so right after the conversion the "encrypted"
    /// notes could still be read out of the database file with a hex editor —
    /// as could notes that were edited or cleared long before it. Rewriting the
    /// file (VACUUM) and emptying the log is what actually removes them.
    ///
    /// Done once per database (a site-local marker records it), and again
    /// whenever a start finds plain-text notes to convert. If it fails — a full
    /// disk, say — the notes are still encrypted where they are used; the marker
    /// is withheld so the next start tries again.
    /// </summary>
    private static async Task ScrubPlainTextRemnantsAsync(
        HarpoDbContext db, bool rowsWereConverted, ILogger logger, CancellationToken ct)
    {
        var marker = await db.SiteSettings.SingleOrDefaultAsync(x => x.Id == NotesScrubbedId, ct);
        if (marker is not null && !rowsWereConverted)
        {
            return;
        }
        try
        {
            await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(TRUNCATE);", ct);
            await db.Database.ExecuteSqlRawAsync("VACUUM;", ct);
            await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(TRUNCATE);", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex,
                "Notes are encrypted, but the database file could not be rewritten to remove the plain-text " +
                "copies SQLite keeps in freed pages. This will be retried at the next start.");
            if (marker is not null)
            {
                db.SiteSettings.Remove(marker);
                await db.SaveChangesAsync(ct);
            }
            return;
        }
        if (marker is null)
        {
            db.SiteSettings.Add(new SiteSetting { Id = NotesScrubbedId, Value = "v1" });
            await db.SaveChangesAsync(ct);
        }
    }

    private static async Task<(int Revisions, int TotpSecrets, int Notes, int Undecryptable)> SweepAsync(
        HarpoDbContext db, CryptoService crypto, CancellationToken ct)
    {
        var revisions = 0;
        var totpSecrets = 0;
        var notes = 0;
        var undecryptable = 0;

        // Page by Id so interleaved saves can't skip rows; tombstoned rows are
        // swept too — restored entries must still reveal their history.
        for (var offset = 0; ; offset += BatchSize)
        {
            var page = await db.PasswordRevisions
                .OrderBy(x => x.Id)
                .Skip(offset)
                .Take(BatchSize)
                .ToListAsync(ct);
            if (page.Count == 0)
            {
                break;
            }
            foreach (var revision in page)
            {
                if (!crypto.TryDecrypt(revision.EncryptedPassword, out var plaintext, out var underActive))
                {
                    undecryptable++;
                    continue;
                }
                if (underActive)
                {
                    continue;
                }
                revision.EncryptedPassword = crypto.Encrypt(plaintext);
                revision.Fingerprint = crypto.Fingerprint(plaintext);
                revisions++;
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        for (var offset = 0; ; offset += BatchSize)
        {
            var page = await db.PasswordEntries
                .Where(x => x.EncryptedTotpSecret != null)
                .OrderBy(x => x.Id)
                .Skip(offset)
                .Take(BatchSize)
                .ToListAsync(ct);
            if (page.Count == 0)
            {
                break;
            }
            foreach (var entry in page)
            {
                if (!crypto.TryDecrypt(entry.EncryptedTotpSecret!, out var plaintext, out var underActive))
                {
                    undecryptable++;
                    continue;
                }
                if (underActive)
                {
                    continue;
                }
                entry.EncryptedTotpSecret = crypto.Encrypt(plaintext);
                totpSecrets++;
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        for (var offset = 0; ; offset += BatchSize)
        {
            var page = await db.PasswordEntries
                .Where(x => x.EncryptedNotes != "")
                .OrderBy(x => x.Id)
                .Skip(offset)
                .Take(BatchSize)
                .ToListAsync(ct);
            if (page.Count == 0)
            {
                break;
            }
            foreach (var entry in page)
            {
                if (ProtectedNotes.TryBringUpToDate(crypto, entry.EncryptedNotes, out var updated, out var unreadable))
                {
                    entry.EncryptedNotes = updated;
                    notes++;
                }
                else if (unreadable)
                {
                    undecryptable++;
                }
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        return (revisions, totpSecrets, notes, undecryptable);
    }

    /// <summary>
    /// First-sync master-key check for a site that started empty (so
    /// <see cref="EnsureMasterKeyStateAsync"/> planted no canary). The replication
    /// engine calls this as a peer's rows are merged. While no canary exists yet,
    /// if password revisions have arrived from a peer and NONE of them decrypt
    /// under any configured key, the configured master key does not match the
    /// cluster — throw so replication halts loudly (surfaced as the peer's last
    /// error) instead of filling the store with unreadable ciphertext. Once at
    /// least one revision decrypts, the key is proven against real cluster data,
    /// so a canary is planted (committed by the caller's SaveChanges) and later
    /// starts fail fast the same way a pre-existing vault does.
    /// Established sites (canary present) are left untouched.
    /// </summary>
    internal static async Task ValidateFirstSyncAsync(
        HarpoDbContext db, CryptoService crypto, IReadOnlyCollection<string> incomingRevisionBlobs, CancellationToken ct)
    {
        if (incomingRevisionBlobs.Count == 0)
        {
            return; // no ciphertext to test the key against in this batch
        }
        if (await db.SiteSettings.AnyAsync(x => x.Id == CanaryId, ct))
        {
            return; // key already proven; normal merge rules apply from here
        }
        if (!incomingRevisionBlobs.Any(blob => crypto.TryDecrypt(blob, out _, out _)))
        {
            throw new InvalidOperationException(
                "This site's Harpo:MasterKey does not match the cluster: none of the password data "
                + "replicated from the peer can be decrypted with the configured key(s). Replication is "
                + "halted so this site does not fill up with unreadable data, or write new secrets under a "
                + "key no other site can read. Set Harpo:MasterKey to the cluster's key (and stage any old "
                + "keys in Harpo:PreviousMasterKeys if you are rotating), then restart.");
        }
        db.SiteSettings.Add(new SiteSetting { Id = CanaryId, Value = crypto.Encrypt(CanaryPlaintext) });
    }

    private static InvalidOperationException WrongKey(CryptoService crypto) => new(
        "Harpo:MasterKey does not match the data in this database"
        + (crypto.HasPreviousKeys ? ", and no Harpo:PreviousMasterKeys entry matches either." : ".")
        + " If you are rotating the master key, set the NEW key as Harpo:MasterKey and keep the OLD key in "
        + "Harpo:PreviousMasterKeys until every replicated site has been rotated. Refusing to start rather "
        + "than serve an unreadable vault.");
}
