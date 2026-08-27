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
/// </summary>
public static class KeyRotation
{
    public const string CanaryId = "master-key-canary";
    public const string CanaryPlaintext = "Harpo master key canary v1";
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
            if (samples.Count > 0 && !samples.Any(s => crypto.TryDecrypt(s, out _, out _)))
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

        if (!crypto.HasPreviousKeys)
        {
            return;
        }

        logger.LogWarning(
            "Master key rotation: {Count} previous master key(s) configured. Local data is being " +
            "re-encrypted under the active key; remove Harpo:PreviousMasterKeys (and restart) once " +
            "every replicated site has been rotated and replication has caught up.",
            crypto.PreviousKeyCount);

        var (revisions, totpSecrets, undecryptable) = await SweepAsync(db, crypto, ct);

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
        if (revisions > 0 || totpSecrets > 0)
        {
            logger.LogInformation(
                "Master key rotation: re-encrypted {Revisions} password revision(s) and {Totp} 2FA secret(s) under the active key.",
                revisions, totpSecrets);
            await audit.RecordAsync(
                ServerUser, AuditActions.KeyRotate, "master-key",
                $"re-encrypted {revisions} password revision(s) and {totpSecrets} 2FA secret(s) under the active key"
                + (undecryptable > 0 ? $"; {undecryptable} value(s) matched no configured key" : ""));
        }
    }

    private static async Task<(int Revisions, int TotpSecrets, int Undecryptable)> SweepAsync(
        HarpoDbContext db, CryptoService crypto, CancellationToken ct)
    {
        var revisions = 0;
        var totpSecrets = 0;
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

        return (revisions, totpSecrets, undecryptable);
    }

    private static InvalidOperationException WrongKey(CryptoService crypto) => new(
        "Harpo:MasterKey does not match the data in this database"
        + (crypto.HasPreviousKeys ? ", and no Harpo:PreviousMasterKeys entry matches either." : ".")
        + " If you are rotating the master key, set the NEW key as Harpo:MasterKey and keep the OLD key in "
        + "Harpo:PreviousMasterKeys until every replicated site has been rotated. Refusing to start rather "
        + "than serve an unreadable vault.");
}
