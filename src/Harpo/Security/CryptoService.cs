using System.Security.Cryptography;
using System.Text;

namespace Harpo.Security;

/// <summary>
/// Encrypts password values at rest with AES-256-GCM. The master key comes from
/// configuration (<c>Harpo:MasterKey</c>) and must be identical on every site,
/// because ciphertext replicates between sites as-is.
///
/// Each key may be given either as base64 of exactly 32 bytes, or as an arbitrary
/// passphrase which is stretched to 32 bytes with PBKDF2-SHA256.
///
/// Rotation: <c>Harpo:PreviousMasterKeys</c> holds older keys that are still
/// accepted for DECRYPTION only — everything written (and every fingerprint
/// computed) uses the active key. While previous keys are configured, startup
/// re-encrypts local data under the active key (<see cref="KeyRotation"/>) and
/// replication re-encrypts rows arriving from not-yet-rotated peers.
/// </summary>
public sealed class CryptoService
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;
    private readonly byte[][] _previousKeys;
    private readonly byte[] _fingerprintKey;

    public CryptoService(IConfiguration configuration)
        : this(configuration["Harpo:MasterKey"]
               ?? throw new InvalidOperationException(
                   "Harpo:MasterKey is not configured. Set it to a base64-encoded 32-byte key " +
                   "(generate one with: openssl rand -base64 32) or a strong passphrase. " +
                   "All replicated sites must use the same key."),
               configuration.GetSection("Harpo:PreviousMasterKeys").Get<string[]>())
    {
    }

    public CryptoService(string masterKey, IReadOnlyList<string>? previousMasterKeys = null)
    {
        if (string.IsNullOrWhiteSpace(masterKey))
        {
            throw new InvalidOperationException("Harpo master key must not be empty.");
        }
        _key = DeriveKey(masterKey);
        _previousKeys = (previousMasterKeys ?? [])
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(DeriveKey)
            .ToArray();
        // Distinct subkey for fingerprints so equality hashes never share key
        // material with the encryption path. Deterministic across sites (same
        // master key), which replication and cross-site reuse detection require.
        using var hmac = new HMACSHA256(_key);
        _fingerprintKey = hmac.ComputeHash(Encoding.UTF8.GetBytes("Harpo.Fingerprint.v1"));
    }

    /// <summary>True while rotation keys are configured — the signal that a key rotation is underway.</summary>
    public bool HasPreviousKeys => _previousKeys.Length > 0;

    public int PreviousKeyCount => _previousKeys.Length;

    /// <summary>
    /// Keyed equality hash of a password for reuse detection. Reveals nothing to
    /// anyone without the master key; to a master-key holder it reveals only
    /// equality — and a master-key holder can decrypt outright anyway. Always
    /// computed under the ACTIVE key, so rotation changes every fingerprint —
    /// deterministically, hence identically on every site.
    /// </summary>
    public string Fingerprint(string plaintext)
    {
        using var hmac = new HMACSHA256(_fingerprintKey);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(plaintext)));
    }

    private static byte[] DeriveKey(string masterKey)
    {
        try
        {
            var raw = Convert.FromBase64String(masterKey);
            if (raw.Length == 32)
            {
                return raw;
            }
        }
        catch (FormatException)
        {
            // Not base64 — treat as a passphrase.
        }

        // Deterministic derivation (fixed salt) so every site derives the same key
        // from the same passphrase, which replication requires.
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(masterKey),
            Encoding.UTF8.GetBytes("Harpo.MasterKey.v1"),
            iterations: 210_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);
    }

    /// <summary>Returns base64( nonce[12] || tag[16] || ciphertext ). Always encrypts under the active key.</summary>
    public string Encrypt(string plaintext)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        var blob = new byte[NonceSize + TagSize + cipherBytes.Length];
        nonce.CopyTo(blob, 0);
        tag.CopyTo(blob, NonceSize);
        cipherBytes.CopyTo(blob, NonceSize + TagSize);
        return Convert.ToBase64String(blob);
    }

    /// <summary>
    /// Decrypts with the active key, falling back to each previous key in order.
    /// The GCM authentication tag makes trying a wrong key a clean failure, so no
    /// key marker is needed in the blob.
    /// </summary>
    public string Decrypt(string encrypted)
    {
        if (TryDecrypt(encrypted, out var plaintext, out _))
        {
            return plaintext;
        }
        throw new CryptographicException(
            HasPreviousKeys
                ? "The value could not be decrypted with the master key or any previous master key."
                : "The value could not be decrypted with the master key.");
    }

    /// <summary>
    /// Like <see cref="Decrypt"/> but non-throwing, and reports whether the blob
    /// was already under the active key — the rotation sweep and replication use
    /// this to decide what needs re-encrypting.
    /// </summary>
    public bool TryDecrypt(string encrypted, out string plaintext, out bool underActiveKey)
    {
        plaintext = "";
        underActiveKey = false;

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(encrypted);
        }
        catch (FormatException)
        {
            return false;
        }
        if (blob.Length < NonceSize + TagSize)
        {
            return false;
        }

        if (TryDecryptWith(_key, blob, out plaintext))
        {
            underActiveKey = true;
            return true;
        }
        foreach (var previous in _previousKeys)
        {
            if (TryDecryptWith(previous, blob, out plaintext))
            {
                return true;
            }
        }
        return false;
    }

    private static bool TryDecryptWith(byte[] key, byte[] blob, out string plaintext)
    {
        var nonce = blob.AsSpan(0, NonceSize);
        var tag = blob.AsSpan(NonceSize, TagSize);
        var cipherBytes = blob.AsSpan(NonceSize + TagSize);
        var plainBytes = new byte[cipherBytes.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipherBytes, tag, plainBytes);
        }
        catch (CryptographicException)
        {
            plaintext = "";
            return false;
        }
        plaintext = Encoding.UTF8.GetString(plainBytes);
        return true;
    }
}
