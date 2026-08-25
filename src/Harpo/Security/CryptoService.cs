using System.Security.Cryptography;
using System.Text;

namespace Harpo.Security;

/// <summary>
/// Encrypts password values at rest with AES-256-GCM. The master key comes from
/// configuration (<c>Harpo:MasterKey</c>) and must be identical on every site,
/// because ciphertext replicates between sites as-is.
///
/// The key may be given either as base64 of exactly 32 bytes, or as an arbitrary
/// passphrase which is stretched to 32 bytes with PBKDF2-SHA256.
/// </summary>
public sealed class CryptoService
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;

    public CryptoService(IConfiguration configuration)
        : this(configuration["Harpo:MasterKey"]
               ?? throw new InvalidOperationException(
                   "Harpo:MasterKey is not configured. Set it to a base64-encoded 32-byte key " +
                   "(generate one with: openssl rand -base64 32) or a strong passphrase. " +
                   "All replicated sites must use the same key."))
    {
    }

    public CryptoService(string masterKey)
    {
        if (string.IsNullOrWhiteSpace(masterKey))
        {
            throw new InvalidOperationException("Harpo master key must not be empty.");
        }
        _key = DeriveKey(masterKey);
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

    /// <summary>Returns base64( nonce[12] || tag[16] || ciphertext ).</summary>
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

    public string Decrypt(string encrypted)
    {
        var blob = Convert.FromBase64String(encrypted);
        if (blob.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Ciphertext blob is too short.");
        }

        var nonce = blob.AsSpan(0, NonceSize);
        var tag = blob.AsSpan(NonceSize, TagSize);
        var cipherBytes = blob.AsSpan(NonceSize + TagSize);
        var plainBytes = new byte[cipherBytes.Length];

        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);
        return Encoding.UTF8.GetString(plainBytes);
    }
}
