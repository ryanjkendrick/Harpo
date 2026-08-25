using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Harpo.Security;

public sealed record TotpParameters(byte[] Secret, int Digits, int Period, string Algorithm);

public sealed record TotpCode(string Code, int SecondsRemaining, int Period);

/// <summary>
/// RFC 6238 TOTP, dependency-free. Accepts either a bare base32 secret
/// ("JBSWY3DPEHPK3PXP") or a full otpauth:// URI (what 2FA QR codes contain),
/// which may carry non-default digits, period, and algorithm.
/// </summary>
public static class Totp
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>Validates and canonicalizes user input for storage. Throws ArgumentException with a friendly message.</summary>
    public static string Normalize(string input)
    {
        var trimmed = input.Trim();
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("The 2FA secret is empty.");
        }
        var parameters = Parse(trimmed); // throws on anything unusable
        _ = Generate(parameters, DateTimeOffset.UnixEpoch); // proves it generates
        return trimmed;
    }

    public static TotpParameters Parse(string stored)
    {
        if (stored.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
        {
            var uri = new Uri(stored);
            if (!uri.Host.Equals("totp", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Only otpauth://totp/ URIs are supported (not hotp).");
            }
            var query = QueryHelpers.ParseQuery(uri.Query);
            var secret = query.TryGetValue("secret", out var s) && !string.IsNullOrWhiteSpace(s)
                ? s.ToString()
                : throw new ArgumentException("The otpauth URI has no secret parameter.");
            var digits = query.TryGetValue("digits", out var d) && int.TryParse(d, out var dv) ? dv : 6;
            var period = query.TryGetValue("period", out var p) && int.TryParse(p, out var pv) ? pv : 30;
            var algorithm = query.TryGetValue("algorithm", out var a) ? a.ToString().ToUpperInvariant() : "SHA1";
            return Create(secret, digits, period, algorithm);
        }
        return Create(stored, digits: 6, period: 30, algorithm: "SHA1");
    }

    private static TotpParameters Create(string base32Secret, int digits, int period, string algorithm)
    {
        if (digits is < 6 or > 8)
        {
            throw new ArgumentException("TOTP digits must be between 6 and 8.");
        }
        if (period is < 5 or > 300)
        {
            throw new ArgumentException("TOTP period must be between 5 and 300 seconds.");
        }
        if (algorithm is not ("SHA1" or "SHA256" or "SHA512"))
        {
            throw new ArgumentException($"Unsupported TOTP algorithm '{algorithm}'.");
        }
        return new TotpParameters(Base32Decode(base32Secret), digits, period, algorithm);
    }

    /// <summary>The current code for a stored secret/URI plus how long it stays valid.</summary>
    public static TotpCode GenerateCurrent(string stored, DateTimeOffset now)
    {
        var parameters = Parse(stored);
        var code = Generate(parameters, now);
        var elapsed = (int)(now.ToUnixTimeSeconds() % parameters.Period);
        return new TotpCode(code, parameters.Period - elapsed, parameters.Period);
    }

    public static string Generate(TotpParameters parameters, DateTimeOffset time)
    {
        var counter = time.ToUnixTimeSeconds() / parameters.Period;
        Span<byte> counterBytes = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);

        using HMAC hmac = parameters.Algorithm switch
        {
            "SHA256" => new HMACSHA256(parameters.Secret),
            "SHA512" => new HMACSHA512(parameters.Secret),
            _ => new HMACSHA1(parameters.Secret),
        };
        var hash = hmac.ComputeHash(counterBytes.ToArray());

        // RFC 4226 dynamic truncation.
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                     | (hash[offset + 1] << 16)
                     | (hash[offset + 2] << 8)
                     | hash[offset + 3];
        var code = binary % (int)Math.Pow(10, parameters.Digits);
        return code.ToString().PadLeft(parameters.Digits, '0');
    }

    /// <summary>RFC 4648 base32; tolerant of case, spaces, dashes, and missing padding.</summary>
    public static byte[] Base32Decode(string input)
    {
        var cleaned = input.Replace(" ", "").Replace("-", "").TrimEnd('=').ToUpperInvariant();
        if (cleaned.Length == 0)
        {
            throw new ArgumentException("The 2FA secret is empty.");
        }

        var bits = 0;
        var value = 0;
        var output = new List<byte>(cleaned.Length * 5 / 8);
        foreach (var c in cleaned)
        {
            var index = Base32Alphabet.IndexOf(c);
            if (index < 0)
            {
                throw new ArgumentException($"'{c}' is not valid base32 — check the 2FA secret for typos.");
            }
            value = (value << 5) | index;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        if (output.Count == 0)
        {
            throw new ArgumentException("The 2FA secret is too short.");
        }
        return output.ToArray();
    }
}
