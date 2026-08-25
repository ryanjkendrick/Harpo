using System.Security.Cryptography;
using System.Text;

namespace Harpo.Data;

public static class DeterministicGuid
{
    /// <summary>
    /// Derives a stable GUID from a set of parts (RFC 4122 v5-style, SHA-1 based).
    /// Used for natural-keyed rows (e.g. group membership) so that two sites
    /// creating the same logical row independently produce the same Id and the
    /// rows merge under replication instead of violating unique indexes.
    /// </summary>
    public static Guid For(params string[] parts)
    {
        var input = Encoding.UTF8.GetBytes(string.Join("\u001f", parts));
        var hash = SHA1.HashData(input);
        var bytes = new byte[16];
        Array.Copy(hash, bytes, 16);
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50); // version 5
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80); // RFC 4122 variant
        return new Guid(bytes);
    }
}
