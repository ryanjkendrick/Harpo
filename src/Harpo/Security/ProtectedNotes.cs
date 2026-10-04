namespace Harpo.Security;

/// <summary>
/// How an entry's notes are kept at rest. People put recovery codes and security
/// answers in notes, so they are encrypted with the master key like passwords
/// and 2FA secrets — in the database, and therefore in what replicates.
///
/// The stored value is one of:
///  - empty — no notes;
///  - <see cref="Marker"/> followed by a <see cref="CryptoService"/> blob;
///  - anything else — plain text from before notes were encrypted, or from a
///    peer site still running such a version. It is readable as it is, and is
///    encrypted where it stands the first time this code meets it: at startup
///    (<see cref="KeyRotation"/>) or as the row arrives by replication.
///
/// The marker is what tells the last two apart, so text that starts with it is
/// always taken to be ciphertext.
/// </summary>
public static class ProtectedNotes
{
    public const string Marker = "enc:v1:";

    public static bool IsProtected(string stored) => stored.StartsWith(Marker, StringComparison.Ordinal);

    /// <summary>What to store for notes as the user typed them.</summary>
    public static string Protect(CryptoService crypto, string plaintext) =>
        plaintext.Length == 0 ? "" : Marker + crypto.Encrypt(plaintext);

    /// <summary>
    /// The notes behind a stored value. False only when they are encrypted under
    /// a key this site does not have — a peer on another master key, or a rotation
    /// applied out of order; never for empty or not-yet-encrypted values.
    /// </summary>
    public static bool TryRead(CryptoService crypto, string stored, out string plaintext)
    {
        if (!IsProtected(stored))
        {
            plaintext = stored;
            return true;
        }
        return crypto.TryDecrypt(stored[Marker.Length..], out plaintext, out _);
    }

    /// <summary>
    /// What to store when an entry is saved with <paramref name="plaintext"/> in
    /// its notes field.
    ///
    /// Notes this site cannot read are shown to the user as an empty field, so an
    /// empty field coming back means "I did not touch them", not "delete them":
    /// they are kept, the same way a blank 2FA field keeps the secret. Typing
    /// something replaces them. Unchanged notes keep their existing ciphertext
    /// rather than being re-encrypted on every save.
    /// </summary>
    public static string Replace(CryptoService crypto, string stored, string plaintext)
    {
        if (!TryRead(crypto, stored, out var current))
        {
            return plaintext.Length == 0 ? stored : Protect(crypto, plaintext);
        }
        var alreadyStoredThatWay = stored.Length == 0 || IsProtected(stored);
        return current == plaintext && alreadyStoredThatWay ? stored : Protect(crypto, plaintext);
    }

    /// <summary>
    /// For values this site did not just write — its own rows at startup, a
    /// peer's rows as they arrive. True, with the value to hold instead, when the
    /// notes are still plain text (encrypt them) or encrypted under a previous
    /// master key during a rotation (move them to the active key). Empty notes,
    /// notes already under the active key, and notes no configured key opens are
    /// left exactly as they are; <paramref name="unreadable"/> flags the last.
    /// </summary>
    public static bool TryBringUpToDate(CryptoService crypto, string stored, out string updated, out bool unreadable)
    {
        updated = stored;
        unreadable = false;
        if (stored.Length == 0)
        {
            return false;
        }
        if (!IsProtected(stored))
        {
            updated = Protect(crypto, stored);
            return true;
        }
        if (!crypto.TryDecrypt(stored[Marker.Length..], out var plaintext, out var underActiveKey))
        {
            unreadable = true;
            return false;
        }
        if (underActiveKey)
        {
            return false;
        }
        updated = Protect(crypto, plaintext);
        return true;
    }
}
