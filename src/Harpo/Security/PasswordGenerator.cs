using System.Security.Cryptography;

namespace Harpo.Security;

public static class PasswordGenerator
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!@#$%^&*-_=+?";

    /// <summary>
    /// Generates a random password containing at least one character from each
    /// class, using a cryptographic RNG. Visually ambiguous characters (O/0, l/1)
    /// are excluded.
    /// </summary>
    public static string Generate(int length = 20)
    {
        if (length < 8)
        {
            length = 8;
        }

        var all = Upper + Lower + Digits + Symbols;
        var chars = new char[length];
        chars[0] = Pick(Upper);
        chars[1] = Pick(Lower);
        chars[2] = Pick(Digits);
        chars[3] = Pick(Symbols);
        for (var i = 4; i < length; i++)
        {
            chars[i] = Pick(all);
        }

        // Fisher–Yates shuffle so the guaranteed classes aren't always in front.
        for (var i = chars.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars);
    }

    private static char Pick(string alphabet) => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
}
