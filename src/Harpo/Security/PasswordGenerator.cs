using System.Security.Cryptography;

namespace Harpo.Security;

/// <summary>User-tunable generation settings (the vault UI persists these per browser).</summary>
public sealed record PasswordGeneratorOptions
{
    public int Length { get; init; } = 20;
    public bool Uppercase { get; init; } = true;
    public bool Lowercase { get; init; } = true;
    public bool Digits { get; init; } = true;
    public bool Symbols { get; init; } = true;
    /// <summary>Skip visually confusable characters (O/0, I/l/1).</summary>
    public bool ExcludeAmbiguous { get; init; } = true;
}

public static class PasswordGenerator
{
    private const string UpperFull = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string UpperSafe = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string LowerFull = "abcdefghijklmnopqrstuvwxyz";
    private const string LowerSafe = "abcdefghijkmnopqrstuvwxyz";
    private const string DigitsFull = "0123456789";
    private const string DigitsSafe = "23456789";
    private const string SymbolSet = "!@#$%^&*-_=+?";

    public static string Generate(int length = 20) =>
        Generate(new PasswordGeneratorOptions { Length = length });

    /// <summary>
    /// Generates with a cryptographic RNG, guaranteeing at least one character
    /// from every enabled class. Length is clamped to 8–128; with every class
    /// disabled it falls back to lowercase rather than failing.
    /// </summary>
    public static string Generate(PasswordGeneratorOptions options)
    {
        var length = Math.Clamp(options.Length, 8, 128);

        var pools = new List<string>();
        if (options.Uppercase)
        {
            pools.Add(options.ExcludeAmbiguous ? UpperSafe : UpperFull);
        }
        if (options.Lowercase)
        {
            pools.Add(options.ExcludeAmbiguous ? LowerSafe : LowerFull);
        }
        if (options.Digits)
        {
            pools.Add(options.ExcludeAmbiguous ? DigitsSafe : DigitsFull);
        }
        if (options.Symbols)
        {
            pools.Add(SymbolSet);
        }
        if (pools.Count == 0)
        {
            pools.Add(options.ExcludeAmbiguous ? LowerSafe : LowerFull);
        }

        var all = string.Concat(pools);
        var chars = new char[length];
        for (var i = 0; i < pools.Count; i++)
        {
            chars[i] = Pick(pools[i]); // one from each enabled class
        }
        for (var i = pools.Count; i < length; i++)
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
