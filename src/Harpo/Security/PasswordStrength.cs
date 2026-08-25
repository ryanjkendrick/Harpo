namespace Harpo.Security;

/// <summary>
/// Deliberately simple, dependency-free password strength heuristic in the
/// spirit of zxcvbn's buckets: 0 terrible, 1 weak, 2 fair, 3 good, 4 strong.
/// It estimates pool entropy from length and character variety, then applies
/// penalties for well-known passwords, repeats, and sequential runs. It is a
/// hygiene signal for the health report, not a cracking-cost oracle.
/// </summary>
public static class PasswordStrength
{
    private static readonly HashSet<string> Common = new(StringComparer.Ordinal)
    {
        "password", "passwort", "passw0rd", "password1", "p@ssword", "p@ssw0rd",
        "123456", "1234567", "12345678", "123456789", "1234567890", "12345",
        "qwerty", "qwertyuiop", "qwerty123", "azerty", "asdfgh", "asdfghjkl", "zxcvbnm",
        "letmein", "welcome", "welcome1", "admin", "administrator", "root", "login",
        "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "baseball",
        "master", "shadow", "superman", "batman", "trustno1", "starwars", "whatever",
        "abc123", "abcd1234", "111111", "000000", "654321", "666666", "121212",
        "secret", "changeme", "default", "guest", "test", "temp",
    };

    public static int Score(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return 0;
        }

        var lower = password.ToLowerInvariant();
        // "Password2024!" is still "password".
        var stripped = lower.TrimEnd("0123456789!@#$%^&*.?_-".ToCharArray());
        if (Common.Contains(lower) || (stripped.Length >= 4 && Common.Contains(stripped)))
        {
            return 0;
        }

        var pool = 0;
        if (password.Any(char.IsLower)) { pool += 26; }
        if (password.Any(char.IsUpper)) { pool += 26; }
        if (password.Any(char.IsDigit)) { pool += 10; }
        if (password.Any(c => !char.IsLetterOrDigit(c))) { pool += 33; }
        var entropy = password.Length * Math.Log2(Math.Max(pool, 1));

        // Low variety and lazy patterns don't deserve their nominal entropy.
        if (password.Distinct().Count() <= 2)
        {
            entropy = Math.Min(entropy, 20);
        }
        if (HasRun(password, minLength: 4))
        {
            entropy *= 0.6;
        }

        return entropy switch
        {
            < 28 => 0,
            < 36 => 1,
            < 60 => 2,
            < 80 => 3,
            _ => 4,
        };
    }

    public static string Label(int? score) => score switch
    {
        0 => "terrible",
        1 => "weak",
        2 => "fair",
        3 => "good",
        4 => "strong",
        _ => "unscored",
    };

    /// <summary>Detects runs of identical ("aaaa") or consecutive ("abcd", "4321") characters.</summary>
    private static bool HasRun(string password, int minLength)
    {
        var same = 1;
        var up = 1;
        var down = 1;
        for (var i = 1; i < password.Length; i++)
        {
            var delta = password[i] - password[i - 1];
            same = delta == 0 ? same + 1 : 1;
            up = delta == 1 ? up + 1 : 1;
            down = delta == -1 ? down + 1 : 1;
            if (same >= minLength || up >= minLength || down >= minLength)
            {
                return true;
            }
        }
        return false;
    }
}
