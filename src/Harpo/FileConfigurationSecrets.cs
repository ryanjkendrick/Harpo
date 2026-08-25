namespace Harpo;

/// <summary>
/// Lets any configuration value be supplied from a file instead of inline, so
/// keys can come from Docker/Kubernetes secrets rather than environment
/// variables: set <c>&lt;Key&gt;__File</c> to a path and the file's (trimmed)
/// content becomes <c>&lt;Key&gt;</c>. For example:
///
///   Harpo__MasterKey__File: /run/secrets/harpo_master_key
///
/// Works for every key (master key, database key, replication key, ...). A
/// configured file that does not exist fails startup loudly — a half-applied
/// secret must never fall back to an empty value.
/// </summary>
public static class FileConfigurationSecrets
{
    public const string Suffix = ":File";

    public static void ApplyFileIndirection(IConfigurationManager configuration)
    {
        var overrides = new Dictionary<string, string?>();
        foreach (var (key, value) in configuration.AsEnumerable())
        {
            if (!key.EndsWith(Suffix, StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }
            if (!File.Exists(value))
            {
                throw new InvalidOperationException(
                    $"Configuration key '{key}' points at '{value}', but that file does not exist. " +
                    "Fix the secret mount or remove the setting.");
            }
            overrides[key[..^Suffix.Length]] = File.ReadAllText(value).Trim();
        }
        if (overrides.Count > 0)
        {
            configuration.AddInMemoryCollection(overrides);
        }
    }
}
