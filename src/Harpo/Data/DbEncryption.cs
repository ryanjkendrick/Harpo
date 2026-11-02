using Microsoft.Data.Sqlite;

namespace Harpo.Data;

public sealed record DbEncryptionOptions(
    string? DatabaseKey,
    string? PreviousDatabaseKey,
    bool RemoveEncryption,
    bool KeyLeftBlank = false)
{
    public static DbEncryptionOptions FromConfiguration(IConfiguration configuration) => new(
        Nullify(configuration["Harpo:DatabaseKey"]),
        Nullify(configuration["Harpo:PreviousDatabaseKey"]),
        configuration.GetValue("Harpo:RemoveDatabaseEncryption", false),
        IsKeyLeftBlank(configuration));

    // appsettings.json ships a blank key, so a blank value alone means nothing. It
    // is a mistake only when someone supplied it: "${HARPO_DATABASE_KEY}" with the
    // variable unset, or an empty secret file.
    private static bool IsKeyLeftBlank(IConfiguration configuration) =>
        string.IsNullOrWhiteSpace(configuration["Harpo:DatabaseKey"])
        && (Environment.GetEnvironmentVariable("Harpo__DatabaseKey") is not null
            || !string.IsNullOrWhiteSpace(configuration["Harpo:DatabaseKey:File"]));

    private static string? Nullify(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;

    public bool WantsEncryption => DatabaseKey is not null && !RemoveEncryption;
}

/// <summary>
/// Optional full-file database encryption via SQLCipher. The native library we
/// bundle (e_sqlcipher) opens ordinary SQLite files identically when no key is
/// used, so encryption is opt-in purely through configuration:
///
///   Harpo__DatabaseKey                  encrypt the database with this key (per-site,
///                                       unlike the master key — sites may differ)
///   Harpo__PreviousDatabaseKey          set alongside a new DatabaseKey to rotate keys
///   Harpo__RemoveDatabaseEncryption     "true" + the current key → decrypt back to plain
///
/// At startup <see cref="EnsureEncryptionStateAsync"/> reconciles the file with the
/// configuration: a plaintext database is encrypted in place (via sqlcipher_export),
/// keys are rotated (PRAGMA rekey), or — explicitly only — the file is decrypted.
/// A key mismatch or a missing key for an encrypted file fails fast with a clear error.
///
/// Threat model reminder (see README): this protects copied files, volumes, and
/// backups. An attacker on the live host can read the key from the environment,
/// same as the master key.
/// </summary>
public static class DbEncryption
{
    private const int SqliteFull = 13;

    private static readonly byte[] PlainHeader = "SQLite format 3\0"u8.ToArray();

    /// <summary>Returns the connection string the app should actually use (adds Password when encrypting).</summary>
    public static string ApplyKey(string connectionString, DbEncryptionOptions options)
    {
        if (!options.WantsEncryption)
        {
            return connectionString;
        }
        var builder = new SqliteConnectionStringBuilder(connectionString) { Password = options.DatabaseKey };
        return builder.ToString();
    }

    /// <summary>Reconciles the database file on disk with the configured encryption state.</summary>
    public static async Task EnsureEncryptionStateAsync(string rawConnectionString, DbEncryptionOptions options, ILogger logger)
    {
        var path = new SqliteConnectionStringBuilder(rawConnectionString).DataSource;
        if (string.IsNullOrEmpty(path) || path == ":memory:" || !File.Exists(path))
        {
            if (options.WantsEncryption)
            {
                logger.LogInformation("Database file does not exist yet; it will be created encrypted (SQLCipher).");
            }
            return;
        }

        var isPlaintext = await IsPlaintextAsync(path);

        if (options.DatabaseKey is null)
        {
            if (!isPlaintext)
            {
                throw new InvalidOperationException(
                    $"The database at '{path}' is encrypted, but Harpo:DatabaseKey is not configured. " +
                    "Restore the key to start Harpo. (To permanently remove encryption, set the key plus " +
                    "Harpo:RemoveDatabaseEncryption=true for one start.)");
            }
            return; // plaintext file, no key wanted — nothing to do
        }

        if (isPlaintext)
        {
            if (options.RemoveEncryption)
            {
                logger.LogWarning("Harpo:RemoveDatabaseEncryption is set but the database is already unencrypted; nothing to do.");
                return;
            }
            logger.LogWarning("Encrypting existing database '{Path}' with the configured Harpo:DatabaseKey...", path);
            await ExportAsync(path, sourceKey: null, targetKey: options.DatabaseKey);
            logger.LogWarning("Database encryption complete.");
            return;
        }

        // Encrypted file. Find out which key opens it.
        if (await CanOpenAsync(path, options.DatabaseKey))
        {
            if (options.RemoveEncryption)
            {
                logger.LogWarning("Harpo:RemoveDatabaseEncryption is set — decrypting database '{Path}' back to plaintext...", path);
                await ExportAsync(path, sourceKey: options.DatabaseKey, targetKey: null);
                logger.LogWarning(
                    "Database decryption complete. Remove Harpo:RemoveDatabaseEncryption and Harpo:DatabaseKey from the configuration.");
            }
            return;
        }

        if (options.PreviousDatabaseKey is not null && await CanOpenAsync(path, options.PreviousDatabaseKey))
        {
            logger.LogWarning("Rotating the database encryption key of '{Path}'...", path);
            await RekeyAsync(path, options.PreviousDatabaseKey, options.DatabaseKey);
            logger.LogWarning("Database key rotation complete. Remove Harpo:PreviousDatabaseKey from the configuration.");
            return;
        }

        throw new InvalidOperationException(
            $"The database at '{path}' is encrypted, but the configured Harpo:DatabaseKey does not open it" +
            (options.PreviousDatabaseKey is null
                ? ". If you are rotating keys, set Harpo:PreviousDatabaseKey to the old key."
                : ", and neither does Harpo:PreviousDatabaseKey."));
    }

    /// <summary>
    /// What the file on disk actually is, read from the file rather than taken from
    /// the configuration. Null when there is no file to look at.
    /// </summary>
    public static async Task<bool?> IsEncryptedAsync(string rawConnectionString)
    {
        var path = new SqliteConnectionStringBuilder(rawConnectionString).DataSource;
        if (string.IsNullOrEmpty(path) || path == ":memory:" || !File.Exists(path))
        {
            return null;
        }
        return !await IsPlaintextAsync(path);
    }

    /// <summary>
    /// Says on every start whether the file is encrypted. Without this, a key that
    /// came through blank leaves the site unencrypted with nothing to show for it.
    /// </summary>
    public static async Task LogStateAsync(string rawConnectionString, DbEncryptionOptions options, ILogger logger)
    {
        switch (await IsEncryptedAsync(rawConnectionString))
        {
            case true:
                logger.LogInformation("The database file is encrypted (SQLCipher).");
                break;
            case false when options.KeyLeftBlank:
                logger.LogWarning(
                    "The database file is NOT encrypted: Harpo:DatabaseKey was supplied but is blank, so no key " +
                    "was applied. If you meant to encrypt the file, check the variable or secret it comes from.");
                break;
            case false:
                logger.LogInformation(
                    "The database file is not encrypted ({Reason}). Passwords, 2FA secrets and notes are still " +
                    "encrypted under the master key; entry names, URLs and usernames are readable in the file.",
                    options.RemoveEncryption ? "Harpo:RemoveDatabaseEncryption is set" : "Harpo:DatabaseKey is not set");
                break;
        }
    }

    /// <summary>An unencrypted SQLite file starts with the magic header; SQLCipher files look random.</summary>
    public static async Task<bool> IsPlaintextAsync(string path)
    {
        // Also read while the app runs, so it must not get in the way of SQLite.
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length == 0)
        {
            return true;
        }
        var header = new byte[PlainHeader.Length];
        await stream.ReadExactlyAsync(header.AsMemory(0, (int)Math.Min(header.Length, stream.Length)));
        return header.AsSpan().SequenceEqual(PlainHeader);
    }

    private static async Task<bool> CanOpenAsync(string path, string key)
    {
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Password = key }.ToString();
        try
        {
            await using var connection = new SqliteConnection(cs);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_master";
            await command.ExecuteScalarAsync();
            return true;
        }
        catch (SqliteException)
        {
            return false;
        }
        finally
        {
            SqliteConnection.ClearAllPools();
        }
    }

    /// <summary>
    /// Re-encrypts the whole database into a temp file with sqlcipher_export
    /// (targetKey null → plaintext), then atomically swaps it into place.
    /// </summary>
    private static async Task ExportAsync(string path, string? sourceKey, string? targetKey)
    {
        var tempPath = path + ".recrypt-tmp";
        DeleteWithSidecars(tempPath);

        var sourceCs = new SqliteConnectionStringBuilder { DataSource = path, Password = sourceKey ?? "" }.ToString();
        try
        {
            await using (var connection = new SqliteConnection(sourceCs))
            {
                await connection.OpenAsync();
                await using (var attach = connection.CreateCommand())
                {
                    attach.CommandText = "ATTACH DATABASE $path AS target KEY $key";
                    attach.Parameters.AddWithValue("$path", tempPath);
                    attach.Parameters.AddWithValue("$key", targetKey ?? "");
                    await attach.ExecuteNonQueryAsync();
                }
                await using (var export = connection.CreateCommand())
                {
                    export.CommandText = "SELECT sqlcipher_export('target')";
                    await export.ExecuteScalarAsync();
                }
                await using (var detach = connection.CreateCommand())
                {
                    detach.CommandText = "DETACH DATABASE target";
                    await detach.ExecuteNonQueryAsync();
                }
            }
        }
        catch (Exception ex)
        {
            // The original still holds everything (closing may fold its WAL in, which
            // changes no data). A half-written copy only takes up space, and when
            // decrypting it holds plaintext, so it must not stay.
            SqliteConnection.ClearAllPools();
            DeleteWithSidecars(tempPath);
            if (IsDiskFull(ex))
            {
                throw new InvalidOperationException(DiskFullMessage(path, targetKey is null ? "decrypt" : "encrypt"), ex);
            }
            throw;
        }
        SqliteConnection.ClearAllPools();

        // The old WAL/SHM belong to the old file (and, when encrypting, still hold
        // plaintext pages) — they must not survive the swap.
        File.Delete(path + "-wal");
        File.Delete(path + "-shm");
        File.Move(tempPath, path, overwrite: true);
        File.Delete(tempPath + "-wal");
        File.Delete(tempPath + "-shm");
    }

    private static void DeleteWithSidecars(string path)
    {
        File.Delete(path);
        File.Delete(path + "-wal");
        File.Delete(path + "-shm");
    }

    // sqlcipher_export passes the failure on as a generic error 1, keeping only
    // SQLite's text for it, so the code alone does not catch it.
    private static bool IsDiskFull(Exception ex) =>
        ex is SqliteException sqlite
        && (sqlite.SqliteErrorCode == SqliteFull || sqlite.Message.Contains("database or disk is full", StringComparison.Ordinal));

    private static string DiskFullMessage(string path, string verb)
    {
        var bytes = new FileInfo(path).Length + (File.Exists(path + "-wal") ? new FileInfo(path + "-wal").Length : 0);
        var megabytes = Math.Ceiling(bytes / (1024d * 1024d));
        return $"There is not enough free disk space to {verb} the database at '{path}'. Harpo writes a second copy " +
            $"of the file first, which needs about {megabytes:0} MB free on that volume. Nothing has been lost and " +
            "the file is as it was. Free up some space and start Harpo again.";
    }

    private static async Task RekeyAsync(string path, string oldKey, string newKey)
    {
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Password = oldKey }.ToString();
        await using (var connection = new SqliteConnection(cs))
        {
            await connection.OpenAsync();
            // PRAGMA does not take parameters; quote the key safely via SQL itself.
            await using var quote = connection.CreateCommand();
            quote.CommandText = "SELECT quote($key)";
            quote.Parameters.AddWithValue("$key", newKey);
            var quoted = (string)(await quote.ExecuteScalarAsync())!;
            await using var rekey = connection.CreateCommand();
            rekey.CommandText = "PRAGMA rekey = " + quoted;
            await rekey.ExecuteNonQueryAsync();
        }
        SqliteConnection.ClearAllPools();
    }
}

/// <summary>Lets the Administration page show what the database file is.</summary>
public sealed class DbEncryptionStatus
{
    private readonly string _rawConnectionString;

    public DbEncryptionStatus(string rawConnectionString)
    {
        _rawConnectionString = rawConnectionString;
    }

    public Task<bool?> IsEncryptedAsync() => DbEncryption.IsEncryptedAsync(_rawConnectionString);
}
