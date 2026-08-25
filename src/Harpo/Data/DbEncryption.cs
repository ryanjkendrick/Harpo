using Microsoft.Data.Sqlite;

namespace Harpo.Data;

public sealed record DbEncryptionOptions(
    string? DatabaseKey,
    string? PreviousDatabaseKey,
    bool RemoveEncryption)
{
    public static DbEncryptionOptions FromConfiguration(IConfiguration configuration) => new(
        Nullify(configuration["Harpo:DatabaseKey"]),
        Nullify(configuration["Harpo:PreviousDatabaseKey"]),
        configuration.GetValue("Harpo:RemoveDatabaseEncryption", false));

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

    /// <summary>An unencrypted SQLite file starts with the magic header; SQLCipher files look random.</summary>
    public static async Task<bool> IsPlaintextAsync(string path)
    {
        await using var stream = File.OpenRead(path);
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
        foreach (var stale in new[] { tempPath, tempPath + "-wal", tempPath + "-shm" })
        {
            File.Delete(stale);
        }

        var sourceCs = new SqliteConnectionStringBuilder { DataSource = path, Password = sourceKey ?? "" }.ToString();
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
        SqliteConnection.ClearAllPools();

        // The old WAL/SHM belong to the old file (and, when encrypting, still hold
        // plaintext pages) — they must not survive the swap.
        File.Delete(path + "-wal");
        File.Delete(path + "-shm");
        File.Move(tempPath, path, overwrite: true);
        File.Delete(tempPath + "-wal");
        File.Delete(tempPath + "-shm");
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
