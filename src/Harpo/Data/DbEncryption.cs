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

    // appsettings.json ships a blank key, so a blank value from there means nothing.
    // From anywhere else it is a mistake: "${HARPO_DATABASE_KEY}" with the variable
    // unset, or an empty secret file.
    private static bool IsKeyLeftBlank(IConfiguration configuration) =>
        string.IsNullOrWhiteSpace(configuration["Harpo:DatabaseKey"])
        && configuration is IConfigurationRoot root
        && root.Providers.Any(p =>
            p is not FileConfigurationProvider { Source.Path: "appsettings.json" }
            && p.TryGet("Harpo:DatabaseKey", out _));

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
    private const int SqliteError = 1;
    private const int SqliteIoError = 10;
    private const int SqliteFull = 13;
    private const int SqliteCantOpen = 14;
    private const string TempSuffix = ".recrypt-tmp";

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

        // A copy left by an interrupted run is never used again, and after a decrypt
        // it holds plaintext, so it goes on every start whatever else happens below.
        if (File.Exists(path + TempSuffix))
        {
            logger.LogWarning("Removing the partial database copy an interrupted run left at '{Path}'.", path + TempSuffix);
        }
        RemoveTemp(path + TempSuffix, logger);

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
            await ExportAsync(path, sourceKey: null, targetKey: options.DatabaseKey, logger);
            logger.LogWarning("Database encryption complete.");
            return;
        }

        // Encrypted file. Find out which key opens it.
        if (await CanOpenAsync(path, options.DatabaseKey))
        {
            if (options.RemoveEncryption)
            {
                logger.LogWarning("Harpo:RemoveDatabaseEncryption is set — decrypting database '{Path}' back to plaintext...", path);
                await ExportAsync(path, sourceKey: options.DatabaseKey, targetKey: null, logger);
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
    /// the configuration. Null when there is no file to look at. Not for use while
    /// connections are open: see <see cref="IsPlaintextAsync"/>.
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
    /// Reads the file's state once, for the Administration page, and says on every
    /// start what it is. Without this, a key that came through blank leaves the site
    /// unencrypted with nothing to show for it.
    /// </summary>
    public static async Task ReportStateAsync(
        string rawConnectionString, DbEncryptionOptions options, DbEncryptionStatus status, ILogger logger)
    {
        SqliteConnection.ClearAllPools();
        status.IsEncrypted = await IsEncryptedAsync(rawConnectionString);
        switch (status.IsEncrypted)
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
                    "encrypted under the master key; the rest of the file, such as entry names, URLs, usernames, " +
                    "group membership and the audit log, is readable.",
                    options.RemoveEncryption ? "Harpo:RemoveDatabaseEncryption is set" : "Harpo:DatabaseKey is not set");
                break;
            default:
                logger.LogWarning(
                    "Could not tell whether the database file is encrypted: no file found at the configured " +
                    "Data Source '{Path}'.", new SqliteConnectionStringBuilder(rawConnectionString).DataSource);
                break;
        }
    }

    /// <summary>
    /// An unencrypted SQLite file starts with the magic header; SQLCipher files look
    /// random. Only call this with no connections open: closing any handle on a file
    /// cancels every POSIX lock the process holds on it, SQLite's included, and without
    /// its lock another process opening the database can delete a WAL still in use.
    /// </summary>
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
    private static async Task ExportAsync(string path, string? sourceKey, string? targetKey, ILogger logger)
    {
        var tempPath = path + TempSuffix;
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
            SqliteConnection.ClearAllPools();

            // The old WAL/SHM belong to the old file (and, when encrypting, still hold
            // plaintext pages) — they must not survive the swap.
            File.Delete(path + "-wal");
            File.Delete(path + "-shm");
            File.Move(tempPath, path, overwrite: true);
        }
        catch (Exception ex)
        {
            // The original still holds everything (closing may fold its WAL in, which
            // changes no data). A half-written copy only takes up space, and when
            // decrypting it holds plaintext, so it must not stay.
            SqliteConnection.ClearAllPools();
            RemoveTemp(tempPath, logger);
            if (WriteFailureMessage(ex, path, targetKey is null ? "decrypt" : "encrypt") is { } message)
            {
                throw new InvalidOperationException(message, ex);
            }
            throw;
        }
        RemoveTemp(tempPath, logger);
    }

    private static void RemoveTemp(string tempPath, ILogger logger)
    {
        foreach (var file in new[] { tempPath, tempPath + "-journal", tempPath + "-wal", tempPath + "-shm" })
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Logged, not thrown: this must not hide why the copy failed.
                logger.LogWarning(
                    "Could not remove '{File}' ({Error}). Delete it by hand: it is a partial copy of the database " +
                    "and may hold plaintext.", file, ex.Message);
            }
        }
    }

    /// <summary>
    /// What to tell the operator when SQLite could not write what an encryption
    /// change needs, or null for any other failure (a damaged file, say).
    /// </summary>
    internal static string? WriteFailureMessage(Exception ex, string path, string action)
    {
        if (ex is not SqliteException sqlite)
        {
            return null;
        }
        var code = sqlite.SqliteErrorCode & 0xFF;

        // sqlcipher_export passes a failure on as a generic error 1, keeping only
        // SQLite's text for it. Only then does the text count: ATTACH says "unable to
        // open database" whatever went wrong, a damaged file included.
        bool Says(string text) => code == SqliteError && sqlite.Message.Contains(text, StringComparison.Ordinal);

        if (code == SqliteFull || Says("database or disk is full"))
        {
            return $"There is not enough free disk space to {action} the database at '{path}'. This needs about " +
                $"{MegabytesNeeded(path)} MB free on that volume. Your data has not been changed. Free up some " +
                "space and start Harpo again.";
        }
        if (code is SqliteIoError or SqliteCantOpen || Says("disk I/O error") || Says("unable to open database"))
        {
            return $"Harpo could not write to the volume holding the database at '{path}' to {action} it " +
                $"({sqlite.Message}). Your data has not been changed. Check the free space, quotas and permissions " +
                "on that volume and start Harpo again.";
        }
        return null;
    }

    private static string MegabytesNeeded(string path)
    {
        var bytes = new FileInfo(path).Length + (File.Exists(path + "-wal") ? new FileInfo(path + "-wal").Length : 0);
        return Math.Ceiling(bytes / (1024d * 1024d)).ToString("0");
    }

    private static async Task RekeyAsync(string path, string oldKey, string newKey)
    {
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Password = oldKey }.ToString();
        try
        {
            await using var connection = new SqliteConnection(cs);
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
        catch (Exception ex) when (WriteFailureMessage(ex, path, "rotate the key of") is { } message)
        {
            throw new InvalidOperationException(message, ex);
        }
        SqliteConnection.ClearAllPools();

        // On a full disk PRAGMA rekey reports success and leaves the file under the
        // old key. Saying it worked would have the operator discard the only key that
        // opens the file, so only reopening it counts.
        if (await CanOpenAsync(path, newKey))
        {
            return;
        }
        throw new InvalidOperationException(await CanOpenAsync(path, oldKey)
            ? $"Rotating the key of the database at '{path}' did not take effect: it still opens only with " +
              $"Harpo:PreviousDatabaseKey. The usual cause is too little free disk space (this needs about " +
              $"{MegabytesNeeded(path)} MB on that volume). Keep both keys configured, free up some space and start Harpo again."
            : $"After rotating its key, the database at '{path}' opens with neither Harpo:DatabaseKey nor " +
              "Harpo:PreviousDatabaseKey. Keep both keys, and check the volume and your backups.");
    }
}

/// <summary>
/// What the database file was found to be at startup, for the Administration page.
/// Held rather than read when asked: see <see cref="DbEncryption.IsPlaintextAsync"/>.
/// </summary>
public sealed class DbEncryptionStatus
{
    /// <summary>Null when there was no file to look at.</summary>
    public bool? IsEncrypted { get; set; }
}
