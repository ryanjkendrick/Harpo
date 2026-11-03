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
    // unset, an empty secret file, or a blank path to one.
    private static bool IsKeyLeftBlank(IConfiguration configuration) =>
        string.IsNullOrWhiteSpace(configuration["Harpo:DatabaseKey"])
        && configuration is IConfigurationRoot root
        && root.Providers.Any(p =>
            p is not FileConfigurationProvider { Source.Path: "appsettings.json" }
            && (p.TryGet("Harpo:DatabaseKey", out _) || p.TryGet("Harpo:DatabaseKey" + FileConfigurationSecrets.Suffix, out _)));

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
    private const int SqliteBusy = 5;
    private const int SqliteLocked = 6;
    private const int SqliteReadOnly = 8;
    private const int SqliteIoError = 10;
    private const int SqliteCorrupt = 11;
    private const int SqliteFull = 13;
    private const int SqliteCantOpen = 14;
    private const int SqliteNotADb = 26;
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
        var isFile = !string.IsNullOrEmpty(path) && path != ":memory:";

        // A copy left by an interrupted run is never used again, and after a decrypt
        // it holds plaintext, so it goes on every start whatever else happens below.
        if (isFile)
        {
            if (File.Exists(path + TempSuffix))
            {
                logger.LogWarning("Removing the partial database copy an interrupted run left at '{Path}'.", path + TempSuffix);
            }
            RemoveTemp(path + TempSuffix, logger);
        }

        if (!isFile || !File.Exists(path))
        {
            if (options.WantsEncryption)
            {
                logger.LogInformation("Database file does not exist yet; it will be created encrypted (SQLCipher).");
            }
            return;
        }

        bool isPlaintext;
        try
        {
            isPlaintext = await IsPlaintextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Harpo could not read the database file at '{path}' ({ex.Message}). Your data has not been changed. " +
                "Check its permissions, and that nothing else is using it, and start Harpo again.", ex);
        }

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
            else if (options.PreviousDatabaseKey is not null)
            {
                // Says so after a rotation whose own log line was lost to a kill, too.
                logger.LogWarning(
                    "The database opens with Harpo:DatabaseKey, so Harpo:PreviousDatabaseKey is no longer needed. Remove it from the configuration.");
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
                : ", and neither does Harpo:PreviousDatabaseKey.") +
            " If the key is right, the file may be damaged: a damaged first page looks the same as a wrong key.");
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

    /// <summary>
    /// Whether this key opens the file. False only when SQLite says the key does not
    /// fit: told "wrong key" about a full or read-only volume, an operator goes looking
    /// for old keys and backups when nothing is wrong with either.
    /// </summary>
    private static async Task<bool> CanOpenAsync(string path, string key)
    {
        // Read-write, because only a writer can roll back a journal an interrupted run
        // left. That is safe to try with a wrong key: rollback restores the journal's
        // raw pages without decrypting them. SQLite falls back to read-only by itself
        // when the file cannot be written.
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Password = key, DefaultTimeout = 5 }.ToString();
        try
        {
            await using var connection = new SqliteConnection(cs);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_master";
            await command.ExecuteScalarAsync();
            return true;
        }
        catch (SqliteException ex) when ((ex.SqliteErrorCode & 0xFF) == SqliteNotADb)
        {
            return false;
        }
        catch (SqliteException ex) when ((ex.SqliteErrorCode & 0xFF) is SqliteBusy or SqliteLocked)
        {
            throw InUse(path, "check its key", ex);
        }
        catch (SqliteException ex)
        {
            throw new InvalidOperationException(
                $"Harpo could not open the database at '{path}' to check its key ({ex.Message}), so this says nothing " +
                "about the key itself. Check the free space, quotas and permissions on that volume and start Harpo " +
                "again. If those are fine, the file may be damaged.", ex);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
        }
    }

    /// <summary>
    /// Re-encrypts the whole database into a temp file with sqlcipher_export
    /// (targetKey null → plaintext), then atomically swaps it into place. The WAL has
    /// to go before the swap, or SQLite would apply it to the new file, so everything
    /// in it must be in the main file first. <paramref name="swap"/> is for tests.
    /// </summary>
    internal static async Task ExportAsync(
        string path, string? sourceKey, string? targetKey, ILogger logger, Action<string, string>? swap = null)
    {
        var tempPath = path + TempSuffix;
        var action = targetKey is null ? "decrypt" : "encrypt";
        var copyStarted = false;
        var sourceCs = new SqliteConnectionStringBuilder { DataSource = path, Password = sourceKey ?? "" }.ToString();
        try
        {
            long rows;
            // A short wait: nothing else should have the file open at startup.
            await using (var connection = await OpenExclusiveAsync(sourceCs, waitSeconds: 5))
            {
                await FoldWalAsync(connection, path, action);
                CreateCopyFile(path, tempPath);
                copyStarted = true;
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
                rows = await RequireSameRowsAsync(connection, path, action);
                await using (var detach = connection.CreateCommand())
                {
                    detach.CommandText = "DETACH DATABASE target";
                    await detach.ExecuteNonQueryAsync();
                }
            }
            SqliteConnection.ClearAllPools();

            // The lock went with the connection, so what was checked is looked at again:
            // anything else starting now could have written, or replaced the copy.
            if (new FileInfo(path + "-wal") is { Exists: true, Length: > 0 })
            {
                throw InUse(path, $"{action} it");
            }
            await RequireRowsAsync(tempPath, targetKey ?? "", rows, path, action);
            MatchCopyMode(path, tempPath);

            // The old WAL/SHM belong to the old file (and, when encrypting, still hold
            // plaintext pages) — they must not survive the swap.
            File.Delete(path + "-wal");
            File.Delete(path + "-shm");
            try
            {
                (swap ?? ((from, to) => File.Move(from, to, overwrite: true)))(tempPath, path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException(
                    $"Harpo could not replace the database file at '{path}' with its {action}ed copy ({ex.Message}). " +
                    "Your data has not been changed. The file's folder has to be writable and mounted as a folder: a " +
                    "file mounted on its own cannot be replaced. Fix that and start Harpo again.", ex);
            }
        }
        catch (Exception ex)
        {
            // The original holds everything: FoldWalAsync saw to that before anything
            // here could fail after the WAL went. A half-written copy only takes up
            // space, and when decrypting it holds plaintext, so it must not stay. If the
            // lock was refused, any copy there is the other process's.
            SqliteConnection.ClearAllPools();
            if (copyStarted)
            {
                RemoveTemp(tempPath, logger);
            }
            if (WriteFailureMessage(ex, path, action) is { } message)
            {
                throw new InvalidOperationException(message, ex);
            }
            throw;
        }
        RemoveTemp(tempPath, logger);
    }

    /// <summary>
    /// Opens the file with an exclusive lock, held until the connection is closed, or
    /// fails with SQLITE_BUSY if anything else has it open, even idly: a running site in
    /// WAL mode always holds a shared lock on it. Without this, one Harpo converting the
    /// file leaves another running on the deleted original, where everything it writes
    /// is lost without an error.
    /// </summary>
    internal static async Task<SqliteConnection> OpenExclusiveAsync(string connectionString, int waitSeconds)
    {
        // The mode only takes the lock if it is set before the first read of the file.
        // Opening with a password reads it straight away, so the key has to come after.
        var builder = new SqliteConnectionStringBuilder(connectionString) { Pooling = false, DefaultTimeout = waitSeconds };
        var key = builder.Password;
        builder.Password = "";
        var connection = new SqliteConnection(builder.ToString());
        try
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA locking_mode = EXCLUSIVE";
            await command.ExecuteNonQueryAsync();
            if (key.Length > 0)
            {
                // PRAGMA does not take parameters; quote the key safely via SQL itself.
                command.CommandText = "SELECT quote($key)";
                command.Parameters.AddWithValue("$key", key);
                var quoted = (string)(await command.ExecuteScalarAsync())!;
                command.Parameters.Clear();
                command.CommandText = "PRAGMA key = " + quoted;
                await command.ExecuteNonQueryAsync();
            }
            command.CommandText = "SELECT count(*) FROM sqlite_master";
            await command.ExecuteScalarAsync();
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Moves everything in the WAL into the main file and empties the WAL, or throws.
    /// Closing the last connection tries this too, but says nothing when it fails.
    /// </summary>
    private static async Task FoldWalAsync(SqliteConnection connection, string path, string action)
    {
        await using var checkpoint = connection.CreateCommand();
        checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
        await using var result = await checkpoint.ExecuteReaderAsync();
        if (await result.ReadAsync() && result.GetInt32(0) != 0)
        {
            throw InUse(path, $"{action} it");
        }
    }

    private static InvalidOperationException InUse(string path, string what, Exception? inner = null) => new(
        InUseMessage(path, what), inner);

    private static string InUseMessage(string path, string what) =>
        $"The database at '{path}' is in use by something else, so Harpo cannot safely {what}. Your data has not " +
        "been changed. Stop anything else using the file (only one Harpo may use a database file) and start Harpo again.";

    /// <summary>Compares every table in the attached copy with the original; returns how many rows there are.</summary>
    internal static async Task<long> RequireSameRowsAsync(SqliteConnection connection, string path, string action)
    {
        var tables = new List<string>();
        await using (var list = connection.CreateCommand())
        {
            list.CommandText = "SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
            await using var reader = await list.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                tables.Add(reader.GetString(0));
            }
        }
        var rows = 0L;
        foreach (var table in tables)
        {
            var quoted = Quote(table);
            await using var count = connection.CreateCommand();
            count.CommandText = $"SELECT (SELECT count(*) FROM main.{quoted}), (SELECT count(*) FROM target.{quoted})";
            await using var reader = await count.ExecuteReaderAsync();
            await reader.ReadAsync();
            if (reader.GetInt64(0) != reader.GetInt64(1))
            {
                throw new InvalidOperationException(
                    $"The copy made to {action} the database at '{path}' does not match it (table {table}). " +
                    "Your data has not been changed.");
            }
            rows += reader.GetInt64(0);
        }
        return rows;
    }

    /// <summary>Reopens the finished copy, which must still hold as many rows as were compared.</summary>
    internal static async Task RequireRowsAsync(string tempPath, string key, long rows, string path, string action)
    {
        var cs = new SqliteConnectionStringBuilder { DataSource = tempPath, Mode = SqliteOpenMode.ReadWrite, Password = key }.ToString();
        var found = 0L;
        await using (var connection = new SqliteConnection(cs))
        {
            await connection.OpenAsync();
            var tables = new List<string>();
            await using (var list = connection.CreateCommand())
            {
                list.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
                await using var reader = await list.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    tables.Add(reader.GetString(0));
                }
            }
            foreach (var table in tables)
            {
                await using var count = connection.CreateCommand();
                count.CommandText = $"SELECT count(*) FROM {Quote(table)}";
                found += Convert.ToInt64(await count.ExecuteScalarAsync());
            }
        }
        SqliteConnection.ClearAllPools();
        if (found != rows)
        {
            throw new InvalidOperationException(
                $"The copy made to {action} the database at '{path}' does not hold what it should ({found} rows, not {rows}). " +
                "Your data has not been changed. Make sure nothing else is using the file and start Harpo again.");
        }
    }

    private static string Quote(string name) => "\"" + name.Replace("\"", "\"\"") + "\"";

    /// <summary>
    /// The copy replaces the original, so it must be no easier to read: a file kept
    /// private, once decrypted, would otherwise end up world-readable. Made before
    /// SQLite writes anything to it, with write access for now in case the original
    /// has none.
    /// </summary>
    private static void CreateCopyFile(string path, string tempPath)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        using var stream = new FileStream(tempPath, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = File.GetUnixFileMode(path) | UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
    }

    private static void MatchCopyMode(string path, string tempPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(tempPath, File.GetUnixFileMode(path));
        }
    }

    private static void RemoveTemp(string tempPath, ILogger logger)
    {
        foreach (var file in new[] { tempPath, tempPath + "-journal", tempPath + "-wal", tempPath + "-shm" })
        {
            try
            {
                File.Delete(file);
            }
            catch (DirectoryNotFoundException)
            {
                // A new site whose folder does not exist yet: nothing to remove.
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
    /// What to tell the operator when an encryption change could not write what it
    /// needs, or null for any other failure (a damaged file, say).
    /// </summary>
    internal static string? WriteFailureMessage(Exception ex, string path, string action)
    {
        if (ex is IOException or UnauthorizedAccessException)
        {
            return VolumeMessage(ex.Message, path, action);
        }
        if (ex is not SqliteException sqlite)
        {
            return null;
        }
        var code = sqlite.SqliteErrorCode & 0xFF;

        // sqlcipher_export passes a failure on as a generic error 1, keeping only
        // SQLite's text for it. Only then does the text count: ATTACH says "unable to
        // open database" whatever went wrong, a damaged file included.
        bool Says(string text) => code == SqliteError && sqlite.Message.Contains(text, StringComparison.Ordinal);

        if (code is SqliteBusy or SqliteLocked || Says("database is locked"))
        {
            return InUseMessage(path, $"{action} it");
        }
        if (code == SqliteFull || Says("database or disk is full"))
        {
            return $"There is not enough free disk space to {action} the database at '{path}'. This needs at least " +
                $"{MegabytesNeeded(path)} MB free on that volume, and up to twice that if entries hold a lot of text. " +
                "Your data has not been changed. Free up some space and start Harpo again.";
        }
        if (code is SqliteReadOnly or SqliteIoError or SqliteCantOpen
            || Says("disk I/O error") || Says("unable to open database") || Says("readonly database"))
        {
            return VolumeMessage(sqlite.Message, path, action);
        }
        return null;
    }

    private static string VolumeMessage(string error, string path, string action) =>
        $"Harpo could not write to the volume holding the database at '{path}' to {action} it " +
        $"({error}). Your data has not been changed. Check the free space, quotas and permissions " +
        "on that volume and start Harpo again.";

    /// <summary>
    /// A full copy of the file and its WAL, plus what encrypting usually adds, and some
    /// margin. A lower bound: the 80 bytes encrypting reserves on each page can push
    /// large rows onto more pages, and how many depends on the rows.
    /// </summary>
    private static string MegabytesNeeded(string path)
    {
        var bytes = new FileInfo(path).Length + (File.Exists(path + "-wal") ? new FileInfo(path + "-wal").Length : 0);
        return (Math.Ceiling(bytes * 1.05 / (1024d * 1024d)) + 1).ToString("0");
    }

    private static async Task RekeyAsync(string path, string oldKey, string newKey)
    {
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Password = oldKey }.ToString();
        try
        {
            await using var connection = await OpenExclusiveAsync(cs, waitSeconds: 5);
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
        bool opensWithNew, opensWithOld = false, damaged = false;
        try
        {
            opensWithNew = await CanOpenAsync(path, newKey);
            opensWithOld = !opensWithNew && await CanOpenAsync(path, oldKey);
            damaged = opensWithOld && await IsDamagedAsync(path, oldKey);
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidOperationException(
                $"Could not confirm that rotating the key of the database at '{path}' took effect ({ex.InnerException?.Message}). " +
                "Keep both keys configured: Harpo works out on the next start which one opens the file. Check the " +
                "free space, quotas and permissions on that volume and start Harpo again.", ex);
        }
        if (opensWithNew)
        {
            return;
        }
        if (damaged)
        {
            throw new InvalidOperationException(
                $"Rotating the key of the database at '{path}' did not take effect, because the file is damaged: SQLite's " +
                "integrity check fails. It still opens with Harpo:PreviousDatabaseKey, so keep both keys configured. " +
                "Freeing disk space will not help. Restore from a backup, or export what you can first.");
        }
        throw new InvalidOperationException(opensWithOld
            ? $"Rotating the key of the database at '{path}' did not take effect: it still opens only with " +
              $"Harpo:PreviousDatabaseKey. The usual cause is too little free disk space (this needs at least " +
              $"{MegabytesNeeded(path)} MB on that volume). Keep both keys configured, free up some space and start Harpo again."
            : $"After rotating its key, the database at '{path}' opens with neither Harpo:DatabaseKey nor " +
              "Harpo:PreviousDatabaseKey. Keep both keys, and check the volume and your backups.");
    }

    private static async Task<bool> IsDamagedAsync(string path, string key)
    {
        var cs = new SqliteConnectionStringBuilder { DataSource = path, Password = key }.ToString();
        try
        {
            await using var connection = new SqliteConnection(cs);
            await connection.OpenAsync();
            await using var check = connection.CreateCommand();
            check.CommandText = "PRAGMA integrity_check(1)";
            return (string?)await check.ExecuteScalarAsync() != "ok";
        }
        catch (SqliteException ex) when ((ex.SqliteErrorCode & 0xFF) == SqliteCorrupt)
        {
            return true;
        }
        finally
        {
            SqliteConnection.ClearAllPools();
        }
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
