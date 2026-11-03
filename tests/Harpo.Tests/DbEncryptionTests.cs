using Harpo.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// Exercises the optional SQLCipher full-file encryption lifecycle against real
/// temp files: fresh-encrypted creation, in-place encryption of an existing
/// plaintext database, fail-fast on wrong/missing keys, key rotation, and
/// explicit decryption.
/// </summary>
public class DbEncryptionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("harpo-dbenc-").FullName;

    private string DbPath => Path.Combine(_dir, "test.db");
    private string RawCs => new SqliteConnectionStringBuilder { DataSource = DbPath }.ToString();

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private static HarpoDbContext CreateContext(string connectionString)
    {
        var options = new DbContextOptionsBuilder<HarpoDbContext>().UseSqlite(connectionString).Options;
        return new HarpoDbContext(options, new ManualTime(), Options.Create(new SiteOptions { SiteId = "enc-test" }));
    }

    private static async Task SeedAsync(string connectionString)
    {
        await using var db = CreateContext(connectionString);
        await db.Database.EnsureCreatedAsync();
        db.Groups.Add(new Group { Id = Guid.NewGuid(), Name = "Secret Group" });
        await db.SaveChangesAsync();
        SqliteConnection.ClearAllPools();
    }

    private static async Task<int> CountGroupsAsync(string connectionString)
    {
        await using var db = CreateContext(connectionString);
        var count = await db.Groups.CountAsync();
        SqliteConnection.ClearAllPools();
        return count;
    }

    private async Task<DbEncryptionOptions> EncryptedSeedAsync(string key, bool wal = true)
    {
        await SeedAsync(RawCs);
        var options = new DbEncryptionOptions(key, null, false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);
        if (wal)
        {
            // The export leaves the file in DELETE mode; DbInitializer then sets WAL, so
            // a running site, and so any later rotation or decrypt, always starts from WAL.
            await ExecuteAsync(DbEncryption.ApplyKey(RawCs, options), "PRAGMA journal_mode=WAL");
        }
        return options;
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
        await connection.CloseAsync();
        SqliteConnection.ClearAllPools();
    }

    /// <summary>
    /// Leaves test.db as a killed site does: committed rows that are only in the WAL,
    /// with nothing holding the file. Returns how many groups it holds.
    /// </summary>
    private async Task<int> KilledWithRowsInWalAsync(string? key)
    {
        var live = Path.Combine(_dir, "live.db");
        var liveCs = new SqliteConnectionStringBuilder { DataSource = live, Password = key ?? "" }.ToString();
        await SeedAsync(liveCs);
        await ExecuteAsync(liveCs, "PRAGMA journal_mode=WAL");

        // Held open so that the last close cannot fold the WAL in.
        await using (var holder = new SqliteConnection(liveCs))
        {
            await holder.OpenAsync();
            await using (var db = CreateContext(liveCs))
            {
                db.Groups.AddRange(Enumerable.Range(0, 300).Select(i => new Group { Id = Guid.NewGuid(), Name = $"Group {i}" }));
                await db.SaveChangesAsync();
            }
            File.Copy(live, DbPath);
            File.Copy(live + "-wal", DbPath + "-wal");
            File.Copy(live + "-shm", DbPath + "-shm");
        }
        SqliteConnection.ClearAllPools();
        Assert.True(new FileInfo(DbPath + "-wal").Length > 0);
        return 301;
    }

    /// <summary>Leaves test.db as an interrupted write does: encrypted, in DELETE mode, with a hot journal.</summary>
    private async Task KilledWithHotJournalAsync(string key)
    {
        var live = Path.Combine(_dir, "live.db");
        var liveCs = new SqliteConnectionStringBuilder { DataSource = live, Password = key }.ToString();
        await SeedAsync(liveCs);
        await ExecuteAsync(liveCs, "PRAGMA journal_mode=DELETE");
        await ExecuteAsync(liveCs, "CREATE TABLE Filler (x)");

        // Copied before the write: .NET cannot read the file while SQLite holds it, and
        // the journal is hot whichever of its pages had reached the file.
        File.Copy(live, DbPath);
        await using (var writer = new SqliteConnection(liveCs))
        {
            await writer.OpenAsync();
            await using var command = writer.CreateCommand();
            // A small cache makes SQLite spill to the file, and sync the journal first.
            command.CommandText = """
                PRAGMA cache_size = 2;
                BEGIN IMMEDIATE;
                WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500)
                INSERT INTO Filler SELECT randomblob(1000) FROM n;
                """;
            await command.ExecuteNonQueryAsync();
            File.Copy(live + "-journal", DbPath + "-journal");
        }
        SqliteConnection.ClearAllPools();
        Assert.True(new FileInfo(DbPath + "-journal").Length > 0);
    }

    [Fact]
    public async Task Fresh_database_created_with_key_is_encrypted_on_disk()
    {
        var options = new DbEncryptionOptions("key-1", null, false);
        var keyedCs = DbEncryption.ApplyKey(RawCs, options);
        Assert.NotEqual(RawCs, keyedCs);

        await SeedAsync(keyedCs);

        Assert.False(await DbEncryption.IsPlaintextAsync(DbPath));
        Assert.Equal(1, await CountGroupsAsync(keyedCs));
    }

    [Fact]
    public async Task Existing_plaintext_database_is_encrypted_in_place()
    {
        await SeedAsync(RawCs);
        Assert.True(await DbEncryption.IsPlaintextAsync(DbPath));

        var options = new DbEncryptionOptions("key-1", null, false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);

        Assert.False(await DbEncryption.IsPlaintextAsync(DbPath));
        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
        await Assert.ThrowsAnyAsync<SqliteException>(() => CountGroupsAsync(RawCs));
        Assert.False(File.Exists(DbPath + ".recrypt-tmp"));
    }

    [Fact]
    public async Task Missing_key_on_encrypted_database_fails_fast()
    {
        await EncryptedSeedAsync("key-1");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions(null, null, false), NullLogger.Instance));
        Assert.Contains("Harpo:DatabaseKey is not configured", ex.Message);
    }

    [Fact]
    public async Task Wrong_key_fails_fast_with_rotation_hint()
    {
        await EncryptedSeedAsync("key-1");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("wrong", null, false), NullLogger.Instance));
        Assert.Contains("PreviousDatabaseKey", ex.Message);
    }

    [Fact]
    public async Task Key_rotation_via_previous_key()
    {
        await EncryptedSeedAsync("key-1");

        var rotated = new DbEncryptionOptions("key-2", "key-1", false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, rotated, NullLogger.Instance);

        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, rotated)));
        await Assert.ThrowsAnyAsync<SqliteException>(() => CountGroupsAsync(
            DbEncryption.ApplyKey(RawCs, new DbEncryptionOptions("key-1", null, false))));
    }

    [Fact]
    public async Task Explicit_decrypt_flag_restores_plaintext()
    {
        await EncryptedSeedAsync("key-1");

        var removal = new DbEncryptionOptions("key-1", null, true);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, removal, NullLogger.Instance);

        Assert.True(await DbEncryption.IsPlaintextAsync(DbPath));
        // With RemoveEncryption set, ApplyKey must not add a password.
        Assert.Equal(RawCs, DbEncryption.ApplyKey(RawCs, removal));
        Assert.Equal(1, await CountGroupsAsync(RawCs));
    }

    [Fact]
    public async Task Idempotent_when_state_already_matches()
    {
        var options = await EncryptedSeedAsync("key-1");

        // Running again with the same key is a no-op, not an error.
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);
        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
    }

    [Fact]
    public async Task Reports_what_the_file_on_disk_is()
    {
        Assert.Null(await DbEncryption.IsEncryptedAsync(RawCs)); // no file yet
        Assert.Null(await DbEncryption.IsEncryptedAsync("Data Source=:memory:"));

        await SeedAsync(RawCs);
        Assert.False(await DbEncryption.IsEncryptedAsync(RawCs));

        // Asked with the raw connection string, as the app does: the key plays no part.
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-1", null, false), NullLogger.Instance);
        Assert.True(await DbEncryption.IsEncryptedAsync(RawCs));
    }

    [Fact]
    public async Task Start_log_says_whether_the_file_is_encrypted()
    {
        var unknown = new RecordingLogger();
        var status = new DbEncryptionStatus();
        await DbEncryption.ReportStateAsync(RawCs, new DbEncryptionOptions(null, null, false), status, unknown);
        var line = Assert.Single(unknown.Lines);
        Assert.Equal(LogLevel.Warning, line.Level);
        Assert.Contains("Could not tell", line.Message);
        Assert.Null(status.IsEncrypted);

        await SeedAsync(RawCs);
        var plain = new RecordingLogger();
        await DbEncryption.ReportStateAsync(RawCs, new DbEncryptionOptions(null, null, false), status, plain);
        line = Assert.Single(plain.Lines);
        Assert.Equal(LogLevel.Information, line.Level);
        Assert.Contains("not encrypted (Harpo:DatabaseKey is not set)", line.Message);
        Assert.False(status.IsEncrypted);

        var blank = new RecordingLogger();
        await DbEncryption.ReportStateAsync(RawCs, new DbEncryptionOptions(null, null, false, KeyLeftBlank: true), status, blank);
        line = Assert.Single(blank.Lines);
        Assert.Equal(LogLevel.Warning, line.Level);
        Assert.Contains("NOT encrypted", line.Message);
        Assert.Contains("blank", line.Message);

        var options = new DbEncryptionOptions("key-1", null, false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);
        var encrypted = new RecordingLogger();
        await DbEncryption.ReportStateAsync(RawCs, options, status, encrypted);
        line = Assert.Single(encrypted.Lines);
        Assert.Equal(LogLevel.Information, line.Level);
        Assert.Contains("is encrypted", line.Message);
        Assert.True(status.IsEncrypted);
    }

    [Fact]
    public async Task The_file_is_only_read_with_every_connection_closed()
    {
        // Reading it with one open would cancel SQLite's locks on it. A pooled connection
        // keeps the WAL in place, and closing the last one removes it, which shows here
        // that the pool really was emptied before the read.
        await SeedAsync(RawCs);
        await ExecuteAsync(RawCs, "PRAGMA journal_mode=WAL");
        await CountGroupsWithoutClearingAsync();
        Assert.True(File.Exists(DbPath + "-wal"));

        await DbEncryption.ReportStateAsync(RawCs, new DbEncryptionOptions(null, null, false), new DbEncryptionStatus(), NullLogger.Instance);

        Assert.False(File.Exists(DbPath + "-wal"));
    }

    private async Task CountGroupsWithoutClearingAsync()
    {
        await using var db = CreateContext(RawCs);
        await db.Groups.CountAsync();
    }

    [Fact]
    public void A_key_counts_as_left_blank_only_when_someone_supplied_it()
    {
        // The blank that appsettings.json ships with is not a mistake.
        File.WriteAllText(Path.Combine(_dir, "appsettings.json"), """{ "Harpo": { "DatabaseKey": "" } }""");
        ConfigurationBuilder Shipped() => (ConfigurationBuilder)new ConfigurationBuilder()
            .SetBasePath(_dir)
            .AddJsonFile("appsettings.json");
        static Dictionary<string, string?> Setting(string key, string? value) => new() { [key] = value };

        Assert.False(DbEncryptionOptions.FromConfiguration(Shipped().Build()).KeyLeftBlank);
        Assert.False(DbEncryptionOptions.FromConfiguration(
            Shipped().AddInMemoryCollection(Setting("Harpo:DatabaseKey", "key-1")).Build()).KeyLeftBlank);

        // Anything else that supplies it blank; an empty secret file ends up as this too.
        Assert.True(DbEncryptionOptions.FromConfiguration(
            Shipped().AddInMemoryCollection(Setting("Harpo:DatabaseKey", "")).Build()).KeyLeftBlank);
        Assert.True(DbEncryptionOptions.FromConfiguration(
            Shipped().AddInMemoryCollection(Setting("Harpo:DatabaseKey", "   ")).Build()).KeyLeftBlank);

        // A blank path to a secret file, which FileConfigurationSecrets passes over.
        Assert.True(DbEncryptionOptions.FromConfiguration(
            Shipped().AddInMemoryCollection(Setting("Harpo:DatabaseKey:File", "")).Build()).KeyLeftBlank);
    }

    [Theory]
    [InlineData("Harpo__DatabaseKey")]
    [InlineData("HARPO__DATABASEKEY")]
    [InlineData("Harpo:DatabaseKey")]
    public void A_blank_environment_variable_counts_as_left_blank(string name)
    {
        var configuration = new ConfigurationBuilder().AddEnvironmentVariables(); // read only by this test's builder
        Environment.SetEnvironmentVariable(name, "");
        try
        {
            Assert.True(DbEncryptionOptions.FromConfiguration(configuration.Build()).KeyLeftBlank);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public async Task Failed_encryption_leaves_the_file_alone_and_no_partial_copy()
    {
        await SeedAsync(RawCs);
        await using (var db = CreateContext(RawCs))
        {
            db.Groups.AddRange(Enumerable.Range(0, 2000).Select(i => new Group { Id = Guid.NewGuid(), Name = $"Group {i}" }));
            await db.SaveChangesAsync();
        }
        SqliteConnection.ClearAllPools();

        // Damage the tables' pages but not the schema, so the copy starts and fails partway.
        var bytes = await File.ReadAllBytesAsync(DbPath);
        Array.Fill(bytes, (byte)0xFF, bytes.Length / 2, bytes.Length - bytes.Length / 2);
        await File.WriteAllBytesAsync(DbPath, bytes);

        var ex = await Assert.ThrowsAsync<SqliteException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-1", null, false), NullLogger.Instance));
        Assert.True(ex.Message.Contains("malformed"), ex.Message);

        Assert.Equal(bytes, await File.ReadAllBytesAsync(DbPath));
        Assert.Empty(Directory.GetFiles(_dir, "*.recrypt-tmp*"));
    }

    [Theory]
    [InlineData(1, "SQLite Error 1: 'database or disk is full'.", "not enough free disk space")] // what sqlcipher_export gives
    [InlineData(13, "SQLite Error 13: 'database or disk is full'.", "not enough free disk space")]
    [InlineData(14, "SQLite Error 14: 'unable to open database file'.", "could not write to the volume")]
    [InlineData(1, "SQLite Error 1: 'unable to open database: /data/x'.", "could not write to the volume")]
    [InlineData(522, "SQLite Error 522: 'disk I/O error'.", "could not write to the volume")] // an extended code
    [InlineData(1, "SQLite Error 1: 'disk I/O error'.", "could not write to the volume")]
    public async Task Failures_to_write_get_a_message_that_says_what_to_do(int code, string text, string expected)
    {
        await SeedAsync(RawCs);
        var message = DbEncryption.WriteFailureMessage(new SqliteException(text, code), DbPath, "encrypt");
        Assert.Contains(expected, message);
        Assert.Contains(DbPath, message);
        Assert.Contains("has not been changed", message);
    }

    [Theory]
    [InlineData(5, "SQLite Error 5: 'database is locked'.")]
    [InlineData(6, "SQLite Error 6: 'database table is locked'.")]
    [InlineData(1, "SQLite Error 1: 'database is locked'.")] // what sqlcipher_export gives
    public void A_lock_is_not_blamed_on_the_disk(int code, string text)
    {
        var message = DbEncryption.WriteFailureMessage(new SqliteException(text, code), DbPath, "encrypt");
        Assert.Contains("in use by something else", message);
        Assert.DoesNotContain("free", message);
    }

    [Fact]
    public void Other_failures_are_not_blamed_on_the_disk()
    {
        Assert.Null(DbEncryption.WriteFailureMessage(new SqliteException("SQLite Error 11: 'database disk image is malformed'.", 11), DbPath, "encrypt"));
        Assert.Null(DbEncryption.WriteFailureMessage(new SqliteException("SQLite Error 11: 'unable to open database: /data/x'.", 11), DbPath, "encrypt")); // ATTACH on a damaged file
    }

    [Fact]
    public async Task The_space_asked_for_covers_the_file_its_wal_and_what_encrypting_adds()
    {
        await File.WriteAllBytesAsync(DbPath, new byte[10 * 1024 * 1024]);
        await File.WriteAllBytesAsync(DbPath + "-wal", new byte[10 * 1024 * 1024]);

        var message = DbEncryption.WriteFailureMessage(new SqliteException("SQLite Error 13: 'database or disk is full'.", 13), DbPath, "encrypt");

        Assert.Contains("at least 22 MB", message); // 20 MB + 5%, rounded up, + 1
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_message_for_a_failure_names_what_was_being_done(bool encrypted)
    {
        var options = encrypted ? await EncryptedSeedAsync("key-1") : new DbEncryptionOptions("key-1", null, false);
        if (!encrypted)
        {
            await SeedAsync(RawCs);
        }
        else
        {
            options = options with { RemoveEncryption = true };
        }

        // A directory in the way of the copy.
        var blocked = Directory.CreateDirectory(DbPath + ".recrypt-tmp").FullName;
        await File.WriteAllTextAsync(Path.Combine(blocked, "x"), "x");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance));

        Assert.Contains(encrypted ? "to decrypt it" : "to encrypt it", ex.Message);
    }

    [Fact]
    public async Task A_copy_that_cannot_be_written_or_removed_still_reports_why()
    {
        await SeedAsync(RawCs);
        var before = await File.ReadAllBytesAsync(DbPath);

        // A directory in the way: the copy cannot be created and the cleanup cannot delete it.
        var blocked = Directory.CreateDirectory(DbPath + ".recrypt-tmp").FullName;
        await File.WriteAllTextAsync(Path.Combine(blocked, "x"), "x");
        var logger = new RecordingLogger();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-1", null, false), logger));

        Assert.Contains("could not write to the volume", ex.Message);
        Assert.Contains(logger.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("Delete it by hand"));
        Assert.Equal(before, await File.ReadAllBytesAsync(DbPath));
    }

    [Theory]
    [InlineData(".recrypt-tmp")]
    [InlineData(".recrypt-tmp-journal")]
    public async Task A_copy_left_by_an_interrupted_run_is_removed_on_any_start(string leftover)
    {
        // Encrypted, with the key: nothing here needs a new copy, but the old one still goes.
        var options = await EncryptedSeedAsync("key-1");
        await File.WriteAllTextAsync(DbPath + leftover, "SQLite format 3 partial plaintext");

        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);

        Assert.False(File.Exists(DbPath + leftover));
        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
    }

    [Fact]
    public async Task A_rotation_of_a_file_it_cannot_write_says_so()
    {
        var options = await EncryptedSeedAsync("key-1");

        File.SetUnixFileMode(DbPath, UnixFileMode.UserRead);
        var logger = new RecordingLogger();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-2", "key-1", false), logger));
        File.SetUnixFileMode(DbPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        Assert.Contains("could not write to the volume", ex.Message);
        Assert.Contains("rotate the key of", ex.Message);
        Assert.DoesNotContain(logger.Lines, l => l.Message.Contains("rotation complete"));
        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
    }

    [Fact]
    public async Task A_rotation_that_cannot_create_its_journal_is_not_reported_as_done()
    {
        // DELETE mode, in a folder where the journal it needs cannot be created. SQLCipher
        // swallows this failure as it does a full disk, so only reopening the file shows it.
        var options = await EncryptedSeedAsync("key-1", wal: false);
        var writable = File.GetUnixFileMode(_dir);
        File.SetUnixFileMode(_dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        var logger = new RecordingLogger();
        try
        {
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-2", "key-1", false), logger));
            Assert.Contains("did not take effect", ex.Message);
            Assert.Contains(DbPath, ex.Message);
        }
        finally
        {
            File.SetUnixFileMode(_dir, writable);
        }
        Assert.DoesNotContain(logger.Lines, l => l.Message.Contains("rotation complete"));
        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
    }

    [Theory]
    [InlineData(null, "key-1", null, false)] // encrypt
    [InlineData("key-1", "key-1", null, true)] // decrypt
    [InlineData("key-1", "key-2", "key-1", false)] // rotate
    public async Task Rows_only_in_the_wal_survive(string? sourceKey, string key, string? previous, bool remove)
    {
        var rows = await KilledWithRowsInWalAsync(sourceKey);
        var options = new DbEncryptionOptions(key, previous, remove);

        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);

        Assert.Equal(rows, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
        Assert.Equal(remove, await DbEncryption.IsPlaintextAsync(DbPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task At_the_swap_the_main_file_alone_holds_everything(bool swapFails)
    {
        // Both a kill at this point and a swap that fails leave only the main file.
        var rows = await KilledWithRowsInWalAsync(null);
        var snapshot = Path.Combine(_dir, "at-swap.db");

        var export = DbEncryption.ExportAsync(DbPath, null, "key-1", NullLogger.Instance, (from, to) =>
        {
            Assert.False(File.Exists(to + "-wal"));
            Assert.False(File.Exists(to + "-shm"));
            File.Copy(to, snapshot);
            if (swapFails)
            {
                throw new IOException("Device or resource busy");
            }
            File.Move(from, to, overwrite: true);
        });

        if (swapFails)
        {
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => export);
            Assert.Contains("could not replace the database file", ex.Message);
            Assert.Contains("Device or resource busy", ex.Message);
            Assert.Contains("has not been changed", ex.Message);
            Assert.Empty(Directory.GetFiles(_dir, "*.recrypt-tmp*"));
            Assert.Equal(rows, await CountGroupsAsync(RawCs));
        }
        else
        {
            await export;
            Assert.Equal(rows, await CountGroupsAsync(new SqliteConnectionStringBuilder { DataSource = DbPath, Password = "key-1" }.ToString()));
            // Nothing still pooled from before the swap answers for the old, plaintext file.
            await Assert.ThrowsAnyAsync<SqliteException>(() =>
                CountGroupsAsync(new SqliteConnectionStringBuilder { DataSource = DbPath, Password = "" }.ToString()));
        }
        Assert.Equal(rows, await CountGroupsAsync(new SqliteConnectionStringBuilder { DataSource = snapshot }.ToString()));
    }

    [Theory]
    [InlineData(null, "key-1", null, false)] // encrypt
    [InlineData("key-1", "key-1", null, true)] // decrypt
    [InlineData("key-1", "key-2", "key-1", false)] // rotate
    public async Task A_file_something_else_has_open_is_not_changed(string? sourceKey, string key, string? previous, bool remove)
    {
        // An idle site in WAL mode: no transaction, nothing but its hold on the file.
        // Changing the file under it would lose whatever it writes next.
        var keyed = new SqliteConnectionStringBuilder { DataSource = DbPath, Password = sourceKey ?? "" }.ToString();
        await SeedAsync(keyed);
        await ExecuteAsync(keyed, "PRAGMA journal_mode=WAL");
        var before = await File.ReadAllBytesAsync(DbPath);
        await using var site = new SqliteConnection(new SqliteConnectionStringBuilder(keyed) { Pooling = false }.ToString());
        await site.OpenAsync();
        await using var command = site.CreateCommand();
        command.CommandText = "SELECT count(*) FROM Groups";
        await command.ExecuteScalarAsync();

        var options = new DbEncryptionOptions(key, previous, remove);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance));

        Assert.Contains("in use by something else", ex.Message);
        Assert.Equal(before, await File.ReadAllBytesAsync(DbPath));
        Assert.Empty(Directory.GetFiles(_dir, "*.recrypt-tmp*"));

        // The site carries on, and what it writes stays.
        command.CommandText = "UPDATE Groups SET Name = 'Still here'";
        await command.ExecuteNonQueryAsync();
        await site.CloseAsync();
        SqliteConnection.ClearAllPools();
        await using var db = CreateContext(keyed);
        Assert.Equal("Still here", (await db.Groups.SingleAsync()).Name);
    }

    [Fact]
    public async Task A_copy_replaced_after_the_lock_went_is_not_swapped_in()
    {
        // Anything starting once the lock is released could replace the copy, even with
        // an empty file, which opens without complaint.
        await SeedAsync(RawCs);
        var copy = DbPath + ".recrypt-tmp";
        await File.WriteAllBytesAsync(copy, []);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.RequireRowsAsync(copy, "", 1, DbPath, "encrypt"));

        Assert.Contains("does not hold what it should", ex.Message);
    }

    [Fact]
    public async Task A_copy_missing_rows_is_refused()
    {
        await SeedAsync(RawCs);
        await using var connection = new SqliteConnection(RawCs);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            ATTACH DATABASE ':memory:' AS target;
            CREATE TABLE target."Groups" AS SELECT * FROM main."Groups";
            """;
        await command.ExecuteNonQueryAsync();

        // Copying only what the schema needs: the other tables are all empty, so it matches.
        command.CommandText = "SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'Groups'";
        var others = new List<string>();
        await using (var reader = await command.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                others.Add(reader.GetString(0));
            }
        }
        foreach (var table in others)
        {
            command.CommandText = $"CREATE TABLE target.\"{table}\" AS SELECT * FROM main.\"{table}\"";
            await command.ExecuteNonQueryAsync();
        }
        await DbEncryption.RequireSameRowsAsync(connection, DbPath, "encrypt");

        command.CommandText = "DELETE FROM target.\"Groups\"";
        await command.ExecuteNonQueryAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => DbEncryption.RequireSameRowsAsync(connection, DbPath, "encrypt"));
        Assert.Contains("does not match it (table Groups)", ex.Message);
    }

    [Fact]
    public async Task A_reader_mid_transaction_stops_the_change_and_keeps_the_wal()
    {
        await SeedAsync(RawCs);
        await ExecuteAsync(RawCs, "PRAGMA journal_mode=WAL");

        // Something else in the middle of reading an old snapshot.
        var other = new SqliteConnectionStringBuilder(RawCs) { Pooling = false, DefaultTimeout = 1 }.ToString();
        await using var reader = new SqliteConnection(other);
        await reader.OpenAsync();
        await using var hold = reader.CreateCommand();
        hold.CommandText = "BEGIN; SELECT count(*) FROM Groups;";
        await hold.ExecuteScalarAsync();
        await using (var db = CreateContext(RawCs))
        {
            db.Groups.Add(new Group { Id = Guid.NewGuid(), Name = "Newer" });
            await db.SaveChangesAsync();
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.ExportAsync(DbPath, null, "key-1", NullLogger.Instance));

        Assert.Contains("in use by something else", ex.Message);
        Assert.Empty(Directory.GetFiles(_dir, "*.recrypt-tmp*"));
        Assert.True(new FileInfo(DbPath + "-wal").Length > 0);
        await reader.CloseAsync();
        Assert.True(await DbEncryption.IsPlaintextAsync(DbPath));
        Assert.Equal(2, await CountGroupsAsync(RawCs));
    }

    [Theory]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite)]
    [InlineData(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead)]
    public async Task Encrypting_and_decrypting_keep_the_file_mode(UnixFileMode mode)
    {
        await SeedAsync(RawCs);
        File.SetUnixFileMode(DbPath, mode);

        await DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-1", null, false), NullLogger.Instance);
        Assert.False(await DbEncryption.IsPlaintextAsync(DbPath));
        Assert.Equal(mode, File.GetUnixFileMode(DbPath));

        await DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-1", null, true), NullLogger.Instance);
        Assert.True(await DbEncryption.IsPlaintextAsync(DbPath));
        Assert.Equal(mode, File.GetUnixFileMode(DbPath));
    }

    [Fact]
    public async Task A_hot_journal_is_rolled_back_rather_than_called_a_wrong_key()
    {
        await KilledWithHotJournalAsync("key-1");

        // A wrong key is still told apart, and trying one does no harm.
        var wrong = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("wrong", null, false), NullLogger.Instance));
        Assert.Contains("does not open it", wrong.Message);

        var options = new DbEncryptionOptions("key-1", null, false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);

        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
        Assert.False(File.Exists(DbPath + "-journal"));
    }

    [Fact]
    public async Task A_file_that_cannot_be_opened_is_not_called_a_wrong_key()
    {
        // A journal it cannot roll back, on a volume it cannot write to.
        await KilledWithHotJournalAsync("key-1");
        File.SetUnixFileMode(DbPath, UnixFileMode.UserRead);
        var writable = File.GetUnixFileMode(_dir);
        File.SetUnixFileMode(_dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-1", null, false), NullLogger.Instance));

            Assert.Contains("could not open the database", ex.Message);
            Assert.DoesNotContain("does not open it", ex.Message);
            Assert.IsType<SqliteException>(ex.InnerException);
        }
        finally
        {
            File.SetUnixFileMode(_dir, writable);
        }
    }

    [Fact]
    public async Task A_copy_left_behind_goes_even_when_the_database_file_is_missing()
    {
        await File.WriteAllTextAsync(DbPath + ".recrypt-tmp", "SQLite format 3 partial plaintext");

        await DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions(null, null, false), NullLogger.Instance);

        Assert.False(File.Exists(DbPath + ".recrypt-tmp"));
    }

    [Fact]
    public async Task A_migration_lock_left_by_a_killed_start_does_not_hang_the_next()
    {
        var options = new DbContextOptionsBuilder<HarpoDbContext>().UseSqlite(RawCs).Options;
        var factory = new TestDbFactory(options, new ManualTime(), "enc-test");
        await DbInitializer.InitializeAsync(factory, RawCs);
        await ExecuteAsync(RawCs, "INSERT INTO \"__EFMigrationsLock\" (\"Id\", \"Timestamp\") VALUES (1, '2026-11-02')");
        var logger = new RecordingLogger();

        await DbInitializer.InitializeAsync(factory, RawCs, logger).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Contains(logger.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("migration lock"));
    }

    [Fact]
    public async Task A_file_locked_by_something_else_is_not_called_a_wrong_key_or_a_full_disk()
    {
        var options = await EncryptedSeedAsync("key-1", wal: false);
        await using var other = new SqliteConnection(new SqliteConnectionStringBuilder(DbEncryption.ApplyKey(RawCs, options)) { Pooling = false }.ToString());
        await other.OpenAsync();
        await using var command = other.CreateCommand();
        command.CommandText = "BEGIN EXCLUSIVE";
        await command.ExecuteNonQueryAsync();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance));

        // On macOS .NET cannot even read a file with this lock on it. On Linux, where Harpo
        // runs, it can, so SQLite is what reports it.
        Assert.Contains(OperatingSystem.IsLinux() ? "in use by something else, so Harpo cannot safely check its key" : "could not read the database file", ex.Message);
    }

    [Fact]
    public async Task A_new_site_in_a_folder_that_does_not_exist_yet_logs_no_warning()
    {
        var logger = new RecordingLogger();
        var missing = new SqliteConnectionStringBuilder { DataSource = Path.Combine(_dir, "not-yet", "test.db") }.ToString();

        await DbEncryption.EnsureEncryptionStateAsync(missing, new DbEncryptionOptions(null, null, false), logger);

        Assert.DoesNotContain(logger.Lines, l => l.Level >= LogLevel.Warning);
    }

    [Fact]
    public async Task A_previous_key_no_longer_needed_is_pointed_out()
    {
        await EncryptedSeedAsync("key-2");
        var logger = new RecordingLogger();

        await DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-2", "key-1", false), logger);

        Assert.Contains(logger.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("no longer needed"));
    }

    /// <summary>Corrupts one byte of each of the given pages of the encrypted file.</summary>
    private async Task DamagePagesAsync(Func<int, bool> page)
    {
        const int pageSize = 4096;
        var bytes = await File.ReadAllBytesAsync(DbPath);
        for (var i = 0; i < bytes.Length / pageSize; i++)
        {
            if (page(i))
            {
                bytes[i * pageSize + 100] ^= 0xFF;
            }
        }
        await File.WriteAllBytesAsync(DbPath, bytes);
    }

    [Fact]
    public async Task A_damaged_file_with_the_right_key_is_not_called_a_wrong_key()
    {
        var options = await EncryptedSeedAsync("key-1", wal: false);
        await DamagePagesAsync(i => i > 0); // the schema's pages, but not the first

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance));

        Assert.Contains("may be damaged", ex.Message);
        Assert.DoesNotContain("does not open it", ex.Message);
    }

    [Fact]
    public async Task A_damaged_first_page_says_it_might_be_that_rather_than_the_key()
    {
        var options = await EncryptedSeedAsync("key-1", wal: false);
        await DamagePagesAsync(i => i == 0);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance));

        Assert.Contains("does not open it", ex.Message);
        Assert.Contains("may be damaged", ex.Message);
    }

    [Fact]
    public async Task A_rotation_stopped_by_damage_does_not_send_the_operator_after_disk_space()
    {
        await SeedAsync(RawCs);
        await using (var db = CreateContext(RawCs))
        {
            db.Groups.AddRange(Enumerable.Range(0, 2000).Select(i => new Group { Id = Guid.NewGuid(), Name = $"Group {i}" }));
            await db.SaveChangesAsync();
        }
        SqliteConnection.ClearAllPools();
        var options = new DbEncryptionOptions("key-1", null, false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);
        var pages = new FileInfo(DbPath).Length / 4096;
        await DamagePagesAsync(i => i == pages - 2); // a table page, not the schema's

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-2", "key-1", false), NullLogger.Instance));

        Assert.Contains("the file is damaged", ex.Message);
        Assert.Contains("keep both keys", ex.Message);
        Assert.DoesNotContain("free up some space", ex.Message);
    }

    [Fact]
    public async Task A_migration_lock_something_else_may_be_holding_is_left_alone()
    {
        var options = new DbContextOptionsBuilder<HarpoDbContext>().UseSqlite(RawCs).Options;
        var factory = new TestDbFactory(options, new ManualTime(), "enc-test");
        await DbInitializer.InitializeAsync(factory, RawCs);
        await ExecuteAsync(RawCs, "INSERT INTO \"__EFMigrationsLock\" (\"Id\", \"Timestamp\") VALUES (1, '2026-11-03')");
        await using var other = new SqliteConnection(new SqliteConnectionStringBuilder(RawCs) { Pooling = false }.ToString());
        await other.OpenAsync();
        await using var command = other.CreateCommand();
        command.CommandText = "SELECT count(*) FROM \"__EFMigrationsLock\"";
        Assert.Equal(1L, await command.ExecuteScalarAsync());
        var logger = new RecordingLogger();

        var start = DbInitializer.InitializeAsync(factory, RawCs, logger);

        for (var i = 0; i < 300 && !logger.Lines.Any(l => l.Message.Contains("something else has the database file open")); i++)
        {
            await Task.Delay(100);
        }
        Assert.Contains(logger.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("something else has the database file open"));
        Assert.False(start.IsCompleted);
        Assert.Equal(1L, await command.ExecuteScalarAsync());

        // Once the other process finishes and lets go, this start carries on.
        command.CommandText = "DELETE FROM \"__EFMigrationsLock\"";
        await command.ExecuteNonQueryAsync();
        await start.WaitAsync(TimeSpan.FromSeconds(60));
    }

    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Add((logLevel, formatter(state, exception)));
    }
}
