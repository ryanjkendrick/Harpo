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

    private async Task<DbEncryptionOptions> EncryptedSeedAsync(string key)
    {
        await SeedAsync(RawCs);
        var options = new DbEncryptionOptions(key, null, false);
        await DbEncryption.EnsureEncryptionStateAsync(RawCs, options, NullLogger.Instance);
        return options;
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
    public async Task Status_is_held_and_does_not_touch_the_file_when_asked()
    {
        await SeedAsync(RawCs);
        var status = new DbEncryptionStatus();
        await DbEncryption.ReportStateAsync(RawCs, new DbEncryptionOptions(null, null, false), status, NullLogger.Instance);

        // Opening the file while the app runs would cancel SQLite's locks on it.
        File.Delete(DbPath);
        Assert.False(status.IsEncrypted);
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

    [Fact]
    public void Other_failures_are_not_blamed_on_the_disk()
    {
        Assert.Null(DbEncryption.WriteFailureMessage(new SqliteException("SQLite Error 11: 'database disk image is malformed'.", 11), DbPath, "encrypt"));
        Assert.Null(DbEncryption.WriteFailureMessage(new SqliteException("SQLite Error 11: 'unable to open database: /data/x'.", 11), DbPath, "encrypt")); // ATTACH on a damaged file
        Assert.Null(DbEncryption.WriteFailureMessage(new IOException("nope"), DbPath, "encrypt"));
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
    public async Task A_rotation_that_did_not_take_effect_is_not_reported_as_done()
    {
        var options = await EncryptedSeedAsync("key-1");

        // A file SQLite cannot write stands in for a full disk.
        File.SetUnixFileMode(DbPath, UnixFileMode.UserRead);
        var logger = new RecordingLogger();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DbEncryption.EnsureEncryptionStateAsync(RawCs, new DbEncryptionOptions("key-2", "key-1", false), logger));
        File.SetUnixFileMode(DbPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        Assert.Contains("did not take effect", ex.Message);
        Assert.DoesNotContain(logger.Lines, l => l.Message.Contains("rotation complete"));
        Assert.Equal(1, await CountGroupsAsync(DbEncryption.ApplyKey(RawCs, options)));
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
