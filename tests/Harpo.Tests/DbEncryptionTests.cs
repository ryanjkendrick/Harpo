using Harpo.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
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
}
