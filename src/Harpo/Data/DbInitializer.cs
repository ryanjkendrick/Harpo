using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Data;

public static class DbInitializer
{
    public static async Task InitializeAsync(
        IDbContextFactory<HarpoDbContext> factory, string connectionString, ILogger? logger = null)
    {
        // Make sure the directory for the SQLite file exists (e.g. /data in the container).
        var dataSource = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (!string.IsNullOrEmpty(dataSource) && dataSource != ":memory:")
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(dataSource));
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }

        await using var db = await factory.CreateDbContextAsync();

        // Databases created before Harpo adopted EF migrations (via EnsureCreated)
        // have the full original schema but no migrations history. Baseline them:
        // mark the initial migration as applied so Migrate() only adds what's new.
        if (await TableExistsAsync(db, "Groups") && !await TableExistsAsync(db, "__EFMigrationsHistory"))
        {
            var initialMigration = db.Database.GetMigrations().First();
            var productVersion = typeof(DbContext).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?.Split('+')[0] ?? "10.0.0";
            await db.Database.ExecuteSqlRawAsync(
                """
                CREATE TABLE "__EFMigrationsHistory" (
                    "MigrationId" TEXT NOT NULL CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY,
                    "ProductVersion" TEXT NOT NULL
                )
                """);
            await db.Database.ExecuteSqlAsync(
                $"INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ({initialMigration}, {productVersion})");
            logger?.LogWarning(
                "Existing database baselined at migration {Migration}; newer migrations will now apply.", initialMigration);
        }

        await RemoveStaleMigrationLockAsync(db, connectionString, logger);

        await db.Database.MigrateAsync();

        // WAL lets the replication loop write while the UI reads.
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
        if (!await db.SiteCounters.AnyAsync())
        {
            db.SiteCounters.Add(new SiteCounter { Id = 1, NextSeq = 1 });
            await db.SaveChangesAsync();
        }
    }

    /// <summary>
    /// EF's migration lock is a row, and a process killed mid-migration leaves it behind.
    /// MigrateAsync then waits for it for good, with nothing in the log. A row is stale
    /// only if nothing else has the file open, which an exclusive lock proves: taken
    /// first, on the connection doing the delete, so that nothing can start in between.
    /// </summary>
    private static async Task RemoveStaleMigrationLockAsync(HarpoDbContext db, string connectionString, ILogger? logger)
    {
        if (!await TableExistsAsync(db, "__EFMigrationsLock")
            || await db.Database.SqlQueryRaw<long>("SELECT count(*) AS \"Value\" FROM \"__EFMigrationsLock\"").SingleAsync() == 0)
        {
            return;
        }

        await db.Database.GetDbConnection().CloseAsync();
        SqliteConnection.ClearAllPools(); // this context's own connection would count as something else
        try
        {
            await using var connection = await DbEncryption.OpenExclusiveAsync(connectionString, waitSeconds: 2);
            await using var delete = connection.CreateCommand();
            delete.CommandText = "DELETE FROM \"__EFMigrationsLock\"";
            await delete.ExecuteNonQueryAsync();
            logger?.LogWarning("Removed the migration lock an interrupted start left behind.");
        }
        catch (SqliteException ex) when ((ex.SqliteErrorCode & 0xFF) is 5 or 6) // SQLITE_BUSY, SQLITE_LOCKED
        {
            logger?.LogWarning(
                "A migration lock is set and something else has the database file open, so this start will wait for " +
                "it. Only one Harpo may use a database file: if this does not clear, stop whatever else is using it.");
        }
    }

    private static async Task<bool> TableExistsAsync(HarpoDbContext db, string tableName)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync();
        }
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = $name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "$name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        return Convert.ToInt64(await command.ExecuteScalarAsync()) > 0;
    }
}
