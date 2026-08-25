using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Data;

public static class DbInitializer
{
    public static async Task InitializeAsync(IDbContextFactory<HarpoDbContext> factory, string connectionString)
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
        await db.Database.EnsureCreatedAsync();
        // WAL lets the replication loop write while the UI reads.
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
        if (!await db.SiteCounters.AnyAsync())
        {
            db.SiteCounters.Add(new SiteCounter { Id = 1, NextSeq = 1 });
            await db.SaveChangesAsync();
        }
    }
}
