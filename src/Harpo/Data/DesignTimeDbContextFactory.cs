using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Options;

namespace Harpo.Data;

/// <summary>Used only by the dotnet-ef tooling (e.g. `dotnet ef migrations add`).</summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<HarpoDbContext>
{
    public HarpoDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<HarpoDbContext>()
            .UseSqlite("Data Source=design-time-only.db")
            .Options;
        return new HarpoDbContext(options, TimeProvider.System, Options.Create(new SiteOptions()));
    }
}
