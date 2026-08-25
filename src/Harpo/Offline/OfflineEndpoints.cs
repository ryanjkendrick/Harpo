using System.Security.Claims;
using Harpo.Data;
using Harpo.Services;
using Microsoft.Extensions.Options;

namespace Harpo.Offline;

public static class OfflineEndpoints
{
    /// <summary>Requests must carry this header; it forces a CORS preflight for any cross-origin caller.</summary>
    public const string RequestHeader = "X-Harpo-Offline";

    public static void MapOfflineEndpoints(this IEndpointRouteBuilder app)
    {
        var logger = app.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Harpo.Offline");

        // Lightweight probe so the offline page can tell "feature off" apart from
        // "you are offline", and so devices learn the feature was disabled and wipe.
        app.MapGet("/api/offline/enabled", (IOptions<OfflineOptions> options) =>
            Results.Ok(new { enabled = options.Value.Enabled })).AllowAnonymous();

        app.MapGet("/api/offline/snapshot", async (
            ClaimsPrincipal principal,
            HttpContext http,
            VaultService vault,
            OfflineSnapshotThrottle throttle,
            IOptions<OfflineOptions> options,
            IOptions<SiteOptions> site,
            TimeProvider time,
            CancellationToken ct) =>
        {
            if (!options.Value.Enabled)
            {
                return Results.NotFound();
            }
            if (http.Request.Headers[RequestHeader].Count == 0)
            {
                return Results.BadRequest();
            }

            var user = UserContext.FromPrincipal(principal);
            var minInterval = TimeSpan.FromSeconds(Math.Max(1, options.Value.MinSecondsBetweenSnapshots));
            if (!throttle.TryAcquire(user.Username, minInterval, out var retryAfter))
            {
                http.Response.Headers.RetryAfter = Math.Ceiling(retryAfter.TotalSeconds).ToString("0");
                return Results.StatusCode(StatusCodes.Status429TooManyRequests);
            }

            var (groups, entries) = await vault.GetOfflineDataAsync(user, ct);

            // A snapshot decrypts the user's whole accessible vault — always audit it.
            logger.LogInformation(
                "Offline snapshot issued to {User}: {EntryCount} entries in {GroupCount} groups",
                user.Username, entries.Count, groups.Count);

            var snapshot = new OfflineSnapshot(
                user.Username,
                user.DisplayName,
                site.Value.SiteId,
                time.GetUtcNow().UtcDateTime,
                options.Value.SnapshotMaxAgeDays,
                groups,
                entries);
            return Results.Json(snapshot);
        }).RequireAuthorization();
    }
}
