using System.Security.Claims;
using Harpo.Offline;
using Harpo.Services;
using Microsoft.Extensions.Options;

namespace Harpo.Import;

/// <summary>Per-user cooldown for vault exports — the offline snapshot's throttle, with its own slots.</summary>
public sealed class ExportThrottle(TimeProvider time) : OfflineSnapshotThrottle(time);

public static class ExportEndpoints
{
    public const string Route = "/api/vault/{groupId:guid}/export";

    /// <summary>The download link the export dialog offers.</summary>
    public static string UrlFor(Guid groupId, ExportFormat format) =>
        $"/api/vault/{groupId}/export?format={(format == ExportFormat.Json ? "json" : "csv")}";

    public static void MapExportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(Route, HandleAsync).RequireAuthorization();
    }

    /// <summary>
    /// <c>GET /api/vault/{groupId}/export?format=csv|json</c>: the vault as a
    /// file. Modelled on the offline snapshot: 404 while the site switch is off,
    /// the session checked again here (401), the rights next (403/404) — before
    /// the per-user cooldown (429), so a refusal costs no slot — and only then
    /// the decrypt, which <see cref="VaultService.ExportVaultAsync"/> audits.
    /// </summary>
    public static async Task<IResult> HandleAsync(
        Guid groupId,
        string? format,
        ClaimsPrincipal principal,
        HttpContext http,
        VaultService vault,
        SessionService sessions,
        ExportThrottle throttle,
        IOptions<ExportOptions> options,
        CancellationToken ct)
    {
        if (!options.Value.Enabled)
        {
            return Results.NotFound();
        }
        // A link on another site can still send the session cookie with a
        // top-level navigation (SameSite=Lax), which would drop a plain-text file
        // into the victim's downloads. Browsers say where a request came from;
        // only Harpo's own pages, or the address typed in (none), may start one.
        var fetchSite = http.Request.Headers["Sec-Fetch-Site"].ToString();
        if (fetchSite.Length > 0 && fetchSite is not ("same-origin" or "none"))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        ExportFormat chosen;
        switch ((format ?? "csv").Trim().ToLowerInvariant())
        {
            case "csv":
                chosen = ExportFormat.Csv;
                break;
            case "json":
                chosen = ExportFormat.Json;
                break;
            default:
                return Results.BadRequest(new { error = "format must be csv or json" });
        }

        var user = UserContext.FromPrincipal(principal);
        if (!await sessions.IsLiveAsync(user.SessionId, touch: true, ct))
        {
            return Results.Json(new { error = SessionService.SessionEndedMessage },
                statusCode: StatusCodes.Status401Unauthorized);
        }
        try
        {
            await vault.RequireCanExportAsync(user, groupId, ct);
        }
        catch (VaultNotFoundException)
        {
            return Results.NotFound();
        }
        catch (VaultAccessDeniedException ex)
        {
            return Results.Json(new { error = ex.Message }, statusCode: StatusCodes.Status403Forbidden);
        }

        var minInterval = TimeSpan.FromSeconds(Math.Max(1, options.Value.MinSecondsBetweenExports));
        if (!throttle.TryAcquire(user.Username, minInterval, out var retryAfter))
        {
            http.Response.Headers.RetryAfter = Math.Ceiling(retryAfter.TotalSeconds).ToString("0");
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        ExportFile file;
        try
        {
            file = await vault.ExportVaultAsync(user, groupId, chosen, ct);
        }
        catch (VaultNotFoundException)
        {
            return Results.NotFound();
        }
        catch (VaultAccessDeniedException ex)
        {
            return Results.Json(new { error = ex.Message }, statusCode: StatusCodes.Status403Forbidden);
        }

        // Every password in the vault, in plain text: nothing may keep a copy.
        http.Response.Headers.CacheControl = "no-store, no-cache, max-age=0, private";
        http.Response.Headers.Pragma = "no-cache";
        http.Response.Headers.Expires = "0";
        http.Response.Headers.XContentTypeOptions = "nosniff";
        return Results.File(file.Content, file.ContentType, file.FileName);
    }
}
