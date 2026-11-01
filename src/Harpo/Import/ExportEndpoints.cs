using System.Security.Claims;
using Harpo.Offline;
using Harpo.Services;
using Microsoft.Extensions.Options;

namespace Harpo.Import;

/// <summary>Per-user cooldown for vault exports — the offline snapshot's throttle, with its own slots.</summary>
public sealed class ExportThrottle(TimeProvider time) : OfflineSnapshotThrottle(time);

/// <summary>Per-user cooldown for the all-groups export, apart from the vault exports' so neither uses up the other.</summary>
public sealed class AllGroupsExportThrottle(TimeProvider time) : OfflineSnapshotThrottle(time);

public static class ExportEndpoints
{
    public const string Route = "/api/vault/{groupId:guid}/export";

    /// <summary>Every shared group of the site as one archive, for site administrators.</summary>
    public const string AllGroupsRoute = "/api/admin/export";

    /// <summary>The download link the export dialog offers.</summary>
    public static string UrlFor(Guid groupId, ExportFormat format) =>
        $"/api/vault/{groupId}/export?format={FormatName(format)}";

    /// <summary>The download link the all-groups export dialog offers.</summary>
    public static string AllGroupsUrlFor(ExportFormat format) => $"{AllGroupsRoute}?format={FormatName(format)}";

    private static string FormatName(ExportFormat format) => format == ExportFormat.Json ? "json" : "csv";

    public static void MapExportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(Route, HandleAsync).RequireAuthorization();
        app.MapGet(AllGroupsRoute, HandleAllGroupsAsync).RequireAuthorization();
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
        if (FromAnotherSite(http))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        if (!TryParseFormat(format, out var chosen))
        {
            return Results.BadRequest(new { error = "format must be csv or json" });
        }

        var user = UserContext.FromPrincipal(principal);
        if (!await sessions.IsLiveAsync(user.SessionId, touch: true, ct))
        {
            return SessionEnded();
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
            return Forbidden(ex);
        }

        if (!TryAcquire(http, throttle, user, options.Value.MinSecondsBetweenExports))
        {
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
            return Forbidden(ex);
        }

        NoCopies(http);
        return Results.File(file.Content, file.ContentType, file.FileName);
    }

    /// <summary>
    /// <c>GET /api/admin/export?format=csv|json</c>: every live shared group as
    /// one zip, for site administrators. The same order of checks as
    /// <see cref="HandleAsync"/>: 404 unless both export switches are on, 403
    /// from another site's page, 400 for an unknown format, 401 without a live
    /// session, 403 for anyone but a site admin — all before a cooldown of its
    /// own (429), so a refusal costs no slot — and only then the decrypt, which
    /// <see cref="VaultService.ExportAllGroupsAsync"/> audits once. The archive
    /// is built in memory and never written to disk.
    /// </summary>
    public static async Task<IResult> HandleAllGroupsAsync(
        string? format,
        ClaimsPrincipal principal,
        HttpContext http,
        VaultService vault,
        SessionService sessions,
        AllGroupsExportThrottle throttle,
        IOptions<ExportOptions> options,
        CancellationToken ct)
    {
        if (!options.Value.AllGroupsAvailable)
        {
            return Results.NotFound();
        }
        if (FromAnotherSite(http))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        if (!TryParseFormat(format, out var chosen))
        {
            return Results.BadRequest(new { error = "format must be csv or json" });
        }

        var user = UserContext.FromPrincipal(principal);
        if (!await sessions.IsLiveAsync(user.SessionId, touch: true, ct))
        {
            return SessionEnded();
        }
        try
        {
            await vault.RequireCanExportAllGroupsAsync(user, ct);
        }
        catch (VaultNotFoundException)
        {
            return Results.NotFound();
        }
        catch (VaultAccessDeniedException ex)
        {
            return Forbidden(ex);
        }

        if (!TryAcquire(http, throttle, user, options.Value.MinSecondsBetweenAllGroupsExports))
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        AllGroupsExportFile file;
        try
        {
            file = await vault.ExportAllGroupsAsync(user, chosen, ct);
        }
        catch (VaultNotFoundException)
        {
            return Results.NotFound();
        }
        catch (VaultAccessDeniedException ex)
        {
            return Forbidden(ex);
        }

        NoCopies(http);
        return Results.File(file.Content, AllGroupsExportFile.ContentType, file.FileName);
    }

    /// <summary>
    /// A link on another site can still send the session cookie with a
    /// top-level navigation (SameSite=Lax), which would drop a plain-text file
    /// into the victim's downloads. Browsers say where a request came from;
    /// only Harpo's own pages, or the address typed in (none), may start one.
    /// </summary>
    private static bool FromAnotherSite(HttpContext http)
    {
        var fetchSite = http.Request.Headers["Sec-Fetch-Site"].ToString();
        return fetchSite.Length > 0 && fetchSite is not ("same-origin" or "none");
    }

    private static bool TryParseFormat(string? format, out ExportFormat chosen)
    {
        switch ((format ?? "csv").Trim().ToLowerInvariant())
        {
            case "csv":
                chosen = ExportFormat.Csv;
                return true;
            case "json":
                chosen = ExportFormat.Json;
                return true;
            default:
                chosen = default;
                return false;
        }
    }

    private static IResult SessionEnded() =>
        Results.Json(new { error = SessionService.SessionEndedMessage }, statusCode: StatusCodes.Status401Unauthorized);

    private static IResult Forbidden(VaultAccessDeniedException ex) =>
        Results.Json(new { error = ex.Message }, statusCode: StatusCodes.Status403Forbidden);

    private static bool TryAcquire(HttpContext http, OfflineSnapshotThrottle throttle, UserContext user, int minSeconds)
    {
        var minInterval = TimeSpan.FromSeconds(Math.Max(1, minSeconds));
        if (throttle.TryAcquire(user.Username, minInterval, out var retryAfter))
        {
            return true;
        }
        http.Response.Headers.RetryAfter = Math.Ceiling(retryAfter.TotalSeconds).ToString("0");
        return false;
    }

    /// <summary>Every password in the file, in plain text: nothing may keep a copy.</summary>
    private static void NoCopies(HttpContext http)
    {
        http.Response.Headers.CacheControl = "no-store, no-cache, max-age=0, private";
        http.Response.Headers.Pragma = "no-cache";
        http.Response.Headers.Expires = "0";
        http.Response.Headers.XContentTypeOptions = "nosniff";
    }
}
