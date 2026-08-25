using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Harpo.Replication;

public static class ReplicationEndpoints
{
    public const string KeyHeader = "X-Harpo-Replication-Key";

    /// <summary>
    /// Site-to-site API. Not cookie-authenticated: peers present the shared
    /// replication key instead. Returns 404 while replication is disabled so the
    /// surface simply doesn't exist on standalone sites.
    /// </summary>
    public static void MapReplicationEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/replication").AllowAnonymous();

        group.MapPost("/pull", async (PullRequest request, ReplicationEngine engine, IOptions<ReplicationOptions> options, HttpContext http, CancellationToken ct) =>
        {
            if (!IsAuthorized(http, options.Value))
            {
                return DenyResult(options.Value);
            }
            var response = await engine.BuildResponseAsync(request, ct);
            return Results.Ok(response);
        });

        group.MapGet("/status", async (ReplicationEngine engine, IOptions<ReplicationOptions> options, HttpContext http, CancellationToken ct) =>
        {
            if (!IsAuthorized(http, options.Value))
            {
                return DenyResult(options.Value);
            }
            return Results.Ok(await engine.GetStatusAsync(ct));
        });
    }

    private static bool IsAuthorized(HttpContext http, ReplicationOptions options)
    {
        if (!options.Enabled)
        {
            return false;
        }
        var presented = http.Request.Headers[KeyHeader].ToString();
        if (presented.Length == 0)
        {
            return false;
        }
        var a = Encoding.UTF8.GetBytes(presented);
        var b = Encoding.UTF8.GetBytes(options.Key);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static IResult DenyResult(ReplicationOptions options) =>
        options.Enabled ? Results.StatusCode(StatusCodes.Status403Forbidden) : Results.NotFound();
}
