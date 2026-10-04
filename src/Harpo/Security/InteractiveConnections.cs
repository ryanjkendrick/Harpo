using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Harpo.Security;

public class ConnectionLimitOptions
{
    /// <summary>
    /// How many interactive connections one account may hold open at once —
    /// roughly, browser tabs showing a Harpo page. 0 removes the limit.
    /// </summary>
    public int MaxPerUser { get; set; } = 20;
}

/// <summary>
/// Guards the endpoint behind every interactive page. Each open page holds a
/// connection there, and the server keeps the page's state in memory for as
/// long as it lasts — so who may open one, and how many, is worth bounding:
///
///  - only signed-in users. Every interactive page already requires a session;
///    the connection endpoint itself did not, so anyone who could reach the
///    server could hold connections open without ever logging in.
///  - a ceiling per account, so one account (or one runaway browser) cannot
///    take the server's memory with it.
/// </summary>
public static class InteractiveConnections
{
    /// <summary>
    /// The circuit endpoint and its negotiate/disconnect companions. The script
    /// that boots every page — the login page included — fetches
    /// <c>_blazor/initializers</c>, which opens nothing and stays public.
    /// </summary>
    internal static bool IsCircuitRequest(PathString path) =>
        path.StartsWithSegments("/_blazor") && !path.StartsWithSegments("/_blazor/initializers");

    /// <summary>
    /// One concurrency limiter per account, applied to circuit requests only. A
    /// WebSocket is a single request that lasts as long as the connection, so
    /// "requests in flight" is exactly "connections open". Nothing queues: over
    /// the limit is refused at once.
    /// </summary>
    internal static PartitionedRateLimiter<HttpContext> CreateLimiter(ConnectionLimitOptions options) =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            var user = context.User.Identity?.Name;
            if (options.MaxPerUser <= 0 || string.IsNullOrEmpty(user) || !IsCircuitRequest(context.Request.Path))
            {
                return RateLimitPartition.GetNoLimiter("");
            }
            return RateLimitPartition.GetConcurrencyLimiter(
                user.ToLowerInvariant(),
                _ => new ConcurrencyLimiterOptions { PermitLimit = options.MaxPerUser, QueueLimit = 0 });
        });

    public static IServiceCollection AddInteractiveConnectionLimits(
        this IServiceCollection services, ConnectionLimitOptions options) =>
        services.AddRateLimiter(limiter =>
        {
            limiter.GlobalLimiter = CreateLimiter(options);
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.OnRejected = async (rejected, ct) =>
            {
                var http = rejected.HttpContext;
                http.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger(typeof(InteractiveConnections))
                    .LogWarning(
                        "{User} already holds {Limit} interactive connections; another was refused. " +
                        "Raise Harpo:Connections:MaxPerUser if this account legitimately needs more.",
                        http.User.Identity?.Name, options.MaxPerUser);
                await http.Response.WriteAsync(
                    "Too many Harpo pages are open for this account. Close some and reload.", ct);
            };
        });

    /// <summary>Call after authentication: both checks need to know who is asking.</summary>
    public static IApplicationBuilder UseInteractiveConnectionLimits(this IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            if (IsCircuitRequest(context.Request.Path) && context.User.Identity?.IsAuthenticated != true)
            {
                // A body, so the status-code pages don't re-run this as a "not found" page.
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Sign in to Harpo first.");
                return;
            }
            await next();
        });
        return app.UseRateLimiter();
    }
}
