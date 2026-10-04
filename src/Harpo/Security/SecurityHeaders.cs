using System.Text.RegularExpressions;

namespace Harpo.Security;

/// <summary>
/// Response headers that limit what a Harpo page may load, run and talk to.
///
/// Blazor encodes everything it renders, so nothing here is load-bearing today.
/// It is the second line: were a way to inject markup ever found, a page showing
/// revealed passwords still could not run someone else's script, be restyled to
/// leak what it shows, post a form elsewhere, or be framed by another site.
/// The policy is owned here, in one place — Blazor's own frame-ancestors header
/// is switched off in Program.cs so two policies never have to be reconciled.
/// </summary>
public static partial class SecurityHeaders
{
    public const string OfflinePagePath = "/offline.html";

    /// <summary>
    /// The offline vault is a single self-contained page: its styles are inline so
    /// it works from the service worker's cache with nothing else to fetch. Its
    /// policy differs from the app's in exactly that, and is otherwise tighter (no
    /// forms, no base). The page repeats it in a meta tag for copies cached before
    /// this header existed; only the header can enforce frame-ancestors.
    /// </summary>
    internal const string OfflinePagePolicy =
        "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; "
        + "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    /// <summary>
    /// Everything from this origin only, and nothing inline: no inline script, no
    /// inline style, no eval. <c>data:</c> images are the favicon. The interactive
    /// pages hold a WebSocket to this same host; <c>'self'</c> covers that in
    /// current browsers, and the host is also named outright for those where it
    /// does not — without it they would silently fall back to slower polling.
    /// </summary>
    internal static string AppPolicy(HostString host)
    {
        var connect = "connect-src 'self'";
        if (host.HasValue && SafeHost().IsMatch(host.Value))
        {
            connect += $" ws://{host.Value} wss://{host.Value}";
        }
        return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
            + connect
            + "; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    }

    // The Host header ends up inside a header we send back, so only plain host
    // syntax is ever echoed: a name or IPv4 address, or a bracketed IPv6
    // literal, with an optional port.
    [GeneratedRegex(@"^(?:[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])(?::\d{1,5})?$")]
    private static partial Regex SafeHost();

    /// <summary>
    /// Adds the headers to every response. Set before the rest of the pipeline
    /// runs, so an endpoint with stricter needs of its own (the icon endpoint
    /// sandboxes what it serves) simply replaces the policy.
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy = context.Request.Path.Equals(OfflinePagePath, StringComparison.OrdinalIgnoreCase)
                ? OfflinePagePolicy
                : AppPolicy(context.Request.Host);
            headers.XContentTypeOptions = "nosniff";
            await next();
        });
}
