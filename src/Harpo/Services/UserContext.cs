using System.Security.Claims;
using Harpo.Security;

namespace Harpo.Services;

/// <summary>The authenticated caller, as seen by the service layer.</summary>
public sealed record UserContext(string Username, string DisplayName, bool IsSiteAdmin)
{
    /// <summary>
    /// The server-side session this caller signed in with. Services check it is
    /// still live (<see cref="SessionService.RequireLiveAsync"/>) before revealing
    /// or changing anything, so an interactive page that cached this context when
    /// it opened loses access the moment the session ends — sign-out in another
    /// tab, account disabled, admin role changed, expiry.
    ///
    /// Null only for contexts built in-process that never came from a sign-in
    /// (the startup icon import, unit tests). Every context derived from a
    /// principal has one: <see cref="FromPrincipal"/> never returns null here.
    /// </summary>
    public string? SessionId { get; init; }

    public static UserContext FromPrincipal(ClaimsPrincipal principal)
    {
        var username = principal.Identity?.Name
            ?? throw new InvalidOperationException("No authenticated user.");
        var displayName = principal.FindFirstValue(HarpoClaims.DisplayName) ?? username;
        var isSiteAdmin = principal.IsInRole(HarpoClaims.SiteAdminRole);
        return new UserContext(username.ToLowerInvariant(), displayName, isSiteAdmin)
        {
            // A principal without a session claim (a cookie from before sessions
            // existed) gets an id that matches no session: denied, never exempt.
            SessionId = principal.FindFirstValue(HarpoClaims.SessionId) ?? "",
        };
    }
}

/// <summary>The caller is not allowed to see or touch the requested object.</summary>
public sealed class VaultAccessDeniedException : Exception
{
    public VaultAccessDeniedException(string message) : base(message)
    {
    }
}

public sealed class VaultNotFoundException : Exception
{
    public VaultNotFoundException(string message) : base(message)
    {
    }
}

public sealed class VaultValidationException : Exception
{
    public VaultValidationException(string message, string? field = null) : base(message)
    {
        Field = field;
    }

    /// <summary>
    /// The input the problem belongs to ("name", "password", "totp"), when there
    /// is one — lets a form show the message at that field instead of in a
    /// summary far from it.
    /// </summary>
    public string? Field { get; }
}
