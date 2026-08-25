using System.Security.Claims;
using Harpo.Security;

namespace Harpo.Services;

/// <summary>The authenticated caller, as seen by the service layer.</summary>
public sealed record UserContext(string Username, string DisplayName, bool IsSiteAdmin)
{
    public static UserContext FromPrincipal(ClaimsPrincipal principal)
    {
        var username = principal.Identity?.Name
            ?? throw new InvalidOperationException("No authenticated user.");
        var displayName = principal.FindFirstValue(HarpoClaims.DisplayName) ?? username;
        var isSiteAdmin = principal.IsInRole(HarpoClaims.SiteAdminRole);
        return new UserContext(username.ToLowerInvariant(), displayName, isSiteAdmin);
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
    public VaultValidationException(string message) : base(message)
    {
    }
}
