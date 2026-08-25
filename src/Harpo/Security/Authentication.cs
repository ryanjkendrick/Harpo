using System.Security.Claims;

namespace Harpo.Security;

/// <summary>Result of a successful credential check.</summary>
public sealed record AuthResult(string Username, string DisplayName, bool IsSiteAdmin);

/// <summary>Thrown when the directory itself is unreachable (as opposed to bad credentials).</summary>
public sealed class AuthenticationUnavailableException : Exception
{
    public AuthenticationUnavailableException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

public interface IAuthenticator
{
    /// <summary>Returns null for invalid credentials; throws <see cref="AuthenticationUnavailableException"/> if the backend is down.</summary>
    Task<AuthResult?> AuthenticateAsync(string username, string password, CancellationToken cancellationToken);
}

public static class HarpoClaims
{
    public const string DisplayName = "harpo:displayname";
    public const string SiteAdminRole = "HarpoSiteAdmin";

    public static ClaimsPrincipal CreatePrincipal(AuthResult result)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, result.Username),
            new(ClaimTypes.Name, result.Username),
            new(DisplayName, result.DisplayName),
        };
        if (result.IsSiteAdmin)
        {
            claims.Add(new Claim(ClaimTypes.Role, SiteAdminRole));
        }
        var identity = new ClaimsIdentity(claims, authenticationType: "Harpo");
        return new ClaimsPrincipal(identity);
    }
}
