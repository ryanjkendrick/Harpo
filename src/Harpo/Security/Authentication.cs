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

/// <summary>What the directory says about an account that already holds a session.</summary>
public enum DirectoryAccountStatus
{
    /// <summary>The account exists and is enabled; <see cref="RevalidationResult.IsSiteAdmin"/> is current.</summary>
    Active,

    /// <summary>The account is disabled or no longer exists: its sessions end.</summary>
    Disabled,

    /// <summary>
    /// The directory cannot be asked without the user's password (no service
    /// account configured). Nothing is learned; the session lives until it
    /// expires or the user signs out.
    /// </summary>
    Unknown,

    /// <summary>
    /// The directory could not be reached, or refused the service account.
    /// Retried at every sweep; the session survives this for a bounded grace
    /// period (<c>Auth:RevalidateGraceMinutes</c>).
    /// </summary>
    Unavailable,
}

public sealed record RevalidationResult(DirectoryAccountStatus Status, bool IsSiteAdmin = false)
{
    public static readonly RevalidationResult Disabled = new(DirectoryAccountStatus.Disabled);
    public static readonly RevalidationResult Unknown = new(DirectoryAccountStatus.Unknown);
    public static readonly RevalidationResult Unavailable = new(DirectoryAccountStatus.Unavailable);

    public static RevalidationResult Active(bool isSiteAdmin) => new(DirectoryAccountStatus.Active, isSiteAdmin);
}

public interface IAuthenticator
{
    /// <summary>Returns null for invalid credentials; throws <see cref="AuthenticationUnavailableException"/> if the backend is down.</summary>
    Task<AuthResult?> AuthenticateAsync(string username, string password, CancellationToken cancellationToken);

    /// <summary>
    /// Re-checks an already signed-in account <b>without its password</b>: is it
    /// still enabled, and is it still a site admin? Called by
    /// <see cref="Harpo.Services.SessionService"/> every <c>Auth:RevalidateMinutes</c>.
    /// Directory trouble is reported as <see cref="DirectoryAccountStatus.Unavailable"/>, not thrown.
    /// </summary>
    Task<RevalidationResult> RevalidateAsync(string username, CancellationToken cancellationToken);
}

/// <summary>An account as the directory describes it.</summary>
/// <param name="Username">The lower-cased <c>sAMAccountName</c> (the dev user name in Development mode).</param>
/// <param name="DisplayName">The directory's display name, or the account name when it has none.</param>
/// <param name="Disabled">Whether the account is disabled (AD's ACCOUNTDISABLE flag).</param>
public sealed record DirectoryAccount(string Username, string DisplayName, bool Disabled);

public enum DirectoryLookupStatus
{
    /// <summary>Exactly one account has that name; see <see cref="DirectoryLookup.Account"/>.</summary>
    Found,

    /// <summary>The directory was asked and has no such account under its search base.</summary>
    NotFound,

    /// <summary>
    /// More than one account answers to the name (possible only when the search
    /// base spans several domains). Nothing is assumed about which was meant.
    /// </summary>
    Ambiguous,

    /// <summary>
    /// The directory cannot be asked: no service account is configured, or the
    /// server could not be reached or refused the service account. Nothing was learned.
    /// </summary>
    Unavailable,
}

public sealed record DirectoryLookup(DirectoryLookupStatus Status, DirectoryAccount? Account = null)
{
    public static readonly DirectoryLookup NotFound = new(DirectoryLookupStatus.NotFound);
    public static readonly DirectoryLookup Ambiguous = new(DirectoryLookupStatus.Ambiguous);
    public static readonly DirectoryLookup Unavailable = new(DirectoryLookupStatus.Unavailable);

    public static DirectoryLookup Found(DirectoryAccount account) => new(DirectoryLookupStatus.Found, account);
}

/// <summary>
/// Suggestions for a search term. <see cref="Available"/> is false when the
/// directory could not be asked at all, so "no matches" and "could not look"
/// are never confused.
/// </summary>
public sealed record DirectorySearchResult(bool Available, IReadOnlyList<DirectoryAccount> Accounts)
{
    public static readonly DirectorySearchResult Unavailable = new(false, []);
}

/// <summary>
/// Read-only questions about accounts other than the signed-in user's, asked
/// without any user's password — what group admins need to add the right
/// person. Both authenticators implement it: LDAP through the optional service
/// account (Unavailable without one), Development mode from its user list.
/// Directory trouble is reported as Unavailable, never thrown.
/// </summary>
public interface IDirectory
{
    /// <summary>The account whose <c>sAMAccountName</c> is exactly <paramref name="username"/> (case-insensitive).</summary>
    Task<DirectoryLookup> LookupAccountAsync(string username, CancellationToken cancellationToken);

    /// <summary>
    /// Up to <paramref name="limit"/> accounts whose <c>sAMAccountName</c> starts
    /// with <paramref name="term"/> or whose display name contains it, case-insensitively,
    /// ordered by account name.
    /// </summary>
    Task<DirectorySearchResult> SearchAccountsAsync(string term, int limit, CancellationToken cancellationToken);
}

public static class HarpoClaims
{
    public const string DisplayName = "harpo:displayname";
    public const string SiteAdminRole = "HarpoSiteAdmin";

    /// <summary>
    /// Id of the server-side session (a <see cref="Harpo.Data.UserSession"/> row)
    /// the sign-in created. The cookie is honoured only while that row exists;
    /// see <see cref="Harpo.Services.SessionService"/>.
    /// </summary>
    public const string SessionId = "harpo:sid";

    public static ClaimsPrincipal CreatePrincipal(AuthResult result, string sessionId)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, result.Username),
            new(ClaimTypes.Name, result.Username),
            new(DisplayName, result.DisplayName),
            new(SessionId, sessionId),
        };
        if (result.IsSiteAdmin)
        {
            claims.Add(new Claim(ClaimTypes.Role, SiteAdminRole));
        }
        var identity = new ClaimsIdentity(claims, authenticationType: "Harpo");
        return new ClaimsPrincipal(identity);
    }
}
