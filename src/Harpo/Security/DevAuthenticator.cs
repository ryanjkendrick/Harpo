using System.Security.Cryptography;
using System.Text;

namespace Harpo.Security;

public class DevAuthOptions
{
    public List<DevUser> DevUsers { get; set; } = new();

    public class DevUser
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public bool IsSiteAdmin { get; set; }
        /// <summary>Stands in for an account disabled in AD: it cannot sign in or be added to a group.</summary>
        public bool Disabled { get; set; }
    }
}

/// <summary>
/// Development-only authenticator backed by users listed in configuration
/// (<c>Auth:DevUsers</c>). Lets you run Harpo without a domain controller.
/// Never enable in production — Program.cs logs a loud warning when active.
/// </summary>
public class DevAuthenticator : IAuthenticator, IDirectory
{
    private readonly DevAuthOptions _options;

    public DevAuthenticator(Microsoft.Extensions.Options.IOptions<DevAuthOptions> options)
    {
        _options = options.Value;
    }

    public Task<AuthResult?> AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
    {
        var normalized = username.Trim().ToLowerInvariant();
        foreach (var user in _options.DevUsers)
        {
            if (user.Username.ToLowerInvariant() == normalized && FixedTimeEquals(user.Password, password) && !user.Disabled)
            {
                return Task.FromResult<AuthResult?>(new AuthResult(normalized, DisplayNameOf(user), user.IsSiteAdmin));
            }
        }
        return Task.FromResult<AuthResult?>(null);
    }

    /// <summary>
    /// The configured user list is the "directory": a user still listed is
    /// active (with their current admin flag), a user no longer listed counts as
    /// disabled. This is what the session tests drive.
    /// </summary>
    public Task<RevalidationResult> RevalidateAsync(string username, CancellationToken cancellationToken)
    {
        var normalized = username.Trim().ToLowerInvariant();
        var user = _options.DevUsers.FirstOrDefault(u => u.Username.ToLowerInvariant() == normalized);
        return Task.FromResult(user is null || user.Disabled
            ? RevalidationResult.Disabled
            : RevalidationResult.Active(user.IsSiteAdmin));
    }

    /// <summary>The configured user list is always available, so the answer is Found or NotFound.</summary>
    public Task<DirectoryLookup> LookupAccountAsync(string username, CancellationToken cancellationToken)
    {
        var normalized = username.Trim().ToLowerInvariant();
        var user = _options.DevUsers.FirstOrDefault(u => u.Username.ToLowerInvariant() == normalized);
        return Task.FromResult(user is null ? DirectoryLookup.NotFound : DirectoryLookup.Found(ToAccount(user)));
    }

    /// <summary>Same matching rules as the LDAP search: account-name prefix or display-name substring.</summary>
    public Task<DirectorySearchResult> SearchAccountsAsync(string term, int limit, CancellationToken cancellationToken)
    {
        term = term.Trim();
        if (term.Length == 0 || limit <= 0)
        {
            return Task.FromResult(new DirectorySearchResult(true, []));
        }
        var matches = _options.DevUsers
            .Select(ToAccount)
            .Where(a => a.Username.StartsWith(term, StringComparison.OrdinalIgnoreCase)
                || a.DisplayName.Contains(term, StringComparison.OrdinalIgnoreCase))
            .OrderBy(a => a.Username, StringComparer.Ordinal)
            .Take(limit)
            .ToList();
        return Task.FromResult(new DirectorySearchResult(true, matches));
    }

    private static DirectoryAccount ToAccount(DevAuthOptions.DevUser user) =>
        new(user.Username.Trim().ToLowerInvariant(), DisplayNameOf(user), user.Disabled);

    private static string DisplayNameOf(DevAuthOptions.DevUser user) =>
        string.IsNullOrWhiteSpace(user.DisplayName) ? user.Username : user.DisplayName;

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
