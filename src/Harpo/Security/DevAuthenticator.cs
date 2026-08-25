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
    }
}

/// <summary>
/// Development-only authenticator backed by users listed in configuration
/// (<c>Auth:DevUsers</c>). Lets you run Harpo without a domain controller.
/// Never enable in production — Program.cs logs a loud warning when active.
/// </summary>
public class DevAuthenticator : IAuthenticator
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
            if (user.Username.ToLowerInvariant() == normalized && FixedTimeEquals(user.Password, password))
            {
                var displayName = string.IsNullOrWhiteSpace(user.DisplayName) ? user.Username : user.DisplayName;
                return Task.FromResult<AuthResult?>(new AuthResult(normalized, displayName, user.IsSiteAdmin));
            }
        }
        return Task.FromResult<AuthResult?>(null);
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
