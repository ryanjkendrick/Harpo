using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;

namespace Harpo.Security;

public class LdapOptions
{
    /// <summary>Domain controller hostname or IP, e.g. "dc01.corp.example.com".</summary>
    public string Server { get; set; } = "";
    public int Port { get; set; } = 636;
    /// <summary>Use LDAPS. Strongly recommended: with plain LDAP the bind sends credentials in the clear.</summary>
    public bool UseSsl { get; set; } = true;
    /// <summary>Accept any server certificate (lab setups only).</summary>
    public bool SkipCertificateValidation { get; set; }
    /// <summary>UPN suffix appended for the bind when the user types a bare account name, e.g. "corp.example.com" → jsmith@corp.example.com.</summary>
    public string UpnSuffix { get; set; } = "";
    /// <summary>Search base for user lookups, e.g. "DC=corp,DC=example,DC=com".</summary>
    public string SearchBase { get; set; } = "";
    /// <summary>AD group whose members are Harpo site admins. Either a plain CN ("Harpo Admins") or a full DN.</summary>
    public string AdminGroup { get; set; } = "";
    public int TimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// Optional, read-only directory account used only to re-check signed-in
    /// users (enabled? still in the admin group?) without their passwords —
    /// a UPN ("svc-harpo@corp.example.com"), DOMAIN\name, or DN. Sign-in itself
    /// never uses it. Without it, a disabled account keeps its existing Harpo
    /// session until that session expires or the user signs out.
    /// </summary>
    public string ServiceUser { get; set; } = "";
    /// <summary>Password of <see cref="ServiceUser"/> (or <c>Auth:Ldap:ServicePassword__File</c>).</summary>
    public string ServicePassword { get; set; } = "";
}

/// <summary>
/// Validates credentials by performing an LDAP simple bind against Active Directory
/// as the user, then reads the user's entry for display name and group membership.
/// Works cross-platform (Linux containers included) via System.DirectoryServices.Protocols.
/// </summary>
public class LdapAuthenticator : IAuthenticator
{
    private readonly LdapOptions _options;
    private readonly ILogger<LdapAuthenticator> _logger;

    public LdapAuthenticator(Microsoft.Extensions.Options.IOptions<LdapOptions> options, ILogger<LdapAuthenticator> logger)
    {
        _options = options.Value;
        _logger = logger;
        if (string.IsNullOrWhiteSpace(_options.Server))
        {
            throw new InvalidOperationException(
                "Auth:Mode is 'Ldap' but Auth:Ldap:Server is not configured. " +
                "Set the Auth:Ldap:* settings, or use Auth:Mode=Development for local testing.");
        }

        if (!string.IsNullOrWhiteSpace(_options.ServiceUser))
        {
            if (string.IsNullOrEmpty(_options.ServicePassword))
            {
                // AD treats a bind with an empty password as anonymous — which
                // would "succeed" and then read nothing useful. Refuse to start.
                throw new InvalidOperationException(
                    "Auth:Ldap:ServiceUser is set but Auth:Ldap:ServicePassword is empty.");
            }
            if (string.IsNullOrWhiteSpace(_options.SearchBase))
            {
                throw new InvalidOperationException(
                    "Auth:Ldap:ServiceUser is set but Auth:Ldap:SearchBase is empty — revalidation needs somewhere to look users up.");
            }
        }

        if (_options.SkipCertificateValidation && !OperatingSystem.IsWindows())
        {
            // On Linux/macOS S.DS.P delegates TLS to libldap, which never calls the
            // .NET VerifyServerCertificate callback — certificate checking is
            // controlled by LDAPTLS_REQCERT instead. Set it before the first bind.
            Environment.SetEnvironmentVariable("LDAPTLS_REQCERT", "never");
            _logger.LogWarning(
                "LDAP server certificate validation is DISABLED (Auth:Ldap:SkipCertificateValidation). Lab use only.");
        }
    }

    public Task<AuthResult?> AuthenticateAsync(string username, string password, CancellationToken cancellationToken)
    {
        // S.DS.P is synchronous; run it off the caller's thread.
        return Task.Run(() => Authenticate(username, password), cancellationToken);
    }

    private AuthResult? Authenticate(string username, string password)
    {
        username = username.Trim();
        if (username.Length == 0 || password.Length == 0)
        {
            return null; // AD treats an empty password bind as anonymous — never allow it.
        }

        // Users may type "jsmith", "jsmith@corp.example.com" or "CORP\jsmith".
        var bareUsername = username;
        var slash = bareUsername.LastIndexOf('\\');
        if (slash >= 0)
        {
            bareUsername = bareUsername[(slash + 1)..];
        }
        var at = bareUsername.IndexOf('@');
        if (at >= 0)
        {
            bareUsername = bareUsername[..at];
        }
        bareUsername = bareUsername.ToLowerInvariant();

        var bindUser = username.Contains('@') || username.Contains('\\')
            ? username
            : string.IsNullOrWhiteSpace(_options.UpnSuffix) ? username : $"{username}@{_options.UpnSuffix}";

        try
        {
            using var connection = CreateConnection();
            connection.Credential = new NetworkCredential(bindUser, password);
            connection.Bind(); // throws LdapException 49 on bad credentials

            var (displayName, isAdmin) = LookupUser(connection, bareUsername);
            return new AuthResult(bareUsername, displayName, isAdmin);
        }
        catch (LdapException ex) when (ex.ErrorCode == 49) // invalid credentials
        {
            _logger.LogInformation("Failed login attempt for {Username}", bareUsername);
            return null;
        }
        catch (LdapException ex)
        {
            _logger.LogError(ex, "LDAP error {Code} talking to {Server}", ex.ErrorCode, _options.Server);
            throw new AuthenticationUnavailableException(
                "The directory server could not be reached. Try again or contact an administrator.", ex);
        }
        catch (Exception ex) when (ex is not AuthenticationUnavailableException)
        {
            _logger.LogError(ex, "Unexpected error talking to {Server}", _options.Server);
            throw new AuthenticationUnavailableException(
                "The directory server could not be reached. Try again or contact an administrator.", ex);
        }
    }

    private LdapConnection CreateConnection()
    {
        var identifier = new LdapDirectoryIdentifier(_options.Server, _options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        var connection = new LdapConnection(identifier)
        {
            AuthType = AuthType.Basic,
            Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds),
        };
        connection.SessionOptions.ProtocolVersion = 3;
        if (_options.UseSsl)
        {
            connection.SessionOptions.SecureSocketLayer = true;
            if (_options.SkipCertificateValidation && OperatingSystem.IsWindows())
            {
                // Windows only — on other platforms LDAPTLS_REQCERT is set in the ctor.
                connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
            }
        }
        return connection;
    }

    private (string DisplayName, bool IsAdmin) LookupUser(LdapConnection connection, string bareUsername)
    {
        var displayName = bareUsername;
        var isAdmin = false;
        if (string.IsNullOrWhiteSpace(_options.SearchBase))
        {
            return (displayName, isAdmin);
        }

        var filter = $"(&(objectClass=user)(sAMAccountName={EscapeFilterValue(bareUsername)}))";
        var request = new SearchRequest(
            _options.SearchBase,
            filter,
            SearchScope.Subtree,
            "displayName", "cn", "memberOf");
        var response = (SearchResponse)connection.SendRequest(request);
        if (response.Entries.Count == 0)
        {
            return (displayName, isAdmin);
        }

        var entry = response.Entries[0];
        displayName = GetString(entry, "displayName") ?? GetString(entry, "cn") ?? bareUsername;
        isAdmin = IsInAdminGroup(entry);
        return (displayName, isAdmin);
    }

    private bool IsInAdminGroup(SearchResultEntry entry)
    {
        if (string.IsNullOrWhiteSpace(_options.AdminGroup) || !entry.Attributes.Contains("memberOf"))
        {
            return false;
        }
        var wanted = _options.AdminGroup;
        foreach (var value in entry.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>())
        {
            if (string.Equals(value, wanted, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(FirstRdnValue(value), wanted, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>AD's ACCOUNTDISABLE bit in userAccountControl.</summary>
    private const long AccountDisabledFlag = 0x2;

    /// <summary>
    /// Harpo binds as the user and keeps no password, so it cannot ask the
    /// directory about a signed-in user on its own. With a service account
    /// configured it can: bind as that account, read the user's
    /// userAccountControl and memberOf. Without one the answer is Unknown and
    /// sessions are bounded only by their lifetime (see README, Security model).
    /// </summary>
    public Task<RevalidationResult> RevalidateAsync(string username, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ServiceUser))
        {
            return Task.FromResult(RevalidationResult.Unknown);
        }
        // S.DS.P is synchronous; run it off the caller's thread.
        return Task.Run(() => Revalidate(username), cancellationToken);
    }

    private RevalidationResult Revalidate(string username)
    {
        var bareUsername = username.Trim().ToLowerInvariant();
        try
        {
            using var connection = CreateConnection();
            connection.Credential = new NetworkCredential(ServiceBindName(), _options.ServicePassword);
            connection.Bind();

            var filter = $"(&(objectClass=user)(sAMAccountName={EscapeFilterValue(bareUsername)}))";
            var request = new SearchRequest(
                _options.SearchBase, filter, SearchScope.Subtree, "userAccountControl", "memberOf");
            var response = (SearchResponse)connection.SendRequest(request);
            if (response.Entries.Count == 0)
            {
                // Deleted, renamed, or moved out of the search base: whoever
                // signed in under this name is no longer someone we can vouch for.
                return RevalidationResult.Disabled;
            }
            var entry = response.Entries[0];
            if (!long.TryParse(GetString(entry, "userAccountControl"), out var flags))
            {
                // The service account cannot read the attribute; we learned nothing.
                _logger.LogWarning(
                    "Revalidating {User}: userAccountControl not readable by Auth:Ldap:ServiceUser", bareUsername);
                return RevalidationResult.Unavailable;
            }
            if ((flags & AccountDisabledFlag) != 0)
            {
                return RevalidationResult.Disabled;
            }
            return RevalidationResult.Active(IsInAdminGroup(entry));
        }
        catch (LdapException ex) when (ex.ErrorCode == 49)
        {
            _logger.LogError(
                "The directory rejected Auth:Ldap:ServiceUser's credentials; signed-in users cannot be revalidated");
            return RevalidationResult.Unavailable;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Revalidating {User}: directory server {Server} unavailable", bareUsername, _options.Server);
            return RevalidationResult.Unavailable;
        }
    }

    private string ServiceBindName()
    {
        var name = _options.ServiceUser.Trim();
        return name.Contains('@') || name.Contains('\\') || name.Contains('=') || string.IsNullOrWhiteSpace(_options.UpnSuffix)
            ? name
            : $"{name}@{_options.UpnSuffix}";
    }

    private static string? GetString(SearchResultEntry entry, string attribute)
    {
        if (!entry.Attributes.Contains(attribute))
        {
            return null;
        }
        var values = entry.Attributes[attribute].GetValues(typeof(string));
        return values.Length > 0 ? (string)values[0] : null;
    }

    /// <summary>Extracts "Harpo Admins" from "CN=Harpo Admins,OU=Groups,DC=corp,...".</summary>
    private static string FirstRdnValue(string dn)
    {
        var end = dn.IndexOf(',');
        var rdn = end >= 0 ? dn[..end] : dn;
        var eq = rdn.IndexOf('=');
        return eq >= 0 ? rdn[(eq + 1)..].Trim() : rdn.Trim();
    }

    /// <summary>RFC 4515 escaping for values placed inside an LDAP search filter.</summary>
    public static string EscapeFilterValue(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append(@"\5c"); break;
                case '*': sb.Append(@"\2a"); break;
                case '(': sb.Append(@"\28"); break;
                case ')': sb.Append(@"\29"); break;
                case '\0': sb.Append(@"\00"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}
