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
}

/// <summary>
/// Validates credentials by performing an LDAP simple bind against Active Directory
/// as the user, asks the directory which account that bind authenticated, then reads
/// that account's entry for its name, display name and group membership.
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

        var bindUser = BindName(username, _options.UpnSuffix);

        try
        {
            using var connection = CreateConnection();
            connection.Credential = new NetworkCredential(bindUser, password);
            connection.Bind(); // throws LdapException 49 on bad credentials

            // The directory accepts many names for one account — its UPN, a UPN
            // under an alternate suffix, name@domain, DOMAIN\name, its DN — and the
            // text before an "@" need not be that account's name, or may be someone
            // else's. So the typed text never decides who signed in: the directory
            // says which account this connection is bound as, and the identity,
            // display name and admin flag all come from that one object.
            var account = WhoAmI(connection);
            var result = account is null ? null : LookupUser(connection, account);
            if (result is null)
            {
                // The password was right, but we cannot say for certain whose it
                // was. Refuse rather than guess; the user sees the usual message.
                _logger.LogWarning("Could not resolve the signed-in account for {Username}; sign-in refused", username);
            }
            return result;
        }
        catch (LdapException ex) when (ex.ErrorCode == 49) // invalid credentials
        {
            _logger.LogInformation("Failed login attempt for {Username}", username);
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

    /// <summary>
    /// The name to bind with for what the user typed ("jsmith", "jsmith@corp.example.com"
    /// or "CORP\jsmith"): a bare name gets the configured UPN suffix, anything already
    /// qualified is passed through for the directory to interpret.
    /// </summary>
    internal static string BindName(string typed, string? upnSuffix)
    {
        typed = typed.Trim();
        if (typed.Contains('@') || typed.Contains('\\') || string.IsNullOrWhiteSpace(upnSuffix))
        {
            return typed;
        }
        return $"{typed}@{upnSuffix.Trim()}";
    }

    internal const string WhoAmIOid = "1.3.6.1.4.1.4203.1.11.3";

    /// <summary>
    /// Asks the directory which account the connection is bound as — the LDAP
    /// "Who am I?" operation (RFC 4532), which AD and Samba answer with
    /// "u:DOMAIN\sAMAccountName". Null when it gives no usable answer.
    /// </summary>
    private string? WhoAmI(LdapConnection connection)
    {
        try
        {
            var response = (ExtendedResponse)connection.SendRequest(new ExtendedRequest(WhoAmIOid));
            var authzId = response.ResponseValue is { Length: > 0 } value ? Encoding.UTF8.GetString(value) : null;
            var account = AccountFromAuthzId(authzId);
            if (account is null)
            {
                _logger.LogWarning("The directory's Who am I answer {AuthzId} names no account", authzId ?? "(empty)");
            }
            return account;
        }
        catch (DirectoryOperationException ex)
        {
            // The server refused the operation (it is not unreachable — the bind
            // just succeeded), so this is a failed sign-in, not an outage.
            _logger.LogWarning(ex, "The directory refused the Who am I operation ({Result})", ex.Response?.ResultCode);
            return null;
        }
    }

    /// <summary>
    /// The account name in a Who am I answer: "u:HARPO\grace" → "grace". Anything
    /// else — anonymous (empty), a "dn:" form, a malformed value — is null, so the
    /// sign-in fails rather than falling back to the typed name. The domain part is
    /// dropped because Harpo's identity is the bare sAMAccountName, which assumes
    /// one domain (see README, "Active Directory settings").
    /// </summary>
    internal static string? AccountFromAuthzId(string? authzId)
    {
        if (authzId is null || !authzId.StartsWith("u:", StringComparison.Ordinal))
        {
            return null;
        }
        var name = authzId[2..];
        var slash = name.LastIndexOf('\\');
        if (slash >= 0)
        {
            name = name[(slash + 1)..];
        }
        name = name.Trim();
        return name.Length == 0 || name.Contains('@') ? null : name;
    }

    /// <summary>
    /// Reads the bound account's entry. Exactly one entry must match: none (the
    /// account is outside SearchBase) or several (an ambiguous name) fails the
    /// sign-in rather than signing in someone the directory did not vouch for.
    /// </summary>
    private AuthResult? LookupUser(LdapConnection connection, string account)
    {
        if (string.IsNullOrWhiteSpace(_options.SearchBase))
        {
            // Nothing to read display name or groups from; the name still comes
            // from the directory's answer, not from what was typed.
            var name = account.ToLowerInvariant();
            return new AuthResult(name, name, false);
        }

        var filter = $"(&(objectClass=user)(sAMAccountName={EscapeFilterValue(account)}))";
        var request = new SearchRequest(
            _options.SearchBase,
            filter,
            SearchScope.Subtree,
            "sAMAccountName", "displayName", "cn", "memberOf");
        var response = (SearchResponse)connection.SendRequest(request);
        if (response.Entries.Count != 1)
        {
            _logger.LogWarning(
                "Expected one directory entry for the signed-in account {Account} under {SearchBase}, found {Count}",
                account, _options.SearchBase, response.Entries.Count);
            return null;
        }

        var entry = response.Entries[0];
        // Existing memberships are keyed on the lower-cased sAMAccountName.
        var username = (GetString(entry, "sAMAccountName") ?? account).ToLowerInvariant();
        var displayName = GetString(entry, "displayName") ?? GetString(entry, "cn") ?? username;
        var isAdmin = false;

        if (!string.IsNullOrWhiteSpace(_options.AdminGroup) && entry.Attributes.Contains("memberOf"))
        {
            var wanted = _options.AdminGroup;
            foreach (var value in entry.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>())
            {
                if (string.Equals(value, wanted, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(FirstRdnValue(value), wanted, StringComparison.OrdinalIgnoreCase))
                {
                    isAdmin = true;
                    break;
                }
            }
        }
        return new AuthResult(username, displayName, isAdmin);
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
