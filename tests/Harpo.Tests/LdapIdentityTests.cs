using Harpo.Security;
using Microsoft.Extensions.Logging;

namespace Harpo.Tests;

/// <summary>
/// The pure parts of turning a sign-in into an identity. Which account a bind
/// authenticated can only be proven against a directory (the Samba AD lab);
/// these pin down that the typed text only ever chooses the bind name, and that
/// the identity is read from the directory's answer or not at all.
/// </summary>
public class LdapIdentityTests
{
    [Theory]
    [InlineData("jsmith", "corp.example.com", "jsmith@corp.example.com")]
    [InlineData("  jsmith  ", "corp.example.com", "jsmith@corp.example.com")]
    [InlineData("jsmith@corp.example.com", "corp.example.com", "jsmith@corp.example.com")]
    // An alternate suffix, or a UPN whose prefix is not the account name, is
    // passed through untouched: only the directory knows whose it is.
    [InlineData("ada@review.example", "corp.example.com", "ada@review.example")]
    [InlineData("ada.admin@corp.example.com", "corp.example.com", "ada.admin@corp.example.com")]
    [InlineData(@"CORP\jsmith", "corp.example.com", @"CORP\jsmith")]
    [InlineData("jsmith", "", "jsmith")]
    [InlineData("jsmith", null, "jsmith")]
    public void Bind_name_qualifies_only_a_bare_name(string typed, string? suffix, string expected)
    {
        Assert.Equal(expected, LdapAuthenticator.BindName(typed, suffix));
    }

    [Theory]
    [InlineData(@"u:HARPO\grace", "grace")]
    [InlineData(@"u:CORP\J.Smith", "J.Smith")]
    [InlineData("u:grace", "grace")]
    public void Who_am_i_answer_names_the_account(string authzId, string expected)
    {
        Assert.Equal(expected, LdapAuthenticator.AccountFromAuthzId(authzId));
    }

    [Theory]
    [InlineData(null)] // anonymous: RFC 4532 sends no value
    [InlineData("")]
    [InlineData("u:")]
    [InlineData(@"u:HARPO\")]
    [InlineData("dn:CN=Grace Hopper,CN=Users,DC=harpo,DC=lab")] // not AD's form; never guessed at
    [InlineData("ada@review.example")]
    [InlineData("u:ada@review.example")]
    public void Unusable_who_am_i_answer_names_no_account(string? authzId)
    {
        Assert.Null(LdapAuthenticator.AccountFromAuthzId(authzId));
    }

    private const string RealGroup = "CN=Harpo Admins,OU=Groups,DC=corp,DC=example,DC=com";
    private const string SameNameElsewhere = "CN=Harpo Admins,OU=Branch,DC=corp,DC=example,DC=com";

    [Theory]
    [InlineData(RealGroup, RealGroup, true)]
    [InlineData("cn=harpo admins,ou=groups,dc=corp,dc=example,dc=com", RealGroup, true)] // case does not matter
    [InlineData(RealGroup, SameNameElsewhere, false)]                                    // the point of using a full DN
    [InlineData("CN=Harpo Admins, OU=Groups,DC=corp,DC=example,DC=com", RealGroup, false)] // not guessed at: nobody gets in
    [InlineData("Harpo Admins", RealGroup, true)]
    [InlineData("Harpo Admins", SameNameElsewhere, true)]                                // why a short name draws a warning
    [InlineData("harpo admins", RealGroup, true)]
    [InlineData("Harpo Admins", @"CN=Harpo Admins\, Rogue,OU=Branch,DC=corp,DC=example,DC=com", false)]
    [InlineData("Harpo Admins", "CN=Other,OU=Harpo Admins,DC=corp,DC=example,DC=com", false)]
    [InlineData("", RealGroup, false)]
    [InlineData("  ", RealGroup, false)]
    public void Admin_group_setting_against_a_membership(string setting, string memberOf, bool expected)
    {
        Assert.Equal(expected, LdapAuthenticator.IsAdminGroupMember([memberOf], setting));
    }

    [Fact]
    public void Admin_group_is_found_among_several_and_absent_without_any()
    {
        Assert.True(LdapAuthenticator.IsAdminGroupMember(["CN=Staff,DC=corp", RealGroup], RealGroup));
        Assert.False(LdapAuthenticator.IsAdminGroupMember([], RealGroup));
    }

    [Theory]
    [InlineData("Harpo Admins", true)]
    [InlineData(RealGroup, false)]
    [InlineData("", false)] // no admin group is not a risky one
    [InlineData("  ", false)]
    public void Only_a_short_admin_group_name_draws_the_warning(string setting, bool warned)
    {
        var logger = new RecordingLogger();
        _ = new LdapAuthenticator(
            Microsoft.Extensions.Options.Options.Create(new LdapOptions { Server = "dc01", AdminGroup = setting }), logger);

        Assert.Equal(warned, logger.Warnings.Any(w => w.Contains("Auth:Ldap:AdminGroup") && w.Contains("full DN")));
    }

    private sealed class RecordingLogger : ILogger<LdapAuthenticator>
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
            }
        }
    }
}
