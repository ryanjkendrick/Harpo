using Harpo.Security;

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
}
