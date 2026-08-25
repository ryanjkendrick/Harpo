using System.Security.Cryptography;
using Harpo.Data;
using Harpo.Security;

namespace Harpo.Tests;

public class CryptoTests
{
    [Fact]
    public void Encrypt_then_decrypt_roundtrips()
    {
        var crypto = new CryptoService("some passphrase");
        var secret = "hunter2 🦄 with unicode";
        var encrypted = crypto.Encrypt(secret);

        Assert.NotEqual(secret, encrypted);
        Assert.Equal(secret, crypto.Decrypt(encrypted));
    }

    [Fact]
    public void Same_plaintext_encrypts_differently_each_time()
    {
        var crypto = new CryptoService("some passphrase");
        Assert.NotEqual(crypto.Encrypt("secret"), crypto.Encrypt("secret"));
    }

    [Fact]
    public void Two_instances_with_same_passphrase_interoperate()
    {
        // This is what cross-site replication relies on.
        var siteA = new CryptoService("shared key");
        var siteB = new CryptoService("shared key");
        Assert.Equal("secret", siteB.Decrypt(siteA.Encrypt("secret")));
    }

    [Fact]
    public void Base64_32_byte_key_is_used_directly_and_interoperates()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var siteA = new CryptoService(key);
        var siteB = new CryptoService(key);
        Assert.Equal("secret", siteB.Decrypt(siteA.Encrypt("secret")));
    }

    [Fact]
    public void Tampered_ciphertext_is_rejected()
    {
        var crypto = new CryptoService("some passphrase");
        var blob = Convert.FromBase64String(crypto.Encrypt("secret"));
        blob[^1] ^= 0x01;
        var tampered = Convert.ToBase64String(blob);

        Assert.ThrowsAny<CryptographicException>(() => crypto.Decrypt(tampered));
    }

    [Fact]
    public void Wrong_key_cannot_decrypt()
    {
        var right = new CryptoService("right key");
        var wrong = new CryptoService("wrong key");
        var encrypted = right.Encrypt("secret");

        Assert.ThrowsAny<CryptographicException>(() => wrong.Decrypt(encrypted));
    }

    [Fact]
    public void Empty_master_key_is_rejected()
    {
        Assert.Throws<InvalidOperationException>(() => new CryptoService("  "));
    }

    [Fact]
    public void Generated_passwords_have_all_character_classes()
    {
        for (var i = 0; i < 50; i++)
        {
            var password = PasswordGenerator.Generate(20);
            Assert.Equal(20, password.Length);
            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, c => !char.IsLetterOrDigit(c));
        }
    }

    [Fact]
    public void Generator_options_control_length_and_character_classes()
    {
        for (var i = 0; i < 20; i++)
        {
            var digitsOnly = PasswordGenerator.Generate(new PasswordGeneratorOptions
            {
                Length = 32,
                Uppercase = false,
                Lowercase = false,
                Digits = true,
                Symbols = false,
            });
            Assert.Equal(32, digitsOnly.Length);
            Assert.All(digitsOnly, c => Assert.True(char.IsDigit(c)));

            var noSymbols = PasswordGenerator.Generate(new PasswordGeneratorOptions { Symbols = false, Length = 16 });
            Assert.All(noSymbols, c => Assert.True(char.IsLetterOrDigit(c)));
            Assert.Contains(noSymbols, char.IsUpper);
            Assert.Contains(noSymbols, char.IsLower);
            Assert.Contains(noSymbols, char.IsDigit);
        }
    }

    [Fact]
    public void Ambiguous_characters_follow_the_toggle()
    {
        const string ambiguous = "O0Il1";
        for (var i = 0; i < 30; i++)
        {
            var safe = PasswordGenerator.Generate(new PasswordGeneratorOptions { Length = 64 });
            Assert.DoesNotContain(safe, c => ambiguous.Contains(c));
        }
        // With the toggle off the full alphabets are in play — over enough draws
        // an ambiguous character must appear.
        var sawAmbiguous = Enumerable.Range(0, 50)
            .Select(_ => PasswordGenerator.Generate(new PasswordGeneratorOptions { Length = 64, ExcludeAmbiguous = false }))
            .Any(p => p.Any(c => ambiguous.Contains(c)));
        Assert.True(sawAmbiguous);
    }

    [Fact]
    public void Generator_is_safe_at_the_edges()
    {
        // Length clamps rather than throwing.
        Assert.Equal(8, PasswordGenerator.Generate(new PasswordGeneratorOptions { Length = 3 }).Length);
        Assert.Equal(128, PasswordGenerator.Generate(new PasswordGeneratorOptions { Length = 500 }).Length);

        // Every class disabled falls back to lowercase instead of failing.
        var fallback = PasswordGenerator.Generate(new PasswordGeneratorOptions
        {
            Uppercase = false,
            Lowercase = false,
            Digits = false,
            Symbols = false,
        });
        Assert.All(fallback, c => Assert.True(char.IsLower(c)));
    }

    [Fact]
    public void Deterministic_guids_are_stable_and_distinct()
    {
        var a1 = DeterministicGuid.For("group-1", "alice");
        var a2 = DeterministicGuid.For("group-1", "alice");
        var b = DeterministicGuid.For("group-1", "bob");
        var other = DeterministicGuid.For("group-2", "alice");

        Assert.Equal(a1, a2);
        Assert.NotEqual(a1, b);
        Assert.NotEqual(a1, other);
    }

    [Fact]
    public void Ldap_filter_values_are_escaped()
    {
        Assert.Equal(@"j\2asmith\28\29\5c", LdapAuthenticator.EscapeFilterValue(@"j*smith()\"));
    }
}
