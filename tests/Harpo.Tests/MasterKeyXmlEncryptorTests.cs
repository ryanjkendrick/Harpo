using System.Xml.Linq;
using Harpo.Security;
using Microsoft.Extensions.DependencyInjection;

namespace Harpo.Tests;

public class MasterKeyXmlEncryptorTests
{
    private static MasterKeyXmlDecryptor DecryptorFor(CryptoService crypto) =>
        new(new ServiceCollection().AddSingleton(crypto).BuildServiceProvider());

    [Fact]
    public void Round_trips_a_key_element_through_the_master_key()
    {
        var crypto = new CryptoService("a-master-key");
        var original = new XElement("key",
            new XAttribute("id", Guid.NewGuid()),
            new XElement("descriptor", new XElement("secret", "AQIDBA==")));

        var encrypted = new MasterKeyXmlEncryptor(crypto).Encrypt(original).EncryptedElement;

        // The wrapped form must not leak the plaintext element's contents.
        Assert.DoesNotContain("AQIDBA==", encrypted.ToString());
        Assert.Equal("encryptedKey", encrypted.Name.LocalName);

        var decrypted = DecryptorFor(crypto).Decrypt(encrypted);
        Assert.Equal(original.ToString(SaveOptions.DisableFormatting), decrypted.ToString(SaveOptions.DisableFormatting));
    }

    [Fact]
    public void Decryptor_falls_back_to_a_previous_master_key_so_the_ring_survives_rotation()
    {
        var oldCrypto = new CryptoService("old-master-key");
        var element = new XElement("key", new XElement("secret", "sentinel-value"));
        var encrypted = new MasterKeyXmlEncryptor(oldCrypto).Encrypt(element).EncryptedElement;

        // After a staged rotation the old key is kept as a previous key; the ring,
        // written under the old key, must still decrypt.
        var rotated = new CryptoService("new-master-key", ["old-master-key"]);
        var decrypted = DecryptorFor(rotated).Decrypt(encrypted);
        Assert.Equal("sentinel-value", decrypted.Element("secret")!.Value);
    }

    [Fact]
    public void A_key_encrypted_under_an_unknown_master_key_cannot_be_read()
    {
        var encrypted = new MasterKeyXmlEncryptor(new CryptoService("real-key")).Encrypt(
            new XElement("key", new XElement("secret", "x"))).EncryptedElement;

        Assert.ThrowsAny<Exception>(() => DecryptorFor(new CryptoService("a-different-key")).Decrypt(encrypted));
    }
}
