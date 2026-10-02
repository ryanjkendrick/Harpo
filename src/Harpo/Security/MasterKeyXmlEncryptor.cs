using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace Harpo.Security;

/// <summary>
/// Encrypts the ASP.NET Core Data Protection key ring at rest with the Harpo
/// master key (<c>Harpo:MasterKey</c>), via <see cref="CryptoService"/>.
///
/// Those keys sign and encrypt the auth cookie and antiforgery tokens. They are
/// persisted to <c>Harpo:DataProtectionKeysPath</c> (the <c>/data</c> volume),
/// which SQLCipher database-file encryption does NOT cover — so without this a
/// stolen volume or backup hands over the keys to mint a valid session cookie
/// (including a site admin's) against any reachable instance. Wrapping the ring
/// with the master key means a copied volume is useless without the master key,
/// which lives only in configuration/secrets, never in <c>/data</c>.
///
/// Keys already written in the clear (an upgrade from before this existed) stay
/// readable — Data Protection reads unencrypted and encrypted elements side by
/// side — and are replaced by encrypted ones as the ring rolls. Because
/// <see cref="CryptoService.Decrypt"/> also tries the previous master keys, the
/// ring survives a staged master key rotation.
///
/// The decryptor type is recorded in the stored XML, so keep this type's name
/// and namespace stable; renaming it would orphan keys already encrypted with it.
/// </summary>
public sealed class MasterKeyXmlEncryptor : IXmlEncryptor
{
    private readonly CryptoService _crypto;

    public MasterKeyXmlEncryptor(CryptoService crypto) => _crypto = crypto;

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);
        var blob = _crypto.Encrypt(plaintextElement.ToString(SaveOptions.DisableFormatting));
        var encrypted = new XElement("encryptedKey",
            new XComment(" Data Protection key, encrypted by Harpo with the master key. "),
            new XElement("value", blob));
        return new EncryptedXmlInfo(encrypted, typeof(MasterKeyXmlDecryptor));
    }
}

/// <summary>Counterpart to <see cref="MasterKeyXmlEncryptor"/>. Instantiated by Data Protection via the service provider.</summary>
public sealed class MasterKeyXmlDecryptor : IXmlDecryptor
{
    private readonly CryptoService _crypto;

    // Data Protection always supplies the IServiceProvider when activating a
    // decryptor; resolve the master key from it rather than requiring a
    // parameterless ctor.
    public MasterKeyXmlDecryptor(IServiceProvider services)
        => _crypto = services.GetRequiredService<CryptoService>();

    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);
        var blob = encryptedElement.Element("value")?.Value
            ?? throw new InvalidOperationException("Encrypted Data Protection key is missing its <value> element.");
        return XElement.Parse(_crypto.Decrypt(blob));
    }
}
