using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Xml.Linq;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class AsymmetricTests
{
    readonly string PlainText = @"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
    XDocument PublicKey = null;
    XDocument PrivateKey = null;

    [SetUp]
    public void Init()
    {
        var sut = new Asymmetric();
        PublicKey = sut.PublicKey;
        PrivateKey = sut.PrivateKey;
    }

    [Test]
    public void Encrypt_Decrypt_Equal()
    {
        var sut = new Asymmetric();
        var encryptedBytes = sut.Encrypt(PlainText);
        var decryptedText = sut.Decrypt(encryptedBytes);

        Assert.AreEqual(PlainText, decryptedText);
    }

    [Test]
    public void Encrypt_Decrypt_Existing_Key_Pair_Equal()
    {
        var encryptor = new Asymmetric(PublicKey);
        var decryptor = new Asymmetric(privateKey: PrivateKey);

        Assert.IsNull(encryptor.PrivateKey);
        Assert.IsNull(decryptor.PublicKey);

        var encryptedBytes = encryptor.Encrypt(PlainText);
        var decryptedText = decryptor.Decrypt(encryptedBytes);

        Assert.AreEqual(PlainText, decryptedText);
    }

    [Test]
    public void Encrypt_No_Public_Key_Exception()
    {
        var ex = Assert.Throws<CryptographicException>(() =>
        {
            var sut = new Asymmetric(privateKey: PrivateKey);
            sut.Encrypt(PlainText);
        });
        Assert.AreEqual("PublicKey missing.", ex.Message);
    }

    [Test]
    public void Decrypt_No_Private_Key_Exception()
    {
        var ex = Assert.Throws<CryptographicException>(() =>
        {
            var sut = new Asymmetric(PublicKey);
            sut.Decrypt(new byte[100]);
        });
        Assert.AreEqual("PrivateKey missing.", ex.Message);
    }

    [Test]
    public void Decrypt_Cipher_Size_Exception()
    {
        var ex = Assert.Throws<CryptographicException>(() =>
        {
            var sut = new Asymmetric(privateKey: PrivateKey);
            sut.Decrypt(new byte[100]);
        });
        Assert.AreEqual("Parameter encryptedBytes must be divisible by 256.", ex.Message);
    }
}
