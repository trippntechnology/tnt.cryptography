using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]

public class SymmetricCipherTests
{
  private string PlainText = @"{
  ""ApplicationID"": ""523b80f8-f1e2-4f26-9846-81935fbc23ed"",
  ""LicenseID"": ""d40349c7-dc4a-4f32-a29f-b81b7e4c38ef"",
  ""Secret"": ""e!diXVX*7Fh3!v*sWuro"",
  ""ServiceEndpoint"": ""https://tnt-service-eyhpfrebbdhvgwdt.westus-01.azurewebsites.net/""
}";

  [Test]
  public void TestEncryptionDecryption()
  {
    string password = "thepasswordfortheca";
    byte[] rawKey = CipherAttributes.CreateKey(password);
    string key = Convert.ToBase64String(rawKey);

    Assert.That(key, Is.EqualTo("Jzk9veqSO9ZhYte+2C8erHTrSJNg0Wh0BqRtcJBxRtQ="));

    CipherAttributes encryptionCA = new CipherAttributes(password);

    Assert.That(encryptionCA.Key, Is.EqualTo("Jzk9veqSO9ZhYte+2C8erHTrSJNg0Wh0BqRtcJBxRtQ="));

    SymmetricCipher encrytionCipher = new SymmetricCipher(encryptionCA);
    var encryptedBytes = encrytionCipher.Encypt(Encoding.UTF8.GetBytes(PlainText));

    var encryptedText = Convert.ToBase64String(encryptedBytes);
    var formattedEncryptedText = FormatUtils.FormatWithTags(encryptedText);
    File.WriteAllLines("TestEncryptionDecryption.txt", formattedEncryptedText);

    CipherAttributes decryptionCA = new CipherAttributes(encryptionCA.Key, encryptionCA.IV);

    Assert.That(decryptionCA.Key, Is.EqualTo(encryptionCA.Key));
    Assert.That(decryptionCA.IV, Is.EqualTo(encryptionCA.IV));

    SymmetricCipher decriptionCipher = new SymmetricCipher(decryptionCA);
    var decryptedBytes = decriptionCipher.Decrypt(encryptedBytes);
    var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

    Assert.That(decryptedText, Is.Not.Null);
    Assert.That(decryptedText, Is.EqualTo(PlainText));
  }

  [Test]
  public void TestEncryptionDecryptionFile()
  {
    List<string> license = File.ReadAllLines("License.txt").ToList();
    string encryptedLicense = license.Count > 1 ? FormatUtils.RemoveTags(license) : license[0];
    byte[] encryptedBytes = Convert.FromBase64String(encryptedLicense);

    var json = "{\"Key\":\"Jzk9veqSO9ZhYte+2C8erHTrSJNg0Wh0BqRtcJBxRtQ=\",\"IV\":\"DD7J27KHMiEDUnJD\"}";
    var cipherAttrs = JsonSerializer.Deserialize<CipherAttributesTests.CA>(json);
    if (cipherAttrs == null) return;

    var cipherAttributes = new CipherAttributes(cipherAttrs.Key, cipherAttrs.IV);

    var sameKey = cipherAttributes.Key == cipherAttrs.Key;
    var sameIV = cipherAttributes.IV == cipherAttrs.IV;

    var symmetricCipher = new SymmetricCipher(cipherAttributes);
    var decryptedBytes = symmetricCipher.Decrypt(encryptedBytes);
    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
    Assert.That(decryptedText, Is.EqualTo(PlainText));
  }

  [Test]
  public void EncryptionDecriptionProcess()
  {
    var key = "Jzk9veqSO9ZhYte+2C8erHTrSJNg0Wh0BqRtcJBxRtQ=";
    var iv = "DD7J27KHMiEDUnJD";
    var _plainTextBytes = Encoding.UTF8.GetBytes(PlainText);

    var _encryptCA = new CipherAttributes(key, iv);
    var _encryptCipher = new SymmetricCipher(_encryptCA);
    var _encryptedBytes = _encryptCipher.Encypt(_plainTextBytes);
    var _encryptedBytesText = Convert.ToBase64String(_encryptedBytes);
    Assert.That(_encryptedBytesText, Is.EqualTo("M8aypcHQl1W/Ogk3YZ3d+qfLL6yetm9zvrda+YmdNucGpgVV9wOy/zpn9Xc8i4Frqs7YTF0Qi+F5fKvGnwYXWezraeYdpp07a68hrUwQ64QLAOfd8ROKa0sY6lD48fRibcQ6ITkm6Wh0PLF/vglINdTH3Sg3hNF0+u3IMz57R09wrr69NZ89IjuA2bFYZuLpIT/wkYZdcRcYSlV+xTauHlFNzfJSWMFdoJVZXSLcEYL1f/8kenL3ZPvPCT4O51SQnZYvsc2gmA4Ex79CSnyquYZYwMpnCNOgTl5kEJ1lMfml+TBpHwossshcs7gZGYjm0rHWyR6S28j2/gkow2SI0g=="));
    var _formattedEncryptedBytesText = FormatUtils.FormatWithTags(_encryptedBytesText);
    File.WriteAllLines("test.txt", _formattedEncryptedBytesText);

    var formattedEncryptedBytesText_ = File.ReadAllLines("test.txt").ToList();
    Assert.That(formattedEncryptedBytesText_, Is.EqualTo(_formattedEncryptedBytesText));
    var encryptedBytesText_ = FormatUtils.RemoveTags(formattedEncryptedBytesText_);
    Assert.That(encryptedBytesText_, Is.EqualTo(_encryptedBytesText));
    var encryptedBytes_ = Convert.FromBase64String(_encryptedBytesText);
    Assert.That(encryptedBytes_, Is.EqualTo(_encryptedBytes));
    var decryptCA = new CipherAttributes(key, iv);
    var decryptCipher = new SymmetricCipher(decryptCA);
    var plainTextBytes_ = decryptCipher.Decrypt(encryptedBytes_);
    Assert.That(plainTextBytes_, Is.EqualTo(_plainTextBytes));
    var plainText = Encoding.UTF8.GetString(plainTextBytes_);
    Assert.That(plainText, Is.EqualTo(PlainText));
  }
}
