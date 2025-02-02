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

  private string EncryptedLines = @"--- BEGIN ---
M8aypcHQl1W/Ogk3YZ3d+qfLL6yetm9zvrda+YmdNucGpgVV9wOy/zpn9Xc8i4Frqs7YTF0Qi+F5fKvG
nwYXWezraeYdpp07a68hrUwQ64QLAOfd8ROKa0sY6lD48fRibcQ6ITkm6Wh0PLF/vglINdTH3Sg3hNF0
+u3IMz57R09wrr69NZ89IjuA2bFYZuLpIT/wkYZdcRcYSlV+xTauHlFNzfJSWMFdoJVZXSLcEYL1f/8k
enL3ZPvPCT4O51SQnZYvsc2gmA4Ex79CSnyquYZYwMpnCNOgTl5kEJ1lMfml+TBpHwossshcs7gZGYjm
0rHWyR6S28j2/gkow2SI0g==
--- END ---
";
  private const string PASSWORD = "thepasswordfortheca";
  private const string ENCODED_KEY = "Jzk9veqSO9ZhYte+2C8erHTrSJNg0Wh0BqRtcJBxRtQ=";
  private const string IV = "NyO0AbiASbWOOOvm";
  private string CipherAttributesJson = $"{{\"Key\":\"{ENCODED_KEY}\",\"IV\":\"{IV}\"}}";
  private const string EXPECTED_CIPHER_ATTS_STRING = $"{{\"Key\":{{\"EncodedValue\":\"{ENCODED_KEY}\"}},\"IV\":{{\"Value\":\"{IV}\"}}}}";

  [Test]
  public void Test1()
  {
    var lines = EncryptedLines.Split("\r\n").ToList();
    var encodedText = FormatUtils.RemoveTags(lines);
    var expectedObject = JsonSerializer.Deserialize<TestObject>(PlainText);
    var cipherKey = new CipherKey(ENCODED_KEY);
    var iv = new InitializationVector(IV);
    var cipherAttributes = new CipherAttributes(cipherKey, iv);
    var cipher = new SymmetricCipher(cipherAttributes);
    var foo = cipher.Decrypt(Convert.FromBase64String(encodedText));
    var bar = Encoding.UTF8.GetString(foo);
  }

  [Test]
  public void TestEncryptionDecryption()
  {
    var cipherKey = new CipherKey(PASSWORD, 0);
    Assert.That(cipherKey.EncodedValue, Is.EqualTo(ENCODED_KEY));
    var iv = new InitializationVector(IV);

    CipherAttributes encryptCipherAttrs = new CipherAttributes(cipherKey, iv);

    Assert.That(encryptCipherAttrs.Key.EncodedValue, Is.EqualTo(ENCODED_KEY));
    Assert.That(encryptCipherAttrs.IV.Value, Is.EqualTo(IV));

    SymmetricCipher encrytionCipher = new SymmetricCipher(encryptCipherAttrs);
    var encryptedBytes = encrytionCipher.Encrypt(Encoding.UTF8.GetBytes(PlainText));

    var encryptedText = Convert.ToBase64String(encryptedBytes);
    var formattedEncryptedText = FormatUtils.FormatWithTags(encryptedText);
    File.WriteAllLines("TestEncryptionDecryption.txt", formattedEncryptedText);



    CipherAttributes decryptionCA = new CipherAttributes(encryptCipherAttrs);

    Assert.That(decryptionCA.Key.EncodedValue, Is.EqualTo(encryptCipherAttrs.Key.EncodedValue));
    Assert.That(decryptionCA.IV.Value, Is.EqualTo(encryptCipherAttrs.IV.Value));

    SymmetricCipher decriptionCipher = new SymmetricCipher(decryptionCA);
    var decryptedBytes = decriptionCipher.Decrypt(encryptedBytes);
    var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

    Assert.That(decryptedText, Is.Not.Null);
    Assert.That(decryptedText, Is.EqualTo(PlainText));
  }

  [Test]
  public void EncryptionDecryptionProcess()
  {
    var key = "Jzk9veqSO9ZhYte+2C8erHTrSJNg0Wh0BqRtcJBxRtQ=";
    var iv = "DD7J27KHMiEDUnJD";
    var _plainTextBytes = Encoding.UTF8.GetBytes(PlainText);
    var cipherKey = new CipherKey(key);
    var initializationVector = new InitializationVector(iv);

    var _encryptCA = new CipherAttributes(cipherKey, initializationVector);
    var _encryptCipher = new SymmetricCipher(_encryptCA);
    var _encryptedBytes = _encryptCipher.Encrypt(_plainTextBytes);
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
    var decryptCA = new CipherAttributes(cipherKey, initializationVector);
    var decryptCipher = new SymmetricCipher(decryptCA);
    var plainTextBytes_ = decryptCipher.Decrypt(encryptedBytes_);
    Assert.That(plainTextBytes_, Is.EqualTo(_plainTextBytes));
    var plainText = Encoding.UTF8.GetString(plainTextBytes_);
    Assert.That(plainText, Is.EqualTo(PlainText));
  }
}
