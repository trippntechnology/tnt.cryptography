using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class CipherAttributesTests
{
  private const string PASSWORD = "thisisthepasswordusedinthetest";
  private const string ENCODED_KEY = "U4UAdDUUSeVEP3a361krforOlA9TpyYbeVV0NT8nd34=";
  private const string IV = "FKwQqFFFP2bQqoE1";
  private const string EXPECTED_CIPHER_ATTS_STRING = $"{{\"Key\":{{\"EncodedValue\":\"{ENCODED_KEY}\"}},\"IV\":{{\"Value\":\"{IV}\"}}}}";

  [Test]
  public void CopyConstructorTest()
  {
    var cipherAttr = new CipherAttributes(new CipherKey(ENCODED_KEY), new InitializationVector(IV));
    var sut = new CipherAttributes(cipherAttr);
    Assert.That(sut.Key.EncodedValue, Is.EqualTo(cipherAttr.Key.EncodedValue));
    Assert.That(sut.IV.Value, Is.EqualTo(cipherAttr.IV.Value));

    Assert.That(sut.Key.ByteValue, Is.Not.EqualTo(new byte[0]));
    Assert.That(sut.Key.ByteValue, Is.EqualTo(cipherAttr.Key.ByteValue));
    Assert.That(sut.IV.ByteValue, Is.Not.EqualTo(new byte[0]));
    Assert.That(sut.IV.ByteValue, Is.EqualTo(cipherAttr.IV.ByteValue));
  }


  [Test]
  public void ToStringTest()
  {
    var cipherKey = new CipherKey(PASSWORD, 0);
    var iv = new InitializationVector(IV);
    CipherAttributes sut = new CipherAttributes(cipherKey, iv);
    var value = sut.ToString();
    Console.WriteLine(value);
    Assert.That(value, Is.EqualTo(EXPECTED_CIPHER_ATTS_STRING));
  }

  [Test]
  public void TestSerialization()
  {
    var expectCipherAttrs = new CipherAttributes(new CipherKey(ENCODED_KEY), new InitializationVector(IV));
    string cipherAttrsString = $"{{\"Key\":{{\"EncodedValue\":\"{ENCODED_KEY}\"}},\"IV\":{{\"Value\":\"{IV}\"}}}}";
    CipherAttributes? sut = JsonSerializer.Deserialize<CipherAttributes>(EXPECTED_CIPHER_ATTS_STRING);
    Assert.That(sut, Is.Not.Null);

    Assert.That(sut.Key.EncodedValue, Is.EqualTo(expectCipherAttrs.Key.EncodedValue));
    Assert.That(sut.IV.Value, Is.EqualTo(expectCipherAttrs.IV.Value));

    Assert.That(sut.Key.ByteValue, Is.Not.EqualTo(new byte[0]));
    Assert.That(sut.Key.ByteValue, Is.EqualTo(expectCipherAttrs.Key.ByteValue));
    Assert.That(sut.IV.ByteValue, Is.Not.EqualTo(new byte[0]));
    Assert.That(sut.IV.ByteValue, Is.EqualTo(expectCipherAttrs.IV.ByteValue));
  }
}