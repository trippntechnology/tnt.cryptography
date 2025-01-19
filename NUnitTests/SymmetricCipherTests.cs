using System.Diagnostics.CodeAnalysis;
using System.Text;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]

public class SymmetricCipherTests
{
  private string PlainText = @"Quisque id mi. Nullam sagittis. Ut non enim eleifend felis pretium feugiat. Pellentesque posuere. In hac habitasse platea dictumst.

Praesent adipiscing. Cras ultricies mi eu turpis hendrerit fringilla. Praesent nonummy mi in odio. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos hymenaeos. Vestibulum suscipit nulla quis orci.

Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Pellentesque posuere. Praesent adipiscing. In hac habitasse platea dictumst. Fusce egestas elit eget lorem.

Curabitur ligula sapien, tincidunt non, euismod vitae, posuere imperdiet, leo. Donec sodales sagittis magna. Etiam sit amet orci eget eros faucibus tincidunt. Vestibulum dapibus nunc ac augue. Praesent adipiscing.

Praesent nec nisl a purus blandit viverra. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos hymenaeos. Suspendisse pulvinar, augue ac venenatis condimentum, sem libero volutpat nibh, nec pellentesque velit pede quis nunc. Fusce vel dui. Donec interdum, metus et hendrerit aliquet, dolor diam sagittis ligula, eget egestas libero turpis vel mi.";

  [Test]
  public void TestEncryptionDecryption()
  {
    byte[] rawKey = CipherAttributes.CreateKey("this is the password");
    string key = Convert.ToBase64String(rawKey);

    Assert.That(key, Is.EqualTo("DQrgzgpovQxZDgORye9RtcNQA7PirOobuxYKv5KuCHQ="));

    CipherAttributes cipherParams = new CipherAttributes(key);
    SymmetricCipher symmetricCipher = new SymmetricCipher(cipherParams);

    var encryptedBytes = symmetricCipher.Encypt(Encoding.UTF8.GetBytes(PlainText));
    var decryptedBytes = symmetricCipher.Decrypt(encryptedBytes);
    var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

    Assert.That(decryptedText, Is.Not.Null);
    Assert.That(decryptedText, Is.EqualTo(PlainText));
  }
}
