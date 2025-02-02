using System.Diagnostics.CodeAnalysis;
using System.Text;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class InitializationVectorTests
{
  private const string IV = "ABCDEFGHIJKLMNOP";

  [Test]
  public void InitializationVector_Invalid_Length()
  {
    Assert.That(() => { new InitializationVector("abcdefghijklmno"); }, Throws.ArgumentException);
    Assert.That(() => { new InitializationVector("abcdefghijklmnopq"); }, Throws.ArgumentException);

    Assert.That(() => { new InitializationVector(new byte[15]); }, Throws.ArgumentException);
    Assert.That(() => { new InitializationVector(new byte[17]); }, Throws.ArgumentException);
  }

  [Test]
  public void InitializationVector()
  {
    var sut = new InitializationVector(IV);
    Assert.That(sut.Value, Is.EqualTo(IV));

    var ivBytes = Encoding.UTF8.GetBytes(IV);
    sut = new InitializationVector(ivBytes);
    Assert.That(sut.Value, Is.EqualTo(IV));
    Assert.That(sut.ByteValue, Is.EqualTo(ivBytes));
  }
}
