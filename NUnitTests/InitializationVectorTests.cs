using System.Diagnostics.CodeAnalysis;
using System.Text;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class InitializationVectorTests
{
  private const string IV = "ABCDEFGHIJKLMNOP";

  [Test]
  public void InitializationVector_Constructor_Tests()
  {
    var sut = new InitializationVector(IV);
    Assert.That(sut.Value, Is.EqualTo(IV));

    var ivBytes = Encoding.UTF8.GetBytes(IV);
    sut = new InitializationVector(ivBytes);
    Assert.That(sut.Value, Is.EqualTo(IV));
    Assert.That(sut.ByteValue, Is.EqualTo(ivBytes));
  }

  [Test]
  public void GenerateRandomString()
  {
    var sut = InitializationVector.GenerateRandomString();
    Assert.That(sut.Length, Is.EqualTo(16));
    Assert.That(sut, Is.Not.EqualTo(InitializationVector.GenerateRandomString()));
    sut = InitializationVector.GenerateRandomString(7);
    Assert.That(sut.Length, Is.EqualTo(7));
  }
}
