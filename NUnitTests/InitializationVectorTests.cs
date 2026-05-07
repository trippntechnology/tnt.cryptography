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

  [Test]
  public void CreateTest()
  {
    var result = InitializationVector.Create();
    Assert.That(result, Is.Not.Null);
    Assert.That(result.Value, Is.Not.Empty);
    Assert.That(result.Value.Length, Is.EqualTo(16));
    Assert.That(result.ByteValue, Is.Not.Empty);
  }

  [Test]
  public void CreateWithCustomLengthTest()
  {
    var result = InitializationVector.Create(32);
    Assert.That(result, Is.Not.Null);
    Assert.That(result.Value.Length, Is.EqualTo(32));
  }

  [Test]
  public void CreateGeneratesDifferentValuesTest()
  {
    var result1 = InitializationVector.Create();
    var result2 = InitializationVector.Create();
    Assert.That(result1.Value, Is.Not.EqualTo(result2.Value));
  }

  [Test]
  public void CreateWithSmallLengthTest()
  {
    var result = InitializationVector.Create(1);
    Assert.That(result.Value.Length, Is.EqualTo(1));
  }
}
