using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using TNT.Cryptography;
using TNT.Cryptography.Enumerations;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class CipherKeyTests
{
  private const string PASSWORD = "ThisIsThePassword";
  private const string KEY = "LawKjSG6g340ihcyQnG3k92oNhkGRwSndYFbWuJj//8=";
  private const int SALT = 7;
  private const int ITERATIONS = 11;
  private HashAlgorithmName HASH_ALGORITHM = HashAlgorithmName.SHA256;
  private KeySize KEY_SIZE = KeySize.Bits128;

  [Test]
  public void CreateKeyTest()
  {
    var keyBytes = CipherKey.CreateKey(PASSWORD);
    var encodedKey = Convert.ToBase64String(keyBytes);
    Assert.That(encodedKey, Is.EqualTo(KEY));

    var sut = new CipherKey(encodedKey);
    Assert.That(sut.EncodedValue, Is.EqualTo(encodedKey));

    sut = new CipherKey(PASSWORD, 0);
    Assert.That(sut.EncodedValue, Is.EqualTo(encodedKey));

    sut = new CipherKey(PASSWORD, SALT);
    Assert.That(sut.EncodedValue, Is.Not.EqualTo(encodedKey));

    sut = new CipherKey(PASSWORD, iterations: ITERATIONS);
    Assert.That(sut.EncodedValue, Is.EqualTo("XgSFY8j5GElKXt5i3KPuM9HttgGyi+5BsFBzJ98BX7o="));

    sut = new CipherKey(PASSWORD, hashAlgorithmName: HASH_ALGORITHM);
    Assert.That(sut.EncodedValue, Is.EqualTo("N3MbXY+1J0PdE2wziq6W1EyiM9cEbjatFVkM29jd2zc="));

    sut = new CipherKey(PASSWORD, keySize: KEY_SIZE);
    Assert.That(sut.EncodedValue, Is.EqualTo("LawKjSG6g340ihcyQnG3kw=="));
  }

  [Test]
  public void CreateTest()
  {
    var result = CipherKey.Create(PASSWORD);
    Assert.That(result, Is.Not.Null);
    Assert.That(result.EncodedValue, Is.EqualTo(KEY));
    Assert.That(result.ByteValue, Is.Not.Empty);
  }

  [Test]
  public void CreateWithParametersTest()
  {
    var result = CipherKey.Create(PASSWORD, SALT, ITERATIONS, HASH_ALGORITHM, KEY_SIZE);
    Assert.That(result, Is.Not.Null);
    Assert.That(result.EncodedValue, Is.Not.Empty);
    Assert.That(result.ByteValue, Is.Not.Empty);
  }

  [Test]
  public void CreateWithDifferentIterationsTest()
  {
    var result = CipherKey.Create(PASSWORD, iterations: ITERATIONS);
    Assert.That(result, Is.Not.Null);
    Assert.That(result.EncodedValue, Is.EqualTo("XgSFY8j5GElKXt5i3KPuM9HttgGyi+5BsFBzJ98BX7o="));
  }

  [Test]
  public void CreateWithDifferentHashAlgorithmTest()
  {
    var result = CipherKey.Create(PASSWORD, hashAlgorithmName: HASH_ALGORITHM);
    Assert.That(result, Is.Not.Null);
    Assert.That(result.EncodedValue, Is.EqualTo("N3MbXY+1J0PdE2wziq6W1EyiM9cEbjatFVkM29jd2zc="));
  }

  [Test]
  public void CreateWithDifferentKeySizeTest()
  {
    var result = CipherKey.Create(PASSWORD, keySize: KEY_SIZE);
    Assert.That(result, Is.Not.Null);
    Assert.That(result.EncodedValue, Is.EqualTo("LawKjSG6g340ihcyQnG3kw=="));
  }
}
