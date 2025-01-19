using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class CipherAttributesTests
{
  [Test]
  public void ConstructorTest()
  {
    string password = "key value";
    CipherAttributes sut = new CipherAttributes(password);
    var rgbKey = CipherAttributes.CreateKey(password);
    var key = Convert.ToBase64String(rgbKey);
    Assert.That(sut.Key, Is.Not.Null);
    Assert.That(sut.Key, Is.EqualTo("zicavw+MGi7sdGgx+8bvEvpn1H/QaaAxxxxUqRR/0LE="));
    Assert.That(sut.IV.Length, Is.EqualTo(16));

    sut = new CipherAttributes(password, 7);
    Assert.That(sut.Key, Is.Not.Null);
    Assert.That(sut.Key, Is.Not.EqualTo("zicavw+MGi7sdGgx+8bvEvpn1H/QaaAxxxxUqRR/0LE="));

    sut = new CipherAttributes(password, iterations: 11);
    Assert.That(sut.Key, Is.Not.Null);
    Assert.That(sut.Key, Is.EqualTo("mfn6i0xTwCDoSxZrc3I0WUstJ6Vf5eLNNIqRK0T1pOg="));

    sut = new CipherAttributes(password, hashAlgorithmName: HashAlgorithmName.SHA256);
    Assert.That(sut.Key, Is.Not.Null);
    Assert.That(sut.Key, Is.EqualTo("mk0GWCj8YoyB1eBPWP6tAV6vBj+KpIn/YOdb5kauAcg="));

    sut = new CipherAttributes(password, keySize: TNT.Cryptography.Enumerations.KeySize.Bits128);
    Assert.That(sut.Key, Is.Not.Null);
    Assert.That(sut.Key, Is.EqualTo("zicavw+MGi7sdGgx+8bvEg=="));
  }

  [Test]
  public void CreateKeyTest()
  {
    string password = "key value";
    var rgbKey = CipherAttributes.CreateKey(password);
    var key = Convert.ToBase64String(rgbKey);
    Assert.That(key, Is.Not.Null);
    Assert.That(key, Is.EqualTo("zicavw+MGi7sdGgx+8bvEvpn1H/QaaAxxxxUqRR/0LE="));

    rgbKey = CipherAttributes.CreateKey(password, 7);
    key = Convert.ToBase64String(rgbKey);
    Assert.That(key, Is.Not.Null);
    Assert.That(key, Is.Not.EqualTo("zicavw+MGi7sdGgx+8bvEvpn1H/QaaAxxxxUqRR/0LE="));

    rgbKey = CipherAttributes.CreateKey(password, iterations: 11);
    key = Convert.ToBase64String(rgbKey);
    Assert.That(key, Is.Not.Null);
    Assert.That(key, Is.EqualTo("mfn6i0xTwCDoSxZrc3I0WUstJ6Vf5eLNNIqRK0T1pOg="));

    rgbKey = CipherAttributes.CreateKey(password, hashAlgorithmName: HashAlgorithmName.SHA256);
    key = Convert.ToBase64String(rgbKey);
    Assert.That(key, Is.Not.Null);
    Assert.That(key, Is.EqualTo("mk0GWCj8YoyB1eBPWP6tAV6vBj+KpIn/YOdb5kauAcg="));

    rgbKey = CipherAttributes.CreateKey(password, keySize: TNT.Cryptography.Enumerations.KeySize.Bits128);
    key = Convert.ToBase64String(rgbKey);
    Assert.That(key, Is.Not.Null);
    Assert.That(key, Is.EqualTo("zicavw+MGi7sdGgx+8bvEg=="));
  }

  [Test]
  public void ToStringTest()
  {
    CipherAttributes sut = new CipherAttributes("password");
    string expected = $"{{\"Key\":\"{sut.Key}\",\"IV\":\"{sut.IV}\"}}";
    var value = sut.ToString();
    Console.WriteLine(value);
    Assert.That(value, Is.EqualTo(expected));
  }
}