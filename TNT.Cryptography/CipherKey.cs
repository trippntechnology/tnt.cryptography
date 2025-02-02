using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace TNT.Cryptography;

/// <summary>
/// Represents a cipher key use by <see cref="CipherAttributes"/>
/// </summary>
public class CipherKey
{
  /// <summary>
  /// Base64 encoded key
  /// </summary>
  public string EncodedValue { get; set; }

  /// <summary>
  /// Byte array key
  /// </summary>
  [JsonIgnore]
  public byte[] ByteValue { get; }

  /// <summary>
  /// Default constructor used by deserialization
  /// </summary>
  public CipherKey()
  {
    EncodedValue = string.Empty;
    ByteValue = new byte[0];
  }

  /// <summary>
  /// Initializes using a base64 encoded key
  /// </summary>
  /// <param name="encodedKey"></param>
  public CipherKey(string encodedKey)
  {
    EncodedValue = encodedKey;
    ByteValue = Convert.FromBase64String(EncodedValue);
  }

  /// <summary>
  /// Initializes using a password
  /// </summary>
  public CipherKey(string password, int saltSize = 0, int iterations = 2, HashAlgorithmName? hashAlgorithmName = null,
    Enumerations.KeySize keySize = Enumerations.KeySize.Bits256)
  {
    ByteValue = CreateKey(password, saltSize, iterations, hashAlgorithmName, keySize);
    EncodedValue = Convert.ToBase64String(ByteValue);
  }

  /// <summary>
  /// Generates a key
  /// </summary>
  /// <param name="password">
  /// Passphrase from which a pseudo-random password will be derived. The derived password will be used 
  /// to generate the encryption key. Passphrase can be any string. In this example we assume that this 
  /// passphrase is an ASCII string.</param>
  /// <param name="saltSize">
  /// Salt value used along with passphrase to generate password. Salt can be any string. In this example 
  /// we assume that salt is an ASCII string.
  /// </param>
  /// <param name="iterations">
  /// Number of iterations used to generate password. One or two iterations should be enough. (Default: 2)
  /// </param>
  /// <param name="hashAlgorithmName">
  /// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 hashes are a bit 
  /// slower, but more secure than MD5 hashes. (Default: SHA1)
  /// </param>
  /// <param name="keySize">
  /// Size of encryption key in bits. Allowed values are: 128, 192, and 256. Longer keys are more secure than 
  /// shorter keys. (Default: Bits256)
  /// </param>
  /// <returns><see cref="byte"/> array representing the key</returns>
  public static byte[] CreateKey(string password, int saltSize = 0, int iterations = 2, HashAlgorithmName? hashAlgorithmName = null,
    Enumerations.KeySize keySize = Enumerations.KeySize.Bits256)
  {
    HashAlgorithmName hashAlgorithm = hashAlgorithmName ?? HashAlgorithmName.SHA1;

    // First, create a password, from which the key will be derived. This password will be generated from the 
    // specified passphrase and salt value. The password will be created using the specified hash algorithm. 
    // Password creation can be done in several iterations.
    Rfc2898DeriveBytes passwordBytes = new Rfc2898DeriveBytes(password, saltSize, iterations, hashAlgorithm);

    // Use the password to generate pseudo-random bytes for the encryption key. Specify the size of the key 
    // in bytes (instead of bits).
    return passwordBytes.GetBytes((int)keySize / 8);
  }

}
