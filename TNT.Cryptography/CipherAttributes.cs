using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TNT.Cryptography;

/// <summary>
/// Contains the key and initialization vector used by <see cref="BaseCipher"/>
/// </summary>
public class CipherAttributes
{
  /// <summary>
  /// Base64 format of key
  /// </summary>
  public string Key => Convert.ToBase64String(RawKey);

  /// <summary>
  /// Initialization vector
  /// </summary>
  public string IV => Encoding.ASCII.GetString(RawIV);

  /// <summary>
  /// Key as bytes
  /// </summary>
  [JsonIgnore]
  public byte[] RawKey { get; private set; }

  /// <summary>
  /// Initialization vector as bytes
  /// </summary>
  [JsonIgnore]
  public byte[] RawIV { get; private set; }

  /// <summary>
  /// Initialization constructor
  /// </summary>
  public CipherAttributes(string password, int saltSize = 0, int iterations = 2, HashAlgorithmName? hashAlgorithmName = null,
    Enumerations.KeySize keySize = Enumerations.KeySize.Bits256)
  {
    RawKey = CreateKey(password, saltSize, iterations, hashAlgorithmName, keySize);
    RawIV = Encoding.ASCII.GetBytes(GenerateRandomString(16));
  }

  /// <summary>
  /// Serializes attributes (<seealso cref="CreateKey(string, int, int, HashAlgorithmName?, Enumerations.KeySize)"/>)
  /// </summary>
  /// <returns>Json string with cipher attributes</returns>
  public override string ToString() => JsonSerializer.Serialize(this);


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

  /// <summary>
  /// Generates a random string of alphanumeric characters
  /// </summary>
  /// <param name="length">Length of string (Default: 16)</param>
  /// <returns>Random string of alphanumeric characters of <paramref name="length"/> length</returns>
  public static string GenerateRandomString(int length = 16)
  {
    // Define the characters to choose from (alphanumeric)
    const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    StringBuilder stringBuilder = new StringBuilder(length);
    Random random = new Random(DateTime.Now.Millisecond);

    for (int i = 0; i < length; i++)
    {
      char randomIndex = (char)random.Next(0, chars.Length);
      stringBuilder.Append(chars[randomIndex]);
    }

    return stringBuilder.ToString();
  }
}
