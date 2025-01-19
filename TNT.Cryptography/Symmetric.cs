using System.Security.Cryptography;
using System.Text;

namespace TNT.Cryptography;

/// <summary>
/// This class uses a symmetric key algorithm (System.Security.Cryptography.AES) 
/// to encrypt and decrypt data. As long as encryption and decryption routines use the same 
/// parameters to generate the keys, the keys are guaranteed to be the same. This was adapted 
/// from code found at http://www.obviex.com/samples/Encryption.aspx.
/// </summary>	
[Obsolete("Use SymmetricCipher instead")]
public class Symmetric
{
  /// <summary>
  /// Tag used before the encrypted text
  /// </summary>
  public const string BEGIN_TAG = "--- BEGIN ---";

  /// <summary>
  /// Tag used after the encrypted text
  /// </summary>
  public const string END_TAG = "--- END ---";

  const int LINE_LENGTH = 80;

  /// <summary>
  /// The key
  /// </summary>
  public byte[] Key { get; protected set; }

  #region Constructors

  /// <summary>
  /// Initializes a <see cref="Symmetric"/> with a key represented as a <see cref="byte"/> array
  /// </summary>
  public Symmetric(byte[] key)
  {
    this.Key = key;
  }

  /// <summary>
  /// Initializes a <see cref="Symmetric"/> with a key represented as a base 64 encoded <see cref="string"/>
  /// </summary>
  /// <param name="key">Base 64 encoded <see cref="string"/></param>
  public Symmetric(string key)
    : this(Convert.FromBase64String(key))
  {
  }

  #endregion

  /// <summary>
  /// Generates a key
  /// </summary>
  /// <param name="password">
  /// Passphrase from which a pseudo-random password will be derived. The derived password will be used 
  /// to generate the encryption key. Passphrase can be any string. In this example we assume that this 
  /// passphrase is an ASCII string.</param>
  /// <param name="salt">
  /// Salt value used along with passphrase to generate password. Salt can be any string. In this example 
  /// we assume that salt is an ASCII string.
  /// </param>
  /// <param name="hashAlgorithm">
  /// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 hashes are a bit 
  /// slower, but more secure than MD5 hashes. (Default: SHA1)
  /// </param>
  /// <param name="iterations">
  /// Number of iterations used to generate password. One or two iterations should be enough. (Default: 2)
  /// </param>
  /// <param name="keySize">
  /// Size of encryption key in bits. Allowed values are: 128, 192, and 256. Longer keys are more secure than 
  /// shorter keys. (Default: Bits256)
  /// </param>
  /// <returns><see cref="byte"/> array representing the key</returns>
  [Obsolete("Use AsymmetricCipher")]
  public static byte[] GenerateKey(string password, string salt, Enumerations.HashAlgorithm hashAlgorithm = Enumerations.HashAlgorithm.SHA1,
                  int iterations = 2, Enumerations.KeySize keySize = Enumerations.KeySize.Bits256)
  {
    byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);

    // First, create a password, from which the key will be derived. This password will be generated from the 
    // specified passphrase and salt value. The password will be created using the specified hash algorithm. 
    // Password creation can be done in several iterations.
    PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, saltValueBytes, hashAlgorithm.ToString(), iterations);

    // Use the password to generate pseudo-random bytes for the encryption key. Specify the size of the key 
    // in bytes (instead of bits).
    return passwordBytes.GetBytes((int)keySize / 8);
  }

  /// <summary>
  /// Creates an initialization vector from <paramref name="initVector"/>
  /// </summary>
  /// <param name="initVector">Initialization vector (or IV). This value is required to encrypt the 
  /// first block of plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
  /// </param>
  /// <param name="enforceRijndael">When true, enforces 16 ASCII characters restriction</param>
  /// <returns><see cref="byte"/> array representing the IV</returns>
  /// <exception cref="ArgumentException">Thrown when <paramref name="enforceRijndael"/>is true and 
  /// <paramref name="initVector"/> is not 16 characters long</exception>
  [Obsolete("Use AsymmetricCipher")]
  public static byte[] GenerateIV(string initVector, bool enforceRijndael = true)
  {
    if (initVector.Length != 16) throw new ArgumentException("Parameter, initVector, must be 16 characters");
    return Encoding.ASCII.GetBytes(initVector);
  }

  /// <summary>
  /// Encrypts <paramref name="plainBytes"/> to a <see cref="Cipher"/>
  /// </summary>
  /// <param name="plainBytes"><see cref="byte"/> array to encrypt</param>
  /// <param name="iv">Initialization vector</param>
  /// <returns><see cref="Cipher"/> of <paramref name="plainBytes"/> and <paramref name="iv"/></returns>
  [Obsolete("Use SymmetricCipher.Encrypt")]
  public Cipher EncryptToCipher(byte[] plainBytes, byte[] iv)
  {
    var encryptedBytes = Encrypt(plainBytes, iv);
    return new Cipher(encryptedBytes, iv);
  }

  /// <summary>
  /// Encrypts <paramref name="plainBytes"/>
  /// </summary>
  /// <returns><see cref="byte"/> array representing an encrypted <paramref name="plainBytes"/></returns>
  [Obsolete("Use SymmetricCipher.Encrypt")]
  public byte[] Encrypt(byte[] plainBytes, byte[] iv)
  {
    byte[] initializationVector = Encoding.ASCII.GetBytes("abcede0123456789");
    using (Aes aes = Aes.Create())
    {
      var symmetricEncryptor = aes.CreateEncryptor(Key, iv);
      using (var memoryStream = new MemoryStream())
      {
        using (var cryptoStream = new CryptoStream(memoryStream, symmetricEncryptor, CryptoStreamMode.Write))
        {
          // Start encrypting.
          cryptoStream.Write(plainBytes, 0, plainBytes.Length);

          // Finish encrypting.
          cryptoStream.FlushFinalBlock();

          // Convert our encrypted data from a memory stream into a byte array.
          return memoryStream.ToArray();
        }
      }
    }
  }

  /// <summary>
  /// Decrypts content represented by <paramref name="cipher"/>
  /// </summary>
  /// <param name="cipher"><see cref="Cipher"/> that contains the encrypted content</param>
  /// <returns>Decrypted <see cref="byte"/> array</returns>
  /// <exception cref="ArgumentException">Thrown <see cref="Cipher"/> does not contain IV</exception>
  [Obsolete("Use SymmetricCipher.Decrypt")]
  public byte[] Decrypt(Cipher cipher)
  {
    byte[] plainBytes = cipher.EncryptedBytes;
    var iv = cipher.IV;

    if (iv == null) throw new ArgumentException("Initialization vector must be supplied");

    return Decrypt(plainBytes, iv);
  }

  /// <summary>
  /// Decrypts <paramref name="cipherBytes"/>
  /// </summary>
  /// <param name="cipherBytes">Encrypted <see cref="byte"/> array</param>
  /// <param name="iv"><see cref="byte"/> array representing initialization vector</param>
  /// <returns>Decrypted <see cref="byte"/> array</returns>
  [Obsolete("Use SymmetricCipher.Decrypt")]
  public byte[] Decrypt(byte[] cipherBytes, byte[] iv)
  {
    byte[] plainBytes;
    using (Aes aes = Aes.Create())
    {
      var decryptor = aes.CreateDecryptor(Key, iv);
      using (var memoryStream = new MemoryStream(cipherBytes))
      {
        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
        {
          using (var ms = new MemoryStream())
          {
            cryptoStream.CopyTo(ms);
            plainBytes = ms.ToArray();
          }
        }
      }
    }
    return plainBytes;
  }

  /// <summary>
  /// Adds the <see cref="BEGIN_TAG"/> and <see cref="END_TAG"/> and formats so that 
  /// the longest line is <see cref="LINE_LENGTH"/>
  /// </summary>
  /// <param name="content">Content to format</param>
  /// <returns><see cref="List{String}"/> with the content formatted</returns>
  [Obsolete("Use FormatUtils.FormatWithTags")]
  public static List<string> FormatWithTags(string content)
  {
    List<string> formatted = new List<string>();

    if (string.IsNullOrWhiteSpace(content)) return formatted;

    formatted.Add(BEGIN_TAG);

    while (content.Length > 0)
    {
      string subString = string.Empty;
      if (content.Length >= LINE_LENGTH)
      {
        subString = content.Substring(0, LINE_LENGTH);
        content = content.Substring(LINE_LENGTH);
      }
      else
      {
        subString = content.Substring(0);
        content = string.Empty;
      }
      formatted.Add(subString);
    }

    formatted.Add(END_TAG);

    return formatted;
  }

  /// <summary>
  /// Remove the tags and join all lines back into a single <see cref="String"/>
  /// </summary>
  /// <param name="lines">Lines to format</param>
  /// <returns>Content unformatted</returns>
  [Obsolete("Use FormatUtils.RemoveTags")]
  public static string RemoveTags(List<string> lines)
  {
    var beginIndex = lines.FindIndex(l => l == BEGIN_TAG);
    var endIndex = lines.FindIndex(l => l == END_TAG);

    if (beginIndex == -1 || endIndex == -1 || endIndex < beginIndex) throw new ArgumentException("Unexpected format");
    if (beginIndex + 1 == endIndex) return string.Empty;

    var content = lines.GetRange(beginIndex + 1, endIndex - beginIndex - 1);
    return string.Join("", content);
  }
}