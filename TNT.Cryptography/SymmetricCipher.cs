using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TNT.Cryptography;

/// <summary>
/// Symmetric cipher
/// </summary>
public class SymmetricCipher : BaseCipher
{
  /// <summary>
  /// Initialization constructor
  /// </summary>
  public SymmetricCipher(CipherAttributes cipherAttributes) : base(cipherAttributes)
  {
  }

  /// <summary>
  /// Decrypts <paramref name="encryptedBytes"/>
  /// </summary>
  /// <returns><see cref="byte"/> array of decrypted bytes</returns>
  /// <exception cref="NotImplementedException"></exception>
  public override byte[] Decrypt(byte[] encryptedBytes)
  {
    using (Aes aes = Aes.Create())
    {
      var decryptor = aes.CreateDecryptor(CipherAttributes.Key.ByteValue, CipherAttributes.IV.ByteValue);
      using (var memoryStream = new MemoryStream(encryptedBytes))
      {
        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
        {
          using (var ms = new MemoryStream())
          {
            cryptoStream.CopyTo(ms);
            return ms.ToArray();
          }
        }
      }
    }
  }

  /// <summary>
  /// Decrypts <paramref name="encodedString"/> and deserializes it into an object of <typeparamref name="T"/> 
  /// </summary>
  /// <typeparam name="T">Type of object represented by the encoded string</typeparam>
  /// <param name="encodedString">Base64 encoded string representing encrypted bytes</param>
  /// <returns>Object of <typeparamref name="T"/> on success, null otherwise</returns>
  public override T? Decrypt<T>(string encodedString) where T : default
  {
    var encryptedBytes = Convert.FromBase64String(encodedString);
    var decryptedBytes = Decrypt(encryptedBytes);
    var decryptedString = Encoding.UTF8.GetString(decryptedBytes);
    return JsonSerializer.Deserialize<T>(decryptedString);
  }

  /// <summary>
  /// Encrypts <paramref name="plainTextBytes"/>
  /// </summary>
  /// <returns><see cref="byte"/> array of encrypted bytes</returns>
  public override byte[] Encrypt(byte[] plainTextBytes)
  {
    using (Aes aes = Aes.Create())
    {
      var symmetricEncryptor = aes.CreateEncryptor(CipherAttributes.Key.ByteValue, CipherAttributes.IV.ByteValue);
      using (var memoryStream = new MemoryStream())
      {
        using (var cryptoStream = new CryptoStream(memoryStream, symmetricEncryptor, CryptoStreamMode.Write))
        {
          // Start encrypting.
          cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

          // Finish encrypting.
          cryptoStream.FlushFinalBlock();

          // Convert our encrypted data from a memory stream into a byte array.
          return memoryStream.ToArray();
        }
      }
    }
  }

  /// <summary>
  /// Serialize and encrypts <paramref name="obj"/>
  /// </summary>
  /// <returns>Base64 encoded string that represents <paramref name="obj"/></returns>
  public override string Encrypt(object obj)
  {
    var serializedObj = JsonSerializer.Serialize(obj);
    var serializedBytes = Encoding.UTF8.GetBytes(serializedObj);
    var encryptedBytes = Encrypt(serializedBytes);
    return Convert.ToBase64String(encryptedBytes);
  }
}
