using System.Security.Cryptography;

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
  /// Encrypts <paramref name="plainTextBytes"/>
  /// </summary>
  /// <returns><see cref="byte"/> array of encrypted bytes</returns>
  public override byte[] Encypt(byte[] plainTextBytes)
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
}
