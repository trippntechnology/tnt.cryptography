namespace TNT.Cryptography;

/// <summary>
/// Base class for ciphers
/// </summary>
public abstract class BaseCipher
{
  /// <summary>
  /// Attributes used by the cipher
  /// </summary>
  public CipherAttributes CipherAttributes { get; private set; }

  /// <summary>
  /// Initialization constructor
  /// </summary>
  public BaseCipher(CipherAttributes CipherAttributes)
  {
    this.CipherAttributes = CipherAttributes;
  }

  /// <summary>
  /// Implement to encrypt <paramref name="plainTextBytes"/> 
  /// </summary>
  /// <returns>Encrypted bytes</returns>
  public abstract byte[] Encypt(byte[] plainTextBytes);

  /// <summary>
  /// Implement to decrypt <paramref name="encryptedBytes"/>
  /// </summary>
  /// <returns>Decrypted bytes</returns>
  public abstract byte[] Decrypt(byte[] encryptedBytes);
}
