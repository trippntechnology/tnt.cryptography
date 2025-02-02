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
  public abstract byte[] Encrypt(byte[] plainTextBytes);

  /// <summary>
  /// Implement to encrypt a <paramref name="obj"/> and return a base64 encoded string 
  /// </summary>
  /// <returns>Base64 encoded string representing an encrypted <paramref name="obj"/></returns>
  public abstract string Encrypt(object obj);

  /// <summary>
  /// Implement to decrypt <paramref name="encryptedBytes"/>
  /// </summary>
  /// <returns>Decrypted bytes</returns>
  public abstract byte[] Decrypt(byte[] encryptedBytes);

  /// <summary>
  /// Implement to decrypt an encoded string and return an object of <typeparamref name="T"/>
  /// </summary>
  /// <returns>Object of <typeparamref name="T"/></returns>
  public abstract T? Decrypt<T>(string encodedString);
}
