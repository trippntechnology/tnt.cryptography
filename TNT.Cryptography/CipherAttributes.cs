using System.Text.Json;

namespace TNT.Cryptography;

/// <summary>
/// Contains the key and initialization vector used by <see cref="BaseCipher"/>
/// </summary>
public class CipherAttributes
{
  /// <summary>
  /// <see cref="CipherKey"/> used by the cipher
  /// </summary>
  public CipherKey Key { get; set; }

  /// <summary>
  /// <see cref="InitializationVector"/> used by the cipher
  /// </summary>
  public InitializationVector IV { get; set; }

  /// <summary>
  /// Default constructor needed for deserialization
  /// </summary>
  public CipherAttributes()
  {
    Key = new CipherKey();
    IV = new InitializationVector();
  }

  /// <summary>
  /// Initializes <see cref="CipherAttributes"/> with <paramref name="cipherKey"/> and <paramref name="iv"/>
  /// </summary>
  /// <param name="cipherKey">Base64 encoded string that represent the <see cref="RawKey"/></param>
  /// <param name="iv"><see cref="string"/> that is 16 characters long</param>
  public CipherAttributes(CipherKey cipherKey, InitializationVector iv)
  {
    Key = cipherKey;
    IV = iv;
  }

  /// <summary>
  /// Copy constructor
  /// </summary>
  public CipherAttributes(CipherAttributes cipherAttributes)
    : this(cipherAttributes.Key, cipherAttributes.IV) { }


  /// <summary>
  /// Serializes <see cref="CipherAttributes"/>
  /// </summary>
  /// <returns>Json string with cipher attributes</returns>
  public override string ToString()
  {
    var options = new JsonSerializerOptions() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    return JsonSerializer.Serialize(this, options);
  }

}
