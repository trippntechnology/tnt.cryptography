using System.Text;
using System.Text.Json.Serialization;

namespace TNT.Cryptography;

/// <summary>
/// Represents an initialization vector (IV) used in cryptographic operations
/// </summary>
public class InitializationVector(string value = "")
{
  private static Random Random = new Random(DateTime.Now.Millisecond);

  /// <summary>
  /// Value
  /// </summary>
  public string Value { get; set; } = value;

  /// <summary>
  /// Byte array representing <see cref="Value"/>
  /// </summary>
  [JsonIgnore]
  public byte[] ByteValue => Encoding.UTF8.GetBytes(Value);

  /// <summary>
  /// Default constructor used by deserialization
  /// </summary>
  public InitializationVector() : this(string.Empty)
  {
  }

  /// <summary>
  /// Initializes with byte array
  /// </summary>
  /// <param name="byteValue">Byte array to be converted to a UTF-8 string</param>
  public InitializationVector(byte[] byteValue) : this(Encoding.UTF8.GetString(byteValue))
  {
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

    for (int i = 0; i < length; i++)
    {
      char randomIndex = (char)Random.Next(0, chars.Length);
      stringBuilder.Append(chars[randomIndex]);
    }

    return stringBuilder.ToString();
  }

  /// <summary>
  /// Creates a new <see cref="InitializationVector"/> with a randomly generated value
  /// </summary>
  /// <param name="length">Length of the random initialization vector string (Default: 16)</param>
  /// <returns>A new <see cref="InitializationVector"/> instance with a randomly generated value</returns>
  public static InitializationVector Create(int length = 16)
  {
    return new InitializationVector(GenerateRandomString(length));
  }
}
