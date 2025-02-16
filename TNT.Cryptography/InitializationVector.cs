﻿using System.Text;
using System.Text.Json.Serialization;

namespace TNT.Cryptography;

/// <summary>
/// 
/// </summary>
public class InitializationVector
{
  private static Random Random = new Random(DateTime.Now.Millisecond);

  /// <summary>
  /// Value
  /// </summary>
  public string Value { get; set; } = string.Empty;

  /// <summary>
  /// Byte array representing <see cref="Value"/>
  /// </summary>
  [JsonIgnore]
  public byte[] ByteValue => Encoding.UTF8.GetBytes(Value);

  /// <summary>
  /// Default constructor used by deserialization
  /// </summary>
  public InitializationVector()
  {
  }

  /// <summary>
  /// Initializes with initialization vector <see cref="string"/>
  /// </summary>
  /// <param name="iv"></param>
  public InitializationVector(string iv)
  {
    Value = iv;
  }

  /// <summary>
  /// Initializes with byte array representing 16 bit initialization vector
  /// </summary>
  /// <param name="byteValue"></param>
  public InitializationVector(byte[] byteValue)
  {
    Value = Encoding.UTF8.GetString(byteValue);
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
}
