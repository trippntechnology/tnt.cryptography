namespace TNT.Cryptography;

/// <summary>
/// Utility class to format content
/// </summary>
public static class FormatUtils
{
  /// <summary>
  /// Tag used before the encrypted text
  /// </summary>
  public const string BEGIN_TAG = "--- BEGIN ---";

  /// <summary>
  /// Tag used after the encrypted text
  /// </summary>
  public const string END_TAG = "--- END ---";

  /// <summary>
  /// Adds the <see cref="BEGIN_TAG"/> and <see cref="END_TAG"/> and formats so that 
  /// the longest line is <paramref name="maxLineLength"/>
  /// </summary>
  /// <param name="content"><see cref="string"/> to format between tags</param>
  /// <param name="maxLineLength">Max line length (Default: 80)</param>
  /// <returns><see cref="List{String}"/> with the content formatted between tags</returns>
  public static List<string> FormatWithTags(string content, int maxLineLength = 80)
  {
    List<string> formatted = new List<string>();

    if (string.IsNullOrWhiteSpace(content)) return formatted;

    formatted.Add(BEGIN_TAG);

    while (content.Length > 0)
    {
      string subString = string.Empty;
      if (content.Length >= maxLineLength)
      {
        subString = content.Substring(0, maxLineLength);
        content = content.Substring(maxLineLength);
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
  /// <returns>Content unformatted</returns>
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
