using System.Text;
using System.Text.Json;
using TNT.Cryptography;

namespace Crypto
{
  class Program
  {
    static void Main(string[] args)
    {
      //System.Diagnostics.Debugger.Launch();
      var arguments = new Arguments();

      if (!arguments.Parse(args)) { return; }

      switch (arguments.Action)
      {
        case ActionEnum.DECRYPT:
          Decrypt(arguments);
          break;
        case ActionEnum.ENCRYPT:
          Encrypt(arguments);
          break;
        case ActionEnum.GEN_CA:
          GenCa(arguments);
          break;
      }
      return;
    }

    private static void GenCa(Arguments args)
    {
      var cipherKey = new CipherKey(args.PasswordKey!, 0);
      var iv = new InitializationVector();
      CipherAttributes cipherAttrs = new CipherAttributes(cipherKey, iv);
      Console.WriteLine($"ca.Key: {cipherAttrs.Key.EncodedValue}  ca.IV: {cipherAttrs.IV.Value}");
      var caJson = cipherAttrs.ToString();
      File.WriteAllText(args.OutputFile!, caJson);
      Console.WriteLine($"Written to {args.OutputFile}");
      Console.WriteLine(caJson);
    }

    private static void Encrypt(Arguments args)
    {
      string caJson = File.ReadAllText(args.CAFile!);
      CipherAttributes? cipherAttrs = JsonSerializer.Deserialize<CipherAttributes>(caJson);
      if (cipherAttrs == null) return;

      SymmetricCipher cipher = new SymmetricCipher(cipherAttrs);

      string plainText = File.ReadAllText(args.InputFile!);
      byte[] cipherText = cipher.Encrypt(Encoding.UTF8.GetBytes(plainText));
      string base64String = Convert.ToBase64String(cipherText);
      if (args.Format)
      {
        File.WriteAllLines(args.OutputFile!, FormatUtils.FormatWithTags(base64String));
      }
      else
      {
        File.WriteAllText(args.OutputFile!, base64String);
      }
    }

    private static void Decrypt(Arguments args)
    {
      string caJson = File.ReadAllText(args.CAFile!);
      CipherAttributes? cipherAttrs = JsonSerializer.Deserialize<CipherAttributes>(caJson);
      if (cipherAttrs == null) return;

      SymmetricCipher cipher = new SymmetricCipher(cipherAttrs);

      List<string> lines = File.ReadAllLines(args.InputFile!).ToList();
      string encryptedText = lines.Count > 1 ? FormatUtils.RemoveTags(lines) : lines.First();
      byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

      byte[] decryptedBytes = cipher.Decrypt(encryptedBytes);
      string plainText = Encoding.UTF8.GetString(decryptedBytes);
      File.WriteAllText(args.OutputFile!, plainText);
    }
  }
}
