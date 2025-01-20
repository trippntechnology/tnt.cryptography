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
      CipherAttributes ca = new CipherAttributes(args.PasswordKey!);
      var caJson = ca.ToString();
      File.WriteAllText(args.OutputFile!, caJson);
      Console.WriteLine($"Written to {args.OutputFile}");
      Console.WriteLine(caJson);
    }

    private static void Encrypt(Arguments args)
    {
      string caJson = File.ReadAllText(args.CAFile!);
      CA? ca = JsonSerializer.Deserialize<CA>(caJson);
      if (ca == null) return;

      CipherAttributes cipherAttrs = new CipherAttributes(ca.Key, ca.IV);
      SymmetricCipher cipher = new SymmetricCipher(cipherAttrs);

      string plainText = File.ReadAllText(args.InputFile!);
      byte[] cipherText = cipher.Encypt(Encoding.UTF8.GetBytes(plainText));
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
      CA? ca = JsonSerializer.Deserialize<CA>(caJson);
      if (ca == null) return;

      CipherAttributes cipherAttrs = new CipherAttributes(ca.Key, ca.IV);
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
