using System.Text;
using TNT.Cryptography;

namespace Crypto
{
	class Program
	{
		static void Main(string[] args)
		{
			//System.Diagnostics.Debugger.Break();		
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
				case ActionEnum.KEYGEN:
					KeyGen(arguments);
					break;
			}
			return;
		}

		private static void KeyGen(Arguments args)
		{
			var key = Symmetric.GenerateKey(args.PasswordKey, args.Salt);
			var fileText = Convert.ToBase64String(key);
			File.WriteAllText(args.OutputFile, fileText);
		}

		private static void Encrypt(Arguments args)
		{
			var key = File.ReadAllText(args.KeyFile);
			var iv = Symmetric.GenerateIV(args.InitVector);
			var symmetric = new Symmetric(Convert.FromBase64String(key));
			var plainText = File.ReadAllText(args.InputFile);
			var cipher = symmetric.Encrypt(Encoding.UTF8.GetBytes(plainText), iv);
			var base64String = Convert.ToBase64String(cipher);
			if (args.Format)
			{
				File.WriteAllLines(args.OutputFile, Symmetric.FormatWithTags(base64String));
			}
			else
			{
				File.WriteAllText(args.OutputFile, base64String);
			}
		}

		private static void Decrypt(Arguments args)
		{
			var key = File.ReadAllText(args.KeyFile);
			var lines = File.ReadAllLines(args.InputFile).ToList();
			var encryptedText = lines.Count > 1 ? Symmetric.RemoveTags(lines) : lines.First();
			var cipher = new Cipher(Convert.FromBase64String(encryptedText));

			if (!cipher.HasIV && args.InitVector == null) throw new ArgumentException("IV Required");

			var iv = cipher.IV ?? Symmetric.GenerateIV(args.InitVector);
			var symmetric = new Symmetric(key);
			cipher = new Cipher(cipher.EncryptedBytes, iv);
			var decryptedBytes = symmetric.Decrypt(cipher);
			var plainText = Encoding.UTF8.GetString(decryptedBytes);
			File.WriteAllText(args.OutputFile, plainText);
		}
	}
}
