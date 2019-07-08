using System;
using System.IO;
using TNT.Cryptography;
using TNT.Utilities;

namespace Crypto
{
	class Program
	{
		static void Main(string[] args)
		{
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
			var key = Symmetric.GenerateKey(args.PasswordKey, Token.Create(4));
			var fileText = Convert.ToBase64String(key);
			File.WriteAllText(args.OutputFile, fileText);
		}

		private static void Encrypt(Arguments args)
		{
			var key = File.ReadAllText(args.KeyFile);
			var iv = Symmetric.GenerateIV(args.InitVector);
			var symmetric = new Symmetric(Convert.FromBase64String(key));
			var plainText = File.ReadAllText(args.InputFile);
			var cipher = symmetric.Encrypt(plainText, iv);
			File.WriteAllText(args.OutputFile, Convert.ToBase64String(cipher.ToBytes()));
		}

		private static void Decrypt(Arguments args)
		{
			var key = File.ReadAllText(args.KeyFile);
			var encryptedText = File.ReadAllText(args.InputFile);
			var cipher = new Cipher(Convert.FromBase64String(encryptedText));

			if (!cipher.HasIV && args.InitVector == null) throw new ArgumentException("IV Required");

			var iv = cipher.IV ?? Symmetric.GenerateIV(args.InitVector);
			var symmetric = new Symmetric(key);
			 var decryptedBytes = symmetric.Decrypt(cipher, iv);
			var plainText = Symmetric.Deserialize<string>(decryptedBytes);
			File.WriteAllText(args.OutputFile, plainText);
		}
	}
}
