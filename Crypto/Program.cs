using System;
using System.IO;
using System.Xml.Linq;
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
			var symmetric = new Symmetric(Symmetric.GenerateKey(Token.Create(16), Token.Create(4), Token.Create(16)));
			var keyPair = symmetric.KeyPair;
			var fileText = TNT.Utilities.Utilities.Serialize<SymmetricKey>(keyPair, null);
			var fileXml = XDocument.Parse(fileText);
			fileXml.Save(args.OutputFile);
		}

		private static void Encrypt(Arguments args)
		{
			var symmetric = LoadSymmetric(args.KeyFile);
			var plainText = File.ReadAllText(args.InputFile);
			var cypherText = symmetric.Encrypt(plainText);
			File.WriteAllText(args.OutputFile, Convert.ToBase64String(cypherText));
		}

		private static void Decrypt(Arguments args)
		{
			var symmetric = LoadSymmetric(args.KeyFile);
			var cypherText = File.ReadAllText(args.InputFile);
			var plainText = symmetric.Decrypt(cypherText);
			File.WriteAllText(args.OutputFile, plainText);
		}

		private static Symmetric LoadSymmetric(string fileName)
		{
			var keyFile = XDocument.Load(fileName);
			var symmetricKey = Utilities.Deserialize<SymmetricKey>(keyFile.ToString(), new Type[0]);
			return new Symmetric(symmetricKey);
		}
	}
}
