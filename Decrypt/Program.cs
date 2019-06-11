using System;
using System.IO;
using System.Xml.Linq;
using TNT.Cryptography;

namespace Decrypt
{
	class Program
	{
		static void Main(string[] args)
		{
			var parms = new Parameters();

			if (!parms.ParseArgs(args))
			{
				return;
			}

			var key = XDocument.Load(parms.Key);
			var cipherText = Convert.FromBase64String(File.ReadAllText(parms.CipherFile));

			var asymmetric = new Asymmetric(privateKey: key);
			var plainText = asymmetric.Decrypt(cipherText);

			File.WriteAllText(parms.PlainTextFile, plainText);
		}
	}
}
