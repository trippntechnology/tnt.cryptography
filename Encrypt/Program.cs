using System;
using System.IO;
using System.Xml.Linq;
using TNT.Cryptography;

namespace Encrypt
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
			var plainText = File.ReadAllText(parms.PlainTextFile);

			var asymmetric = new Asymmetric(key);
			var cipherText = asymmetric.Encrypt(plainText);

			File.WriteAllText(parms.CipherFile, Convert.ToBase64String(cipherText));
		}
	}
}
