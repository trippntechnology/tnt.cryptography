using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TNT.Cryptography;
using TNT.Utilities;

namespace Tests
{
	[TestClass]
	public class RijndaelTests
	{
		[TestMethod]
		public void Constructor1()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16));
			string plainText = "MacAddress|" + DateTime.Now.ToString();// @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor2()
		{
			Rijndael rijndael1 = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16));
			Rijndael rijndael2 = new Rijndael(rijndael1.Key, rijndael1.IV);
			string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
			string decryptedString = EncryptDecrypt(rijndael2, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor3()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.SHA1);
			string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor4()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.SHA1, 10);
			string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor5()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.SHA1, 10, TNT.Cryptography.Enumerations.KeySize.Bits128);
			string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void SerializeDeserialize()
		{
			string value = @"Curabitur ut justo vulputate, venenatis tortor tincidunt, rutrum mauris. Proin faucibus porta lorem, id semper ligula porta vitae. Proin blandit, ante vel rhoncus laoreet, mi mi accumsan magna, vitae dictum tellus risus vel purus. Duis a felis neque. Morbi posuere eu eros sed placerat. Sed leo purus, porta a ante ut, aliquam condimentum odio. Aliquam ac libero aliquam, placerat justo in, laoreet ex. Quisque maximus nisl vitae nulla rhoncus luctus nec et orci. Sed nec nisi aliquet, vestibulum mi quis, fermentum ipsum. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae;";

			byte[] serializedBytes = Rijndael.Serialize(value);
			string deserializedValue = Rijndael.Deserialize<string>(serializedBytes);

			Assert.AreEqual(value, deserializedValue);
		}

		//[TestMethod]
		//public void EncryptWriteReadDecrypt()
		//{
		//	string value = @"Curabitur ut justo vulputate, venenatis tortor tincidunt, rutrum mauris. Proin faucibus porta lorem, id semper ligula porta vitae. Proin blandit, ante vel rhoncus laoreet, mi mi accumsan magna, vitae dictum tellus risus vel purus. Duis a felis neque. Morbi posuere eu eros sed placerat. Sed leo purus, porta a ante ut, aliquam condimentum odio. Aliquam ac libero aliquam, placerat justo in, laoreet ex. Quisque maximus nisl vitae nulla rhoncus luctus nec et orci. Sed nec nisi aliquet, vestibulum mi quis, fermentum ipsum. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae;";
		//	Rijndael rijndael = new Rijndael("the password", "the salt", "akevlstjeocpsvfr");
		//	string fileName = Path.GetTempFileName();

		//	byte[] valueBytes = Encoding.UTF8.GetBytes(value);
		//	rijndael.EncryptAndWrite(valueBytes, fileName);
		//	byte[] decryptedBytes = rijndael.ReadAndDecrypt(fileName);

		//	Assert.AreEqual(valueBytes, decryptedBytes);

		//	string decryptedString = Rijndael.Deserialize<string>(decryptedBytes);

		//	Assert.AreEqual(value, decryptedString);				
		//}

		private static string EncryptDecrypt(Rijndael rijndael, string plainText)
		{
			byte[] cypher = rijndael.Encrypt(plainText);
			byte[] decryptedBytes = rijndael.Decrypt(cypher);
			string decryptedString = Rijndael.Deserialize<string>(decryptedBytes);
			return decryptedString;
		}
	}
}
