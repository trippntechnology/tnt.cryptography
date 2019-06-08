using Microsoft.VisualStudio.TestTools.UnitTesting;
using TNT.Cryptography;
using TNT.Utilities;

namespace Tests
{
	[TestClass]
	public class RijndaelTests
	{
		string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";

		[TestMethod]
		public void Constructor1()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16));
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor2()
		{
			Rijndael rijndael1 = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16));
			Rijndael rijndael2 = new Rijndael(rijndael1.Key, rijndael1.IV);
			string decryptedString = EncryptDecrypt(rijndael2, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor3()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.SHA1);
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor4()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.SHA1, 10);
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor5()
		{
			Rijndael rijndael = new Rijndael(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.SHA1, 10, TNT.Cryptography.Enumerations.KeySize.Bits128);
			string decryptedString = EncryptDecrypt(rijndael, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void SerializeDeserialize()
		{
			byte[] serializedBytes = Rijndael.Serialize(plainText);
			string deserializedValue = Rijndael.Deserialize<string>(serializedBytes);

			Assert.AreEqual(plainText, deserializedValue);
		}

		[TestMethod]
		public void Constructor_Rijndael_Same_Key_IV()
		{
			var password = Token.Create(10);
			var salt = Token.Create(4);
			var iv = Token.Create(16);
			var sut1 = new Rijndael(password, salt, iv);
			var sut2 = new Rijndael(password, salt, iv);
			CollectionAssert.AreEqual(sut1.Key, sut2.Key);
			CollectionAssert.AreEqual(sut1.IV, sut2.IV);
		}

		private static string EncryptDecrypt(Rijndael rijndael, string plainText)
		{
			byte[] cypher = rijndael.Encrypt(plainText);
			byte[] decryptedBytes = rijndael.Decrypt(cypher);
			return Rijndael.Deserialize<string>(decryptedBytes);
		}
	}
}
