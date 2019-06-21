using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TNT.Cryptography;
using TNT.Cryptography.Enumerations;
using TNT.Utilities;

namespace Tests
{
	[TestClass]
	public class SymmetricTests
	{
		string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
		static SymmetricKey symmetricKey = null;

		[ClassInitialize]
		public static void ClassInitialize(TestContext tc)
		{
			symmetricKey = Symmetric.GenerateKey(Token.Create(10), Token.Create(4), Token.Create(16));
		}

		[TestMethod]
		public void GenerateKey_Defaults()
		{
			var key = Symmetric.GenerateKey(Token.Create(10), Token.Create(4), Token.Create(16));
			string decryptedString = EncryptDecrypt(key, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void GenerateKey_MD5()
		{
			var key = Symmetric.GenerateKey(Token.Create(10), Token.Create(4), Token.Create(16), TNT.Cryptography.Enumerations.HashAlgorithm.MD5);
			string decryptedString = EncryptDecrypt(key, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void GenerateKey_KeySize128()
		{
			var key = Symmetric.GenerateKey(Token.Create(10), Token.Create(4), Token.Create(16), keySize: KeySize.Bits128);
			string decryptedString = EncryptDecrypt(key, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void GenerateKey_KeySize192()
		{
			var key = Symmetric.GenerateKey(Token.Create(10), Token.Create(4), Token.Create(16), keySize: KeySize.Bits192);
			string decryptedString = EncryptDecrypt(key, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor_SymmtricKey()
		{
			Symmetric symmetric = new Symmetric(symmetricKey);
			string decryptedString = EncryptDecrypt(symmetric, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void Constructor_Key_IV_Bytes()
		{
			Symmetric symmetric = new Symmetric(Convert.FromBase64String(symmetricKey.Key), Convert.FromBase64String(symmetricKey.IV));
			string decryptedString = EncryptDecrypt(symmetric, plainText);
			Assert.AreEqual(plainText, decryptedString);
		}

		[TestMethod]
		public void SerializeDeserialize()
		{
			byte[] serializedBytes = Symmetric.Serialize(plainText);
			string deserializedValue = Symmetric.Deserialize<string>(serializedBytes);

			Assert.AreEqual(plainText, deserializedValue);
		}

		[TestMethod]
		public void Constructor_Rijndael_Same_Key_IV()
		{
			var sut1 = new Symmetric(symmetricKey);
			var sut2 = new Symmetric(symmetricKey);
			CollectionAssert.AreEqual(sut1.Key, sut2.Key);
			CollectionAssert.AreEqual(sut1.IV, sut2.IV);
		}

		[ExpectedException(typeof(ArgumentException))]
		[TestMethod]
		public void GenerateKey_Invalid_IV_Throws_exception()
		{
			try
			{
				Symmetric.GenerateKey(Token.Create(10), Token.Create(4), Token.Create(15));
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Parameter, initVector, must be 16 characters", ex.Message);
				throw;
			}
		}

		[TestMethod]
		public void Constructor_KeyPair_AreEqual()
		{
			var sut = new Symmetric(symmetricKey);
			var key = sut.Key;
			var iv = sut.IV;
			var keyPair = sut.KeyPair;

			Assert.AreEqual(Convert.ToBase64String(key), keyPair.Key);
			Assert.AreEqual(Convert.ToBase64String(iv), keyPair.IV);
		}

		[TestMethod]
		public void EncryptDecryptString()
		{
			var symmetric = new Symmetric(symmetricKey);
			var cypherText = symmetric.Encrypt(plainText);
			var decryptedText = symmetric.Decrypt(Convert.ToBase64String(cypherText));
			Assert.AreEqual(plainText, decryptedText);
		}

		private static string EncryptDecrypt(Symmetric rijndael, string plainText)
		{
			byte[] cypher = rijndael.Encrypt(plainText);
			byte[] decryptedBytes = rijndael.Decrypt(cypher);
			return Symmetric.Deserialize<string>(decryptedBytes);
		}

		private static string EncryptDecrypt(SymmetricKey key, string plainText) => EncryptDecrypt(new Symmetric(key), plainText);
	}
}
