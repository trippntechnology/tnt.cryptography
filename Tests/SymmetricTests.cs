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
		byte[] key = Symmetric.GenerateKey(Token.Create(10), Token.Create(4));
		byte[] iv = Symmetric.GenerateIV(Token.Create(16));

		[TestMethod]
		public void Constructor_WithByteArray()
		{
			var key = Symmetric.GenerateKey("Constructor_WithByteArray", "salt");
			var sut = new Symmetric(key);
			Assert.AreEqual(key, sut.Key);
		}

		[TestMethod]
		public void Constructor_WithBase64String()
		{
			var key = Convert.ToBase64String(Symmetric.GenerateKey("Constructor_WithByteArray", "salt"));
			var sut = new Symmetric(key);
			Assert.AreEqual(key, Convert.ToBase64String(sut.Key));
		}

		[TestMethod]
		public void GenerateKey_Defaults()
		{
			var key = Symmetric.GenerateKey("GenerateKey_Defaults", "salt");
			var keyB64 = Convert.ToBase64String(key);
			Assert.AreEqual("XMIqI9XOfHYsg0+y7vtLvGReLaWs1z6QwM+9faMjSXw=", keyB64);
		}

		[TestMethod]
		public void GenerateKey_MD5()
		{
			var key = Symmetric.GenerateKey("GenerateKey_MD5", "salt", TNT.Cryptography.Enumerations.HashAlgorithm.MD5);
			var keyB64 = Convert.ToBase64String(key);
			Assert.AreEqual("oaVJMDQueZox8TP9E9Wrz0Fwxquezw3Sw7JjmdRIBHs=", keyB64);
		}

		[TestMethod]
		public void GenerateKey_KeySize128()
		{
			var key = Symmetric.GenerateKey("GenerateKey_KeySize128", "salt", keySize: KeySize.Bits128);
			var keyB64 = Convert.ToBase64String(key);
			Assert.AreEqual("MPkpMHyGEYhK9ymWaVSMfg==", keyB64);
		}

		[TestMethod]
		public void GenerateKey_KeySize192()
		{
			var key = Symmetric.GenerateKey("GenerateKey_KeySize192", "salt", keySize: KeySize.Bits192);
			var keyB64 = Convert.ToBase64String(key);
			Assert.AreEqual("eJmnbYPLuu1cUx4WRfUgH/PXzhQI7NLp", keyB64);
		}

		[TestMethod]
		public void GenerateIV_Defaults()
		{
			var iv = Symmetric.GenerateIV("GenerateIV_Defau");
			var ivB64 = Convert.ToBase64String(iv);
			Assert.AreEqual("R2VuZXJhdGVJVl9EZWZhdQ==", ivB64);
		}

		[ExpectedException(typeof(ArgumentException))]
		[TestMethod]
		public void GenerateIV_ShortInitVector()
		{
			try
			{
				var iv = Symmetric.GenerateIV("GenerateIV_Defa");
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Parameter, initVector, must be 16 characters", ex.Message);
				throw;
			}
		}

		[TestMethod]
		public void SerializeDeserialize()
		{
			byte[] serializedBytes = Symmetric.Serialize(plainText);
			string deserializedValue = Symmetric.Deserialize<string>(serializedBytes);

			Assert.AreEqual(plainText, deserializedValue);
		}

		[TestMethod]
		public void EncryptDecryptString_AppendIV()
		{
			var symmetric = new Symmetric(key);
			var cipher = symmetric.Encrypt(plainText, iv);
			var decryptedText = symmetric.Decrypt(cipher);
			Assert.AreEqual(plainText, Symmetric.Deserialize<string>(decryptedText));
		}

		[TestMethod]
		public void Decrypt_WithBase64CipherAndIV()
		{
			var symmetric = new Symmetric(key);
			var cipher = symmetric.Encrypt(plainText, iv);
			var decryptedText = symmetric.Decrypt(Convert.ToBase64String(cipher.EncryptedContent), iv);
			Assert.AreEqual(plainText, decryptedText);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void Decrypt_NoCipherIV()
		{
			try
			{
				var symmetric = new Symmetric(key);
				var cipher = symmetric.Encrypt(plainText, iv);
				cipher.IV = null;
				Assert.IsFalse(cipher.HasIV);
				var decryptedText = symmetric.Decrypt(cipher);
				Assert.AreEqual(plainText, decryptedText);
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Initialization vector must be supplied", ex.Message);
				throw;
			}
		}
	}
}
