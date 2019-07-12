using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using TNT.Cryptography;
using TNT.Cryptography.Enumerations;
using TNT.Utilities;

namespace Tests
{
	[TestClass]
	public class SymmetricTests
	{
		readonly string plainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean in est et ex facilisis tincidunt vitae in urna. Aenean sed dolor eget arcu varius rutrum. Proin eget justo placerat, porttitor turpis ac, scelerisque augue. Donec eget commodo nulla, vel mattis eros. Curabitur pretium eros sed commodo ultricies. Quisque cursus eget orci et cursus. In pellentesque imperdiet dolor, vel cursus neque dignissim quis.";
		readonly byte[] key = Symmetric.GenerateKey(Token.Create(10), Token.Create(4));
		readonly byte[] iv = Symmetric.GenerateIV(Token.Create(16));

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

		[TestMethod]
		public void FormatWithTags_NullOrEmpty_EmptyList()
		{
			Assert.AreEqual(0, Symmetric.FormatWithTags(null).Count);
		}

		[TestMethod]
		public void FormatWithTags_79Characters_SingleLine()
		{
			var line = Token.Create(79);
			var result = Symmetric.FormatWithTags(line);
			var expected = new List<string>()
			{
				Symmetric.BEGIN_TAG,
				line,
				Symmetric.END_TAG
			};
			CollectionAssert.AreEqual(expected, result);
		}

		[TestMethod]
		public void FormatWithTags_80Characters_SingleLine()
		{
			var line = Token.Create(80);
			var result = Symmetric.FormatWithTags(line);
			var expected = new List<string>()
			{
				Symmetric.BEGIN_TAG,
				line,
				Symmetric.END_TAG
			};
			CollectionAssert.AreEqual(expected, result);
		}

		[TestMethod]
		public void FormatWithTags_81Characters_SingleLine()
		{
			var line = Token.Create(81);
			var result = Symmetric.FormatWithTags(line);
			var expected = new List<string>()
			{
				Symmetric.BEGIN_TAG,
				line.Substring(0,80),
				line.Substring(80),
				Symmetric.END_TAG
			};
			CollectionAssert.AreEqual(expected, result);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void RemoveTags_NoTags()
		{
			try
			{
				var line1 = Token.Create(20);
				var line2 = Token.Create(20);
				var line3 = Token.Create(20);
				var lines = new List<string>() { line1, line2, line3 };
				var result = Symmetric.RemoveTags(lines);
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Unexpected format", ex.Message);
				throw;
			}
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void RemoveTags_BeginTagOnly()
		{
			try
			{
				var line1 = Token.Create(20);
				var line2 = Token.Create(20);
				var line3 = Token.Create(20);
				var lines = new List<string>() { Symmetric.BEGIN_TAG, line1, line2, line3 };
				var result = Symmetric.RemoveTags(lines);
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Unexpected format", ex.Message);
				throw;
			}
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void RemoveTags_EndTagOnly()
		{
			try
			{
				var line1 = Token.Create(20);
				var line2 = Token.Create(20);
				var line3 = Token.Create(20);
				var lines = new List<string>() { line1, line2, line3, Symmetric.END_TAG };
				var result = Symmetric.RemoveTags(lines);
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Unexpected format", ex.Message);
				throw;
			}
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void RemoveTags_EndBeforeBegin()
		{
			try
			{
				var lines = new List<string>() { Symmetric.END_TAG, Symmetric.BEGIN_TAG };
				var result = Symmetric.RemoveTags(lines);
			}
			catch (Exception ex)
			{
				Assert.AreEqual("Unexpected format", ex.Message);
				throw;
			}
		}

		[TestMethod]
		public void RemoveTags_NoContent()
		{
			var lines = new List<string>() { Symmetric.BEGIN_TAG, Symmetric.END_TAG };
			var result = Symmetric.RemoveTags(lines);
			Assert.AreEqual(string.Empty, result);
		}


		[TestMethod]
		public void RemoveTags_Joins()
		{
			var line1 = Token.Create(20);
			var line2 = Token.Create(20);
			var line3 = Token.Create(20);
			var lines = new List<string>() { Symmetric.BEGIN_TAG, line1, line2, line3, Symmetric.END_TAG };

			var result = Symmetric.RemoveTags(lines);
			Assert.AreEqual(string.Concat(line1, line2, line3), result);
		}

		[TestMethod]
		public void RemoveTags_RemoveLeadingTrailingNoise()
		{
			var line1 = Token.Create(20);
			var line2 = Token.Create(20);
			var line3 = Token.Create(20);
			var lines = new List<string>() { Token.Create(20), Symmetric.BEGIN_TAG, line1, line2, line3, Symmetric.END_TAG, Token.Create(20) };

			var result = Symmetric.RemoveTags(lines);
			Assert.AreEqual(string.Concat(line1, line2, line3), result);
		}
	}
}