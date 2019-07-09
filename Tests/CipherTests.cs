using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using TNT.Cryptography;
using TNT.Utilities;

namespace Tests
{
	[TestClass]
	public class CipherTests
	{
		private static byte[] IV = Encoding.ASCII.GetBytes(Token.Create(16));
		private static readonly byte[] EncryptedContent = Encoding.ASCII.GetBytes(Token.Create(433));

		//[ClassInitialize]
		//public static void Initialize(TestContext tc)
		//{

		//}

		[TestMethod]
		public void Cipher_No_IV()
		{
			var sut = new Cipher(EncryptedContent);
			Assert.IsFalse(sut.HasIV);
			Assert.IsNull(sut.IV);
			CollectionAssert.AreEqual(EncryptedContent, sut.EncryptedContent);
		}

		[TestMethod]
		public void Cipher_With_IV()
		{
			var bytes = new List<byte>(Encoding.ASCII.GetBytes("IV"));
			bytes.AddRange(BitConverter.GetBytes(IV.Length));
			bytes.AddRange(IV);
			bytes.AddRange(EncryptedContent);

			var sut = new Cipher(bytes.ToArray());
			Assert.IsTrue(sut.HasIV);
			Assert.IsNotNull(sut.IV);
			CollectionAssert.AreEqual(IV, sut.IV);
			CollectionAssert.AreEqual(EncryptedContent, sut.EncryptedContent);
		}

		[TestMethod]
		public void ToBytes_No_IV()
		{
			var sut = new Cipher(EncryptedContent);
			var bytes = sut.ToBytes();
			CollectionAssert.AreEqual(EncryptedContent, sut.EncryptedContent);
		}

		[TestMethod]
		public void ToBytes_Add_IV()
		{
			var expected = new List<byte>(Encoding.ASCII.GetBytes("IV"));
			expected.AddRange(BitConverter.GetBytes(IV.Length));
			expected.AddRange(IV);
			expected.AddRange(EncryptedContent);

			var sut = new Cipher(EncryptedContent) { IV = IV };
			Assert.IsTrue(sut.HasIV);
			var bytes = sut.ToBytes();
			CollectionAssert.AreEqual(expected, sut.ToBytes());
		}
	}
}
