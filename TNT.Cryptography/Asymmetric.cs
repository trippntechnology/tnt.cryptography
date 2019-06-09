using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace TNT.Cryptography
{
	/// <summary>
	/// Class that wraps asymmetric encryption using RSA. Much of this code was take from the
	/// examples found at https://www.c-sharpcorner.com/article/implement-symmetric-and-asymmetric-cryptography-algorithms-with-c-sharp/
	/// </summary>
	public class Asymmetric
	{
		private const int KEY_SIZE = 2048;
		private const int PLAIN_BLOCK_SIZE = 244; // Size of plain block that can be encrypted at a time
		private const int CIPHER_BLOCK_SIZE = 256; // Size of cipher block that can be decrypted at a time

		/// <summary>
		/// The public key that is used to encrypt
		/// </summary>
		public XDocument PublicKey { get; private set; }

		/// <summary>
		/// The private key that is used to decrypt
		/// </summary>
		public XDocument PrivateKey { get; private set; }

		/// <summary>
		/// Creates a <see cref="Asymmetric"/> class with the a generated public and private key pair if both 
		/// <paramref name="publicKey"/> and <paramref name="privateKey"/> are null. Otherwise, the class is generated
		/// with the key provided. A <paramref name="publicKey"/> is needed for encryption and a <paramref name="privateKey"/>
		/// is needed for decryption.
		/// </summary>
		/// <param name="publicKey">Encryption key</param>
		/// <param name="privateKey">Decryption key</param>
		public Asymmetric(XDocument publicKey = null, XDocument privateKey = null)
		{
			if (publicKey == null && privateKey == null)
			{
				var rsa = new RSACryptoServiceProvider(KEY_SIZE);

				this.PublicKey = XDocument.Parse(rsa.ToXmlString(false)); // false to get the public key
				this.PrivateKey = XDocument.Parse(rsa.ToXmlString(true)); // true to get the private key
			}
			else
			{
				this.PublicKey = publicKey;
				this.PrivateKey = privateKey;
			}
		}

		/// <summary>
		/// Encrypts the <paramref name="plainText"/> if a <see cref="PublicKey"/> was provided when <see cref="Asymmetric"/>
		/// instance was created.
		/// </summary>
		/// <param name="plainText"><see cref="string"/> to be encrypted</param>
		/// <exception cref="CryptographicException">Thrown when a public key is not available</exception>
		/// <returns>A <see cref="byte"/> array representing the encrypted <paramref name="plainText"/></returns>
		public byte[] Encrypt(string plainText)
		{
			if (this.PublicKey == null) throw new CryptographicException("PublicKey missing.");

			// Convert the text to an array of bytes   
			UnicodeEncoding byteConverter = new UnicodeEncoding();
			var dataToEncrypt = new List<byte>(byteConverter.GetBytes(plainText));

			// Create a byte array to store the encrypted data in it   
			var encryptedData = new List<byte>();
			using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				// Set the rsa key   
				rsa.FromXmlString(PublicKey.ToString());

				while (dataToEncrypt.Count > 0)
				{
					var plainBlock = dataToEncrypt.GetRange(0, Math.Min(PLAIN_BLOCK_SIZE, dataToEncrypt.Count)).ToArray();
					encryptedData.AddRange(rsa.Encrypt(plainBlock, false));
					dataToEncrypt = dataToEncrypt.GetRange(plainBlock.Length, dataToEncrypt.Count - plainBlock.Length);
				}
			}

			return encryptedData.ToArray();
		}

		/// <summary>
		/// Decrypts the <paramref name="encryptedBytes"/> if a <see cref="PrivateKey"/> was provided when <see cref="Asymmetric"/>
		/// instance was created.
		/// </summary>
		/// <param name="encryptedBytes"><see cref="byte"/> array to be decrypted</param>
		/// <exception cref="CryptographicException">Thrown when a private key is not available or the <paramref name="encryptedBytes"/>
		/// length is not divisible by <see cref="CIPHER_BLOCK_SIZE"/></exception>
		/// <returns>a <see cref="string"/> that was decrypted from <paramref name="encryptedBytes"/></returns>
		public string Decrypt(byte[] encryptedBytes)
		{
			if (this.PrivateKey == null) throw new CryptographicException("PrivateKey missing.");
			if (encryptedBytes.Length % CIPHER_BLOCK_SIZE != 0) throw new CryptographicException($"Parameter encryptedBytes must be divisible by {CIPHER_BLOCK_SIZE}.");

			var _encryptedBytes = new List<byte>(encryptedBytes);
			// Create an array to store the decrypted data in it   
			var decryptedBytes = new List<byte>();

			using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				// Set the private key of the algorithm   
				rsa.FromXmlString(PrivateKey.ToString());

				while (_encryptedBytes.Count > 0)
				{
					var encryptedBlock = _encryptedBytes.GetRange(0, CIPHER_BLOCK_SIZE).ToArray();
					//var decryptedBlock = rsa.Decrypt(encryptedBlock, false);
					decryptedBytes.AddRange(rsa.Decrypt(encryptedBlock, false));
					_encryptedBytes = _encryptedBytes.GetRange(CIPHER_BLOCK_SIZE, _encryptedBytes.Count - encryptedBlock.Length);
				}
			}

			// Get the string value from the decryptedData byte array   
			UnicodeEncoding byteConverter = new UnicodeEncoding();
			return byteConverter.GetString(decryptedBytes.ToArray());
		}
	}
}