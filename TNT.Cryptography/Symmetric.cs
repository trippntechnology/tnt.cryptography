using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TNT.Cryptography
{
	/// <summary>
	/// This class uses a symmetric key algorithm (System.Security.Cryptography.Rijndael/AES) 
	/// to encrypt and decrypt data. As long as encryption and decryption routines use the same 
	/// parameters to generate the keys, the keys are guaranteed to be the same. This was adapted 
	/// from code found at http://www.obviex.com/samples/Encryption.aspx.
	/// </summary>	
	public class Symmetric
	{
		private RijndaelManaged Rijndael = null;

		/// <summary>
		/// The key
		/// </summary>
		public byte[] Key { get; protected set; }

		#region Constructors

		/// <summary>
		/// Initializes a <see cref="Symmetric"/> with a key represented as a <see cref="byte"/> array
		/// </summary>
		/// <param name="key">Rijndael key</param>
		public Symmetric(byte[] key)
		{
			this.Key = key;

			// Create uninitialized Rijndael encryption object.
			Rijndael = new RijndaelManaged
			{
				// It is reasonable to set encryption mode to Cipher Block Chaining (CBC). Use default 
				// options for other symmetric key parameters.
				Mode = CipherMode.CBC
			};
		}

		/// <summary>
		/// Initializes a <see cref="Symmetric"/> with a key represented as a base 64 encoded <see cref="string"/>
		/// </summary>
		/// <param name="key">Rijndael base 64 encoded <see cref="string"/></param>
		public Symmetric(string key)
			: this(Convert.FromBase64String(key))
		{
		}

		#endregion

		/// <summary>
		/// Generates a Rijndael key
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password will be used 
		/// to generate the encryption key. Passphrase can be any string. In this example we assume that this 
		/// passphrase is an ASCII string.</param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In this example 
		/// we assume that salt is an ASCII string.
		/// </param>
		/// <param name="hashAlgorithm">
		/// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 hashes are a bit 
		/// slower, but more secure than MD5 hashes. (Default: SHA1)
		/// </param>
		/// <param name="iterations">
		/// Number of iterations used to generate password. One or two iterations should be enough. (Default: 2)
		/// </param>
		/// <param name="keySize">
		/// Size of encryption key in bits. Allowed values are: 128, 192, and 256. Longer keys are more secure than 
		/// shorter keys. (Default: Bits256)
		/// </param>
		/// <returns><see cref="byte"/> array representing the key</returns>
		public static byte[] GenerateKey(string password, string salt, Enumerations.HashAlgorithm hashAlgorithm = Enumerations.HashAlgorithm.SHA1,
										int iterations = 2, Enumerations.KeySize keySize = Enumerations.KeySize.Bits256)
		{
			byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);

			// First, create a password, from which the key will be derived. This password will be generated from the 
			// specified passphrase and salt value. The password will be created using the specified hash algorithm. 
			// Password creation can be done in several iterations.
			PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, saltValueBytes, hashAlgorithm.ToString(), iterations);

			// Use the password to generate pseudo-random bytes for the encryption key. Specify the size of the key 
			// in bytes (instead of bits).
			return passwordBytes.GetBytes((int)keySize / 8);
		}

		/// <summary>
		/// Creates an initialization vector from <paramref name="initVector"/>
		/// </summary>
		/// <param name="initVector">Initialization vector (or IV). This value is required to encrypt the 
		/// first block of plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
		/// </param>
		/// <param name="enforceRijndael">When true, enforces 16 ASCII characters restriction</param>
		/// <returns><see cref="byte"/> array representing the IV</returns>
		/// <exception cref="ArgumentException">Thrown when <paramref name="enforceRijndael"/>is true and 
		/// <paramref name="initVector"/> is not 16 characters long</exception>
		public static byte[] GenerateIV(string initVector, bool enforceRijndael = true)
		{
			if (initVector.Length != 16) throw new ArgumentException("Parameter, initVector, must be 16 characters");
			return Encoding.ASCII.GetBytes(initVector);
		}

		/// <summary>
		/// Encrypts a <see cref="string"/>
		/// </summary>
		/// <param name="unencryptedString"><see cref="string"/> to be encrypted</param>
		/// <param name="iv"><see cref="byte"/> array representing the initialization vector</param>
		/// <returns>A <see cref="Cipher"/> the encrypted <paramref name="unencryptedString"/></returns>
		public Cipher Encrypt(string unencryptedString, byte[] iv) => Encrypt(Serialize(unencryptedString), iv);

		/// <summary>
		/// Encrypts <see cref=""/> using Rijndael symmetric key algorithm
		/// </summary>
		/// <param name="plainBytes">Unencrypted bytes to be encrypted.</param>
		/// <returns>A <see cref="Cipher"/> that represents the encrypted <paramref name="plainBytes"/></returns>
		public Cipher Encrypt(byte[] plainBytes, byte[] iv)
		{
			byte[] cipherBytes;

			// Define memory stream which will be used to hold encrypted data.
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (var encryptor = Rijndael.CreateEncryptor(Key, iv))
				{
					// Define cryptographic stream (always use Write mode for encryption).
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
					{
						// Start encrypting.
						cryptoStream.Write(plainBytes, 0, plainBytes.Length);

						// Finish encrypting.
						cryptoStream.FlushFinalBlock();

						// Convert our encrypted data from a memory stream into a byte array.
						cipherBytes = memoryStream.ToArray();
					}
				}
			}

			// return encrypted bytes
			return new Cipher(cipherBytes) { IV = iv };
		}

		/// <summary>
		/// Decrypts a base64 encoded string and returns the decrypted string 
		/// </summary>
		/// <param name="base64Cypher">Base64 cypher text to decrypt</param>
		/// <param name="iv">Initialization vector</param>
		/// <returns>Decrypted text from <paramref name="base64Cypher"/></returns>
		public string Decrypt(string base64Cypher, byte[] iv) => Deserialize<string>(Decrypt(new Cipher(Convert.FromBase64String(base64Cypher)) { IV = iv }));

		/// <summary>
		/// Decrypts content represented by <paramref name="cipher"/> using Rijndael symmetric key algorithm.
		/// </summary>
		/// <param name="cipher"><see cref="Cipher"/> that contains the encrypted content</param>
		/// <param name="initVector">Optional initialization vector. If an IV is provided in <paramref name="cipher"/>
		/// that IV will be used.</param>
		/// <returns>Decrypted byte array</returns>
		/// <remarks>
		/// Most of the logic in this function is similar to the Encrypt logic. In order for decryption 
		/// to work, all parameters of this function - except cipherText value - must match the corresponding 
		/// parameters of the Encrypt function which was called to generate the ciphertext.
		/// </remarks>
		/// <exception cref="ArgumentException">Thrown if an IV is not supplied either in the <paramref name="cipher"/> or 
		/// <paramref name="initVector"/></exception>
		public byte[] Decrypt(Cipher cipher, byte[] initVector = null)
		{
			byte[] plainBytes;
			var iv = cipher.IV ?? initVector;

			if (iv == null) throw new ArgumentException("Initialization vector must be supplied");

			// Define memory stream which will be used to hold encrypted data.
			using (MemoryStream memoryStream = new MemoryStream(cipher.EncryptedContent))
			{
				using (var decryptor = Rijndael.CreateDecryptor(this.Key, iv))
				{
					// Define cryptographic stream (always use Read mode for encryption).
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
					{
						// Since at this point we don't know what the size of decrypted data will be, allocate the buffer 
						// long enough to hold ciphertext. Plaintext is never longer than ciphertext.
						plainBytes = new byte[cipher.EncryptedContent.Length];

						// Start decrypting.
						int decryptedByteCount = cryptoStream.Read(plainBytes, 0, plainBytes.Length);
					}
				}
			}

			// Return decrypted string.   
			return plainBytes;
		}

		/// <summary>
		/// Serializes <paramref name="obj"/> into a <see cref="byte"/> array
		/// </summary>
		/// <param name="obj"><see cref="object"/> to serialize</param>
		/// <returns>A <see cref="byte"/> array that represents <paramref name="obj"/></returns>
		public static byte[] Serialize(object obj)
		{
			byte[] bytes;

			using (MemoryStream ms = new MemoryStream())
			{
				BinaryFormatter bf = new BinaryFormatter();
				bf.Serialize(ms, obj);
				bytes = ms.ToArray();
			}

			return bytes;
		}

		/// <summary>
		/// Deserializes <paramref name="bytes"/> into the object of type <typeparamref name="T"/>
		/// </summary>
		/// <typeparam name="T">Object type that should be returned</typeparam>
		/// <param name="bytes"><see cref="byte"/> array that should be deserialized</param>
		/// <returns>Object of type <typeparamref name="T"/> that is represented by the serialized <paramref name="bytes"/></returns>
		public static T Deserialize<T>(byte[] bytes)
		{
			T obj;

			using (MemoryStream ms = new MemoryStream(bytes))
			{
				BinaryFormatter bf = new BinaryFormatter();
				obj = (T)bf.Deserialize(ms);
			}

			return obj;
		}
	}
}