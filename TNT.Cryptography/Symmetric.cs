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
		/// <summary>
		/// The key
		/// </summary>
		public byte[] Key { get; protected set; }

		/// <summary>
		/// The initialization vector
		/// </summary>
		public byte[] IV { get; protected set; }

		/// <summary>
		/// Encryptor member
		/// </summary>
		protected ICryptoTransform m_Encryptor;

		/// <summary>
		/// Decryptor member
		/// </summary>
		protected ICryptoTransform m_Decryptor;

		#region Constructors

		/// <summary>
		/// Constructor. Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password will be used 
		/// to generate the encryption key. Passphrase can be any string. In this example we assume that this 
		/// passphrase is an ASCII string.</param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In this example 
		/// we assume that salt is an ASCII string.
		/// </param>
		/// <param name="initVector">
		/// Initialization vector (or IV). This value is required to encrypt the first block of plaintext data. 
		/// For RijndaelManaged class IV must be exactly 16 ASCII characters long.
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
		/// <exception cref="ArgumentException">When <paramref name="initVector"/> is not the correct length</exception>
		public Symmetric(string password, string salt, string initVector, Enumerations.HashAlgorithm hashAlgorithm = Enumerations.HashAlgorithm.SHA1, 
										int iterations = 2, Enumerations.KeySize keySize = Enumerations.KeySize.Bits256)
		{
			if (initVector.Length != 16) throw new ArgumentException("Parameter, initVector, must be 16 characters");

			byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);

			// First, create a password, from which the key will be derived. This password will be generated from the 
			// specified passphrase and salt value. The password will be created using the specified hash algorithm. 
			// Password creation can be done in several iterations.
			PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, saltValueBytes, hashAlgorithm.ToString(), iterations);

			// Use the password to generate pseudo-random bytes for the encryption key. Specify the size of the key 
			// in bytes (instead of bits).
			var key = passwordBytes.GetBytes((int)keySize / 8);

			// Convert strings into byte arrays. Assumes that strings only contain ASCII codes.
			var iv = Encoding.ASCII.GetBytes(initVector);

			Initialize(key, iv);
		}

		/// <summary>
		/// Constructor. Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="keyBytes">Bytes that represent a previously generated <see cref="Key"/></param>
		/// <param name="initVectorBytes">Bytes that represent a previously generated initialization vector</param>
		public Symmetric(byte[] keyBytes, byte[] initVectorBytes)
		{
			Initialize(keyBytes, initVectorBytes);
		}

		/// <summary>
		/// Initializes the <see cref="Key"/> and <see cref="IV"/> with the <paramref name="keyBytes"/> and
		/// <paramref name="initVectorBytes"/> respectively which are used to generate the encryptor and decryptor.
		/// </summary>
		/// <param name="keyBytes">Bytes that represent the <see cref="Key"/></param>
		/// <param name="initVectorBytes">Bytes that represent the <see cref="IV"/></param>
		private void Initialize(byte[] keyBytes, byte[] initVectorBytes)
		{
			this.Key = keyBytes;
			this.IV = initVectorBytes;

			// Create uninitialized Rijndael encryption object.
			RijndaelManaged symmetricKey = new RijndaelManaged();

			// It is reasonable to set encryption mode to Cipher Block Chaining (CBC). Use default 
			// options for other symmetric key parameters.
			symmetricKey.Mode = CipherMode.CBC;

			// Generate encryptor from the existing key bytes and initialization vector. Key size 
			// will be defined based on the number of the key bytes.
			m_Encryptor = symmetricKey.CreateEncryptor(this.Key, this.IV);

			// Generate decryptor from the existing key bytes and initialization vector. Key size 
			// will be defined based on the number of the key bytes.
			m_Decryptor = symmetricKey.CreateDecryptor(this.Key, this.IV);
		}

		#endregion

		/// <summary>
		/// Encrypts a <see cref="string"/>
		/// </summary>
		/// <param name="unencryptedString"><see cref="string"/> to be encrypted</param>
		/// <returns><see cref="byte"/> array that represents the encrypted <see cref="string"/> <paramref name="unencryptedString"/></returns>
		public byte[] Encrypt(string unencryptedString) => Encrypt(Serialize(unencryptedString));

		/// <summary>
		/// Encrypts specified unencrypted bytes using Rijndael symmetric key algorithm and returns a 
		/// an encrypted byte array.
		/// </summary>
		/// <param name="unencryptedBytes">Unencrypted bytes to be encrypted.</param>
		/// <returns>Encrypted bytes</returns>
		public byte[] Encrypt(byte[] unencryptedBytes)
		{
			byte[] cipherTextBytes;

			// Define memory stream which will be used to hold encrypted data.
			using (MemoryStream memoryStream = new MemoryStream())
			{
				// Define cryptographic stream (always use Write mode for encryption).
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, m_Encryptor, CryptoStreamMode.Write))
				{
					// Start encrypting.
					cryptoStream.Write(unencryptedBytes, 0, unencryptedBytes.Length);

					// Finish encrypting.
					cryptoStream.FlushFinalBlock();

					// Convert our encrypted data from a memory stream into a byte array.
					cipherTextBytes = memoryStream.ToArray();
				}
			}

			// return encrypted bytes
			return cipherTextBytes;
		}

		/// <summary>
		/// Decrypts specified cipherBytes using Rijndael symmetric key algorithm.
		/// </summary>
		/// <param name="cipherBytes">Encrypted byte array</param>
		/// <returns>Decrypted byte array</returns>
		/// <remarks>
		/// Most of the logic in this function is similar to the Encrypt logic. In order for decryption 
		/// to work, all parameters of this function - except cipherText value - must match the corresponding 
		/// parameters of the Encrypt function which was called to generate the ciphertext.
		/// </remarks>
		public byte[] Decrypt(byte[] cipherBytes)
		{
			byte[] unencryptedBytes;

			// Define memory stream which will be used to hold encrypted data.
			using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
			{
				// Define cryptographic stream (always use Read mode for encryption).
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, m_Decryptor, CryptoStreamMode.Read))
				{
					// Since at this point we don't know what the size of decrypted data will be, allocate the buffer 
					// long enough to hold ciphertext. Plaintext is never longer than ciphertext.
					unencryptedBytes = new byte[cipherBytes.Length];

					// Start decrypting.
					int decryptedByteCount = cryptoStream.Read(unencryptedBytes, 0, unencryptedBytes.Length);
				}
			}

			// Return decrypted string.   
			return unencryptedBytes;
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