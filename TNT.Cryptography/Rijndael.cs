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
	public class Rijndael
	{
		public byte[] Key { get; protected set; }

		public byte[] IV { get; protected set; }

		#region Members

		/// <summary>
		/// Encryptor member
		/// </summary>
		protected ICryptoTransform m_Encryptor;

		/// <summary>
		/// Decryptor member
		/// </summary>
		protected ICryptoTransform m_Decryptor;

		#endregion

		#region Constructors
		
		/// <summary>
		/// Constructor. Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password 
		/// will be used to generate the encryption key. Passphrase can be any string. In this 
		/// example we assume that this passphrase is an ASCII string.
		/// </param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In 
		/// this example we assume that salt is an ASCII string.
		/// </param>
		/// <param name="initVector">
		/// Initialization vector (or IV). This value is required to encrypt the first block of 
		/// plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
		/// </param>
		/// <param name="hashAlgorithm">
		/// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 
		/// hashes are a bit slower, but more secure than MD5 hashes. (Default: SHA1)
		/// </param>
		/// <param name="iterations">
		/// Number of iterations used to generate password. One or two iterations should be enough. (Default: 2)
		/// </param>
		/// <param name="keySize">
		/// Size of encryption key in bits. Allowed values are: 128, 192, and 256. Longer keys are 
		/// more secure than shorter keys. (Default: Bits256)
		/// </param>
		public Rijndael(string password, string salt, string initVector, Enumerations.HashAlgorithm hashAlgorithm, int iterations, Enumerations.KeySize keySize)
		{
			Initialize(password, salt, initVector, hashAlgorithm, iterations, keySize);
		}

		/// <summary>
		/// Constructor. Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password 
		/// will be used to generate the encryption key. Passphrase can be any string. In this 
		/// example we assume that this passphrase is an ASCII string.
		/// </param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In 
		/// this example we assume that salt is an ASCII string.
		/// </param>
		/// <param name="initVector">
		/// Initialization vector (or IV). This value is required to encrypt the first block of 
		/// plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
		/// </param>
		/// <param name="hashAlgorithm">
		/// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 
		/// hashes are a bit slower, but more secure than MD5 hashes. (Default: SHA1)
		/// </param>
		/// <param name="iterations">
		/// Number of iterations used to generate password. One or two iterations should be enough. (Default: 2)
		/// </param>
		public Rijndael(string password, string salt, string initVector, Enumerations.HashAlgorithm hashAlgorithm, int iterations)
		{
			Initialize(password, salt, initVector, hashAlgorithm, iterations, Enumerations.KeySize.Bits256);
		}

		/// <summary>
		/// Constructor. Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password 
		/// will be used to generate the encryption key. Passphrase can be any string. In this 
		/// example we assume that this passphrase is an ASCII string.
		/// </param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In 
		/// this example we assume that salt is an ASCII string.
		/// </param>
		/// <param name="initVector">
		/// Initialization vector (or IV). This value is required to encrypt the first block of 
		/// plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
		/// </param>
		/// <param name="hashAlgorithm">
		/// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 
		/// hashes are a bit slower, but more secure than MD5 hashes. (Default: SHA1)
		/// </param>
		public Rijndael(string password, string salt, string initVector, Enumerations.HashAlgorithm hashAlgorithm)
		{
			Initialize(password, salt, initVector, hashAlgorithm, 2, Enumerations.KeySize.Bits256);
		}

		/// <summary>
		/// Constructor. Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password 
		/// will be used to generate the encryption key. Passphrase can be any string. In this 
		/// example we assume that this passphrase is an ASCII string.
		/// </param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In 
		/// this example we assume that salt is an ASCII string.
		/// </param>
		/// <param name="initVector">
		/// Initialization vector (or IV). This value is required to encrypt the first block of 
		/// plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
		/// </param>
		public Rijndael(string password, string salt, string initVector)
		{
			Initialize(password, salt, initVector, Enumerations.HashAlgorithm.SHA1, 2, Enumerations.KeySize.Bits256);
		}

		public Rijndael(byte[] keyBytes, byte[] initVectorBytes)
		{
			// Create uninitialized Rijndael encryption object.
			RijndaelManaged symmetricKey = new RijndaelManaged();

			// It is reasonable to set encryption mode to Cipher Block Chaining (CBC). Use default 
			// options for other symmetric key parameters.
			symmetricKey.Mode = CipherMode.CBC;

			// Generate encryptor from the existing key bytes and initialization vector. Key size 
			// will be defined based on the number of the key bytes.
			m_Encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);

			// Generate decryptor from the existing key bytes and initialization vector. Key size 
			// will be defined based on the number of the key bytes.
			m_Decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
		}

		#endregion

		public byte[] Encrypt(string unencryptedString)
		{
			return Encrypt(Serialize(unencryptedString));
		}

		/// <summary>
		/// Encrypts specified unencrypted bytes using Rijndael symmetric key algorithm and returns a 
		/// an encrypted byte array.
		/// </summary>
		/// <param name="unencryptedBytes">Unencrypted bytes to be encrypted.</param>
		/// <returns>Encrypted bytes</returns>
		public byte[] Encrypt(byte [] unencryptedBytes)
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
		/// Most of the logic in this function is similar to the Encrypt
		/// logic. In order for decryption to work, all parameters of this function
		/// - except cipherText value - must match the corresponding parameters of
		/// the Encrypt function which was called to generate the
		/// ciphertext.
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
					// Since at this point we don't know what the size of decrypted data
					// will be, allocate the buffer long enough to hold ciphertext;
					// plaintext is never longer than ciphertext.
				unencryptedBytes	 = new byte[cipherBytes.Length];

					// Start decrypting.
					int decryptedByteCount = cryptoStream.Read(unencryptedBytes, 0, unencryptedBytes.Length);
				}
			}

			// Return decrypted string.   
			return unencryptedBytes;
		}

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

		#region Protected

		/// <summary>
		/// Initializes class to provide encryption/decryption functionality
		/// </summary>
		/// <param name="password">
		/// Passphrase from which a pseudo-random password will be derived. The derived password 
		/// will be used to generate the encryption key. Passphrase can be any string. In this 
		/// example we assume that this passphrase is an ASCII string.
		/// </param>
		/// <param name="salt">
		/// Salt value used along with passphrase to generate password. Salt can be any string. In 
		/// this example we assume that salt is an ASCII string.
		/// </param>
		/// <param name="initVector">
		/// Initialization vector (or IV). This value is required to encrypt the first block of 
		/// plaintext data. For RijndaelManaged class IV must be exactly 16 ASCII characters long.
		/// </param>
		/// <param name="hashAlgorithm">
		/// Hash algorithm used to generate password. Allowed values are: "MD5" and "SHA1". SHA1 
		/// hashes are a bit slower, but more secure than MD5 hashes.
		/// </param>
		/// <param name="iterations">
		/// Number of iterations used to generate password. One or two iterations should be enough.
		/// </param>
		/// <param name="keySize">
		/// Size of encryption key in bits. Allowed values are: 128, 192, and 256. Longer keys are 
		/// more secure than shorter keys.
		/// </param>
		protected void Initialize(string password, string salt, string initVector, Enumerations.HashAlgorithm hashAlgorithm, int iterations, Enumerations.KeySize keySize)
		{
			// Convert strings into byte arrays. Assumes that strings only contain ASCII codes.
			this.IV = Encoding.ASCII.GetBytes(initVector);
			byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);

			// First, create a password, from which the key will be derived. This password will be 
			// generated from the specified passphrase and salt value. The password will be created 
			// using the specified hash algorithm. Password creation can be done in several iterations.
			PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, saltValueBytes, hashAlgorithm.ToString(), iterations);

			// Use the password to generate pseudo-random bytes for the encryption key. Specify the 
			// size of the key in bytes (instead of bits).
			this.Key = passwordBytes.GetBytes((int)keySize / 8);

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
	}
}
