using System.Text;

namespace TNT.Cryptography
{
	/// <summary>
	/// Represents encrypted text that may have the IV included as the first part of the 
	/// cipher
	/// </summary>
	public class Cipher
	{
		private const string IV_TAG = "IV";
		private const int IV_SIZE_LENGTH = 4;

		/// <summary>
		/// Indicates whether the <see cref="Cipher"/> has an <see cref="IV"/>
		/// </summary>
		public bool HasIV { get { return IV?.Length > 0; } }

		/// <summary>
		/// IV of the cipher if exists
		/// </summary>
		public byte[]? IV { get; set; }

		/// <summary>
		/// The encrypted content of the cipher
		/// </summary>
		public byte[] EncryptedBytes { get; private set; }

		/// <summary>
		/// Initializes a <see cref="Cipher"/> with an array of <see cref="byte"/> that represent
		/// a cipher that may include the IV.
		/// </summary>
		/// <param name="cipher">Cipher to be parsed</param>
		public Cipher(byte[] cipher)
		{
			var encryptedArray = cipher.ToArray();
			var tagBytes = new byte[IV_TAG.Length];
			Array.Copy(encryptedArray, 0, tagBytes, 0, IV_TAG.Length);
			var tag = Encoding.ASCII.GetString(tagBytes);

			if (tag == IV_TAG)
			{
				// Has an IV so extract it

				// Shift off IV
				encryptedArray = encryptedArray.Skip(2).ToArray();

				// Get the length of the IV
				var ivLength = BitConverter.ToInt32(encryptedArray, 0);
				encryptedArray = encryptedArray.Skip(IV_SIZE_LENGTH).ToArray();

				// Get the IV
				IV = new byte[ivLength];
				Array.Copy(encryptedArray, 0, IV, 0, ivLength);
				encryptedArray = encryptedArray.Skip(ivLength).ToArray();

				// Get cipher
				//var cipherLength = cipherBytes.Length - tagLength - tagSizeLength - ivLength;
				var cipherArray = new byte[encryptedArray.Length];
				Array.Copy(encryptedArray, 0, cipherArray, 0, encryptedArray.Length);
			}

			EncryptedBytes = encryptedArray;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="encryptedBytes"></param>
		/// <param name="iv"></param>
		public Cipher(byte[] encryptedBytes, byte[] iv) 
		{
			EncryptedBytes = encryptedBytes;
			IV = iv;
		}


		/// <summary>
		/// Converts a <see cref="Cipher"/> to an array of <see cref="byte"/>. If the <see cref="Cipher"/>
		/// includes an IV then the IV is appended to the begin of the byte array as follows:
		/// <code>
		///   0-1			<see cref="IV_TAG"/>
		///   2-5			Length(n) of the IV
		///   6-(6+n)	IV
		///						Remaining bytes represent the encrypted content
		/// </code>
		/// </summary>
		/// <returns></returns>
		public byte[] ToBytes()
		{
			if (HasIV)
			{
				// Append the IV to the beginning of the cipher text
				var bytes = new List<byte>(Encoding.ASCII.GetBytes(IV_TAG));
				bytes.AddRange(BitConverter.GetBytes(IV.Length));
				bytes.AddRange(IV);
				bytes.AddRange(EncryptedBytes);
				return bytes.ToArray();
			}
			else
			{
				return EncryptedBytes;
			}
		}
	}
}