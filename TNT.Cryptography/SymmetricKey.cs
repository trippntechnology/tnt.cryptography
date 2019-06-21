using System;
using System.Diagnostics.CodeAnalysis;

namespace TNT.Cryptography
{
	/// <summary>
	/// Represents a symmetric key
	/// </summary>
	public class SymmetricKey
	{
		/// <summary>
		/// Key
		/// </summary>
		public string Key { get; set; }

		/// <summary>
		/// Initialization vector
		/// </summary>
		public string IV { get; set; }

		/// <summary>
		/// Parameterless constructor provided for serialization
		/// </summary>
		[ExcludeFromCodeCoverage]
		public SymmetricKey() { }

		/// <summary>
		/// Initializes a <see cref="SymmetricKey"/>
		/// </summary>
		/// <param name="key">Key represented as base 64</param>
		/// <param name="iv">Initialization vector represented as base 64</param>
		public SymmetricKey(string key, string iv)
		{
			this.Key = key;
			this.IV = iv;
		}

		/// <summary>
		/// Initializes a <see cref="SymmetricKey"/> 
		/// </summary>
		/// <param name="key">Key represented as a <see cref="byte"/> array</param>
		/// <param name="iv">IV represented as a <see cref="byte"/>array</param>
		public SymmetricKey(byte[] key, byte[] iv)
		{
			this.Key = Convert.ToBase64String(key);
			this.IV = Convert.ToBase64String(iv);
		}
	}
}
