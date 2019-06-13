namespace TNT.Cryptography
{
	/// <summary>
	/// Represents a symmetric key pair
	/// </summary>
	public class KeyPair
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
		/// Initializes a <see cref="KeyPair"/>
		/// </summary>
		/// <param name="key">Key represented as base 64</param>
		/// <param name="iv">Initialization vector represented as base 64</param>
		public KeyPair(string key, string iv)
		{
			this.Key = key;
			this.IV = iv;
		}
	}
}
