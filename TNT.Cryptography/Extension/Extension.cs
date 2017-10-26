using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Abstract Extension class
	/// </summary>
	public abstract class Extension
	{
		/// <summary>
		/// Implement to return the extension's OID
		/// </summary>
		public abstract DerObjectIdentifier OID { get; }

		/// <summary>
		/// Implement to return the extension's value
		/// </summary>
		public abstract X509Extension Value { get; }
	}
}
