using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents a KeyUsage <see cref="Extension"/>
	/// </summary>
	public class KeyUsage : Extension
	{
		Org.BouncyCastle.Asn1.X509.KeyUsage X509KeyUsage = null;

		/// <summary>
		/// The KeyUsage OID
		/// </summary>
		public override DerObjectIdentifier OID { get { return X509Extensions.KeyUsage; } }

/// <summary>
		/// Value associated with the KeyUsage OID
/// </summary>
		public override X509Extension Value { get { return new X509Extension(true, new DerOctetString(this.X509KeyUsage)); } }

		/// <summary>
		/// Initializes KeyUsage
		/// </summary>
		/// <param name="keyUsage">Int representing the <see cref="Org.BouncyCastle.Asn1.X509.KeyUsage"/></param>
		public KeyUsage(int keyUsage)
		{
			this.X509KeyUsage = new Org.BouncyCastle.Asn1.X509.KeyUsage(keyUsage);
		}
	}
}
