using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents a ExtendedKeyUsage <see cref="Extension"/>
	/// </summary>
	public class ExtendedKeyUsage : Extension
	{
		Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage X509ExtendedKeyUsage = null;

		/// <summary>
		/// The ExtendedKeyUsage OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.DerObjectIdentifier OID { get { return X509Extensions.ExtendedKeyUsage; } }

		/// <summary>
		/// Value associated with the ExtendedKeyUsage OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.X509.X509Extension Value { get { return new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(this.X509ExtendedKeyUsage)); } }

		/// <summary>
		/// Initializes <see cref="ExtendedKeyUsage"/> with one or more <see cref="KeyPurposeID"/>
		/// </summary>
		/// <param name="usages">One or more <see cref="KeyPurposeID"/> parameters</param>
		public ExtendedKeyUsage(params KeyPurposeID[] usages)
		{
			this.X509ExtendedKeyUsage = new Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage(usages);
		}
	}
}
