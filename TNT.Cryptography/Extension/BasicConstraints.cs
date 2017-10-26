using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents a BasicContraints <see cref="Extension"/>
	/// </summary>
	public class BasicConstraints : Extension
	{
		Org.BouncyCastle.Asn1.X509.BasicConstraints X509BasicContraints = null;

		/// <summary>
		/// The BasicConstraints OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.DerObjectIdentifier OID { get { return X509Extensions.BasicConstraints; } }

		/// <summary>
		/// The value associated with the BasicConstraints OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.X509.X509Extension Value { get { return new Org.BouncyCastle.Asn1.X509.X509Extension(true, new DerOctetString(this.X509BasicContraints)); } }

		/// <summary>
		/// Initializes BasicConstraints from a <see cref="Org.BouncyCastle.Asn1.X509.BasicConstraints"/>
		/// </summary>
		/// <param name="basicContraints"><see cref="Org.BouncyCastle.Asn1.X509.BasicConstraints"/></param>
		public BasicConstraints(Org.BouncyCastle.Asn1.X509.BasicConstraints basicContraints)
		{
			this.X509BasicContraints = basicContraints;
		}
	}
}
