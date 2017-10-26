using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509.Extension;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents a SubjectKeyIdentifier <see cref="Extension"/>
	/// </summary>
	public class SubjectKeyIdentifier : Extension
	{
		SubjectKeyIdentifierStructure X509SubjectKeyIdentifierStructure = null;

		/// <summary>
		/// The SubjectKeyIdentifier OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.DerObjectIdentifier OID { get { return X509Extensions.SubjectKeyIdentifier; } }

		/// <summary>
		/// The value associated with the SubjectKeyIdentifier OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.X509.X509Extension Value { get { return new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(this.X509SubjectKeyIdentifierStructure)); } }

		/// <summary>
		/// Initializes SubjectKeyIdentifier with a <see cref="AsymmetricKeyParameter"/>
		/// </summary>
		/// <param name="assymetricKeyParameter"><see cref="AsymmetricKeyParameter"/></param>
		public SubjectKeyIdentifier(AsymmetricKeyParameter assymetricKeyParameter)
		{
			this.X509SubjectKeyIdentifierStructure = new SubjectKeyIdentifierStructure(assymetricKeyParameter);
		}
	}
}
