using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents a SubjectAlternativeName <see cref="Extension"/>
	/// </summary>
	public class SubjectAlternativeName : Extension
	{
		GeneralName X509GeneralName = null;

		/// <summary>
		/// The SubjectAlternativeName OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.DerObjectIdentifier OID { get { return X509Extensions.SubjectAlternativeName; } }

		/// <summary>
		/// The value associated with the SubjectAlternativeName OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.X509.X509Extension Value { get { return new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(new GeneralNames(this.X509GeneralName))); } }

		/// <summary>
		/// Initializes SubjectAlternativeName with a <see cref="GeneralName"/> representing the subject alternative name
		/// </summary>
		/// <param name="subjectAltName"><see cref="GeneralName"/> representing the subject alternative name</param>
		public SubjectAlternativeName(GeneralName subjectAltName)
		{
			this.X509GeneralName = subjectAltName;
		}
	}
}
