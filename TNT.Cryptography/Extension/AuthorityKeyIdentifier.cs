using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography.X509Certificates;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents an AuthorityKeyIdentifier <see cref="Extension"/>
	/// </summary>
	public class AuthorityKeyIdentifier : Extension
	{
		AuthorityKeyIdentifierStructure X509AuthorityKeyIdentifierStructure = null;

		/// <summary>
		/// The AuthorityKeyIdentifier OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.DerObjectIdentifier OID { get { return X509Extensions.AuthorityKeyIdentifier; } }

		/// <summary>
		/// The value associated with the AuthorityKeyIdentifier OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.X509.X509Extension Value { get { return new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(this.X509AuthorityKeyIdentifierStructure)); } }

		/// <summary>
		/// Initializes a AuthorityKeyIdentifier from an <see cref="X509Certificate2"/>
		/// </summary>
		/// <param name="ca"><see cref="X509Certificate2"/></param>
		public AuthorityKeyIdentifier(X509Certificate2 ca)
		{
			Org.BouncyCastle.X509.X509Certificate x509Cert = DotNetUtilities.FromX509Certificate(ca);
			this.X509AuthorityKeyIdentifierStructure = new AuthorityKeyIdentifierStructure(x509Cert);
		}

		/// <summary>
		/// Initializes an AuthorityKeyIdentifier from an <see cref="AsymmetricKeyParameter"/>
		/// </summary>
		/// <param name="publicKey"><see cref="AsymmetricKeyParameter"/></param>
		public AuthorityKeyIdentifier(AsymmetricKeyParameter publicKey)
		{
			this.X509AuthorityKeyIdentifierStructure = new AuthorityKeyIdentifierStructure(publicKey);
		}
	}
}
