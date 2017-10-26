using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace TNT.Cryptography
{
	/// <summary>
	/// Represents a <see cref="List{T}"/> of <see cref="Extension.Extension"/>
	/// </summary>
	public class Extensions : List<Extension.Extension>
	{
		/// <summary>
		/// Implicit cast operator that converts <see cref="Extensions"/> into a <see cref="Asn1Set"/>
		/// </summary>
		/// <param name="extensions">An <see cref="Extensions"/> object</param>
		/// <returns><see cref="Asn1Set"/> that represents the <see cref="Extensions"/></returns>
		public static implicit operator Asn1Set(Extensions extensions)
		{
			IList oids = (from o in extensions select o.OID).ToList();
			IList values = (from v in extensions select v.Value).ToList();

			X509Extensions x509Extensions = new X509Extensions(oids, values);
			Org.BouncyCastle.Asn1.Pkcs.AttributePkcs attrPkcs = new Org.BouncyCastle.Asn1.Pkcs.AttributePkcs(Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(x509Extensions));

			return new DerSet(attrPkcs);
		}
	}
}
