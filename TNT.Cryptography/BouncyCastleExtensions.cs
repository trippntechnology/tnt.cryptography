using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace TNT.Cryptography
{
	/// <summary>
	/// Extensions for the Org.BouncyCastle library
	/// </summary>
	public static class BouncyCastleExtensions
	{
		/// <summary>
		/// Extension to convert a <see cref="Pkcs10CertificationRequest"/> to a base 64 encoded string
		/// </summary>
		/// <param name="csr"><see cref="Pkcs10CertificationRequest"/></param>
		/// <returns>Base 64 encoded string representing the <see cref="Pkcs10CertificationRequest"/></returns>
		public static string ToBase64(this Pkcs10CertificationRequest csr)
		{
			using (StringWriter sw = new StringWriter())
			{
				PemWriter pw = new PemWriter(sw);
				pw.WriteObject(csr);
				return pw.Writer.ToString();
			}
		}

		/// <summary>
		/// Extension to convert a string representing a base64 encoded <see cref="Pkcs10CertificationRequest"/> into a 
		/// <see cref="Pkcs10CertificationRequest"/>
		/// </summary>
		/// <param name="csr">String representing a base64 encoded <see cref="Pkcs10CertificationRequest"/></param>
		/// <returns><see cref="Pkcs10CertificationRequest"/></returns>
		public static Pkcs10CertificationRequest ToPkcs10CertificationRequest(this string csr)
		{
			using (TextReader tr = new StringReader(csr))
			{
				PemReader pr = new Org.BouncyCastle.OpenSsl.PemReader(tr);
				return pr.ReadObject() as Pkcs10CertificationRequest;
			}
		}
	}
}
