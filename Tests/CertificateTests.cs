using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TNT.Cryptography;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Castle = Org.BouncyCastle;

namespace Tests
{
	[TestClass]
	public class CertificateTests
	{
		[TestMethod]
		public void Certificate_CreateCertificationRequest()
		{

			X509Certificate2 selfSignedCertificate = null;

			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();

			// create the extension value
			GeneralName subjectAltName = new GeneralName(GeneralName.Rfc822Name, "CreateCertificationRequestTest");

			// create the extensions object and add it as an attribute
			IList oids = new ArrayList();
			IList values = new ArrayList();

			oids.Add(X509Extensions.SubjectAlternativeName);
			values.Add(new Castle.Asn1.X509.X509Extension(false, new DerOctetString(new GeneralNames(subjectAltName))));

			X509Extensions extensions = new X509Extensions(oids, values);

			Castle.Asn1.Pkcs.AttributePkcs attrPkcs = new Castle.Asn1.Pkcs.AttributePkcs(Castle.Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));

			string csr = Certificate.CreateCertificationRequest("cn=CreateCertificationRequestTest", keyPair, new DerSet(attrPkcs));
		}
	}
}
