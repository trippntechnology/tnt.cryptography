using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using TNT.Cryptography;

namespace Tests
{
	[TestClass]
	public class CertificateTests
	{
		protected const string m_CSR = @"-----BEGIN NEW CERTIFICATE REQUEST-----
MIIEaTCCA1ECAQAwcDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNV
BAcMDlNhbHQgTGFrZSBDaXR5MRMwEQYDVQQKDApIZWFsdGhhZ2VuMREwDwYDVQQL
DAhNZWRpY2l0eTERMA8GA1UEAwwIY3NyIHRlc3QwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC9CxOq6NH/TI+cpfrtP/RVDW8TSg/DhRgErnMWKXKeg0/K
8+YD3jBsg/ClMNCgU3auutqCs8KnVmj2Rj+xJXetjCN7K2GtinYDYDjl6ZE9MsnX
MTNZDVpZDZowctkEuIdFwrscfWhYKRlJH0FGLnLEIsR3KLbM2f2DVGKvgsQaLl6L
ppjHxzT7W7QLsnlCLHJgng72QYRMI4NyQk+1cNGPBUbl0ov+cy/TnrG+LfIjoqya
OM06+DNiRhYRMckENFDXasRL76ylKKcQtUWoWDd4TGSvY/VEQ1ikFtW3O5PnhMFO
zkvwHiFM3tP4XHciizFjlfrxxBKcmcDSrBLCvMWrAgMBAAGgggGyMBoGCisGAQQB
gjcNAgMxDBYKNi4xLjc2MDEuMjBOBgkrBgEEAYI3FRQxQTA/AgEFDB5MVFAtU3Ry
aXBwLm1lZHNsYy5tZWRpY2l0eS5jb20MDU1FRFNMQ1xzdHJpcHAMC0luZXRNZ3Iu
ZXhlMHIGCisGAQQBgjcNAgIxZDBiAgEBHloATQBpAGMAcgBvAHMAbwBmAHQAIABS
AFMAQQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABp
AGMAIABQAHIAbwB2AGkAZABlAHIDAQAwgc8GCSqGSIb3DQEJDjGBwTCBvjAOBgNV
HQ8BAf8EBAMCBPAwEwYDVR0lBAwwCgYIKwYBBQUHAwEweAYJKoZIhvcNAQkPBGsw
aTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjAL
BglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAK
BggqhkiG9w0DBzAdBgNVHQ4EFgQUacuMIqWWByVNHWkH11CrbJ1UvhYwDQYJKoZI
hvcNAQEFBQADggEBAJi7HIH/LZGqvhfVuuSUySn7E9xMvdBRWbYGxeoe69qy8W6A
sBMehVfzDT69Ru2zt6lPhqN5cE0A00dkZuQAic2KwfSMGVwIvD6bhq+ZILYWlj4Q
W8l+0cucgUAbp4Rthg7xVNBOUA+JJxXJnjAQpQILJjpyYhdlSnkhxsE+gy+Ene6c
InijMijyrEmAnLvwlbXbkOSWGVxS5r97t/BUhOKs6Z/UcoSN9g1XDSkEDO/NALju
EQA29U+T+024CAmyR67mTZWPkitrX5oqMxmZeecc7p8tQqDC3HSxTs/+rSKbj/vq
/RHRoJO9r/jq0fSIOcIJYKugE+NKPCaXtUznasI=
-----END NEW CERTIFICATE REQUEST-----
";

		private static X509Certificate2 _TA = null;

		protected static X509Certificate2 TA
		{
			get
			{
				if (_TA == null)
				{
					InitializeTrustAnchor();
				}

				return _TA;
			}
			set
			{
				_TA = value;
			}
		}

		protected static DateTime m_EffectiveDate;
		protected static DateTime m_ExpirationDate;

		[ClassInitialize]
		public static void Initialize(TestContext tc)
		{
			m_EffectiveDate = DateTime.Now;
			m_ExpirationDate = m_EffectiveDate.AddDays(2);
		}

		public static void InitializeTrustAnchor()
		{
			X500DistinguishedName dn = new X500DistinguishedName("CN=Trust Anchor, O=TNT, C=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.CrlSign | KeyUsage.KeyCertSign | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(0)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			string csrB64 = csr.ToBase64();
			Pkcs10CertificationRequest copiedCsr = csrB64.ToPkcs10CertificationRequest();

			Assert.AreEqual(csr, copiedCsr);

			TA = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate);

			Assert.IsNotNull(TA);
			Assert.IsTrue(TA.HasPrivateKey);

			Assert.AreEqual(m_EffectiveDate.ToString(), TA.NotBefore.ToString());
			Assert.AreEqual(m_ExpirationDate.ToString(), TA.NotAfter.ToString());
			Assert.AreEqual(TA.Subject, TA.Issuer);
			Assert.AreEqual(4, TA.Extensions.Count);

			Assert.AreEqual(typeof(X509KeyUsageExtension), TA.Extensions[0].GetType());
			Assert.IsTrue(TA.Extensions[0].Critical);
			Assert.AreEqual(typeof(X509SubjectKeyIdentifierExtension), TA.Extensions[1].GetType());
			Assert.AreEqual(typeof(X509BasicConstraintsExtension), TA.Extensions[2].GetType());
			Assert.IsTrue(TA.Extensions[2].Critical);
			Assert.AreEqual(typeof(System.Security.Cryptography.X509Certificates.X509Extension), TA.Extensions[3].GetType());

			File.WriteAllBytes("Trust Anchor.cer", TA.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_SelfSigned_ClientAuth()
		{
			X500DistinguishedName dn = new X500DistinguishedName("CN=Client Authentication, O=TNT, C=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate);

			Assert.AreEqual(m_EffectiveDate.ToString(), cert.NotBefore.ToString());
			Assert.AreEqual(m_ExpirationDate.ToString(), cert.NotAfter.ToString());
			Assert.AreEqual(cert.Subject, cert.Issuer);

			X509EnhancedKeyUsageExtension enhancedKUEx = cert.Extensions[0] as X509EnhancedKeyUsageExtension;
			Assert.AreEqual(KeyPurposeID.IdKPClientAuth.Id, enhancedKUEx.EnhancedKeyUsages[0].Value);

			File.WriteAllBytes("CSR_SelfSigned_ClientAuth.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_ClientAuth()
		{
			X500DistinguishedName dn = new X500DistinguishedName("CN=Client Authentication, O=TNT, C=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(TA));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate, TA);

			Assert.AreEqual(m_EffectiveDate.ToString(), cert.NotBefore.ToString());
			Assert.AreEqual(m_ExpirationDate.ToString(), cert.NotAfter.ToString());
			Assert.AreEqual("C=US, O=TNT, CN=Client Authentication", cert.Subject);
			Assert.AreEqual("CN=Trust Anchor, O=TNT, C=US", cert.Issuer);

			X509EnhancedKeyUsageExtension enhancedKUEx = cert.Extensions[0] as X509EnhancedKeyUsageExtension;
			Assert.AreEqual(KeyPurposeID.IdKPClientAuth.Id, enhancedKUEx.EnhancedKeyUsages[0].Value);

			File.WriteAllBytes("CSR_ClientAuth.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_TA()
		{
			X500DistinguishedName dn = new X500DistinguishedName("CN=Secondary Trust Anchor,O=TNT,C=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.CrlSign | KeyUsage.KeyCertSign | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(TA));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(0)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate, TA);

			X509KeyUsageExtension keyUsageEx = cert.Extensions[0] as X509KeyUsageExtension;
			X509BasicConstraintsExtension basicConstraintEx = cert.Extensions[3] as X509BasicConstraintsExtension;

			System.Security.Cryptography.X509Certificates.X509Extension aki = cert.Extensions[1];
			System.Security.Cryptography.X509Certificates.X509Extension ski = TA.Extensions[1];

			Assert.AreEqual(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, keyUsageEx.KeyUsages);
			Assert.IsTrue(basicConstraintEx.CertificateAuthority);
			Assert.AreEqual("C=US, O=TNT, CN=Secondary Trust Anchor", cert.Subject);
			Assert.AreEqual("CN=Trust Anchor, O=TNT, C=US", cert.Issuer);

			var skiCount = ski.Format(false).Length;
			Assert.AreEqual(ski.Format(false), aki.Format(false).Substring(6, skiCount));

			File.WriteAllBytes("CSR_TA.cer", cert.Export(X509ContentType.Cert));
			File.WriteAllBytes("CSR_TA.pfx", cert.Export(X509ContentType.Pfx, "p"));
		}

		[TestMethod]
		public void Certificate_CSR_TA_SelfSigned()
		{
			X500DistinguishedName dn = new X500DistinguishedName("CN=Secondary Trust Anchor,O=TNT,C=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.CrlSign | KeyUsage.KeyCertSign | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(0)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate, null);

			X509KeyUsageExtension keyUsageEx = cert.Extensions[0] as X509KeyUsageExtension;
			X509BasicConstraintsExtension basicConstraintEx = cert.Extensions[3] as X509BasicConstraintsExtension;

			System.Security.Cryptography.X509Certificates.X509Extension aki = cert.Extensions[1];
			System.Security.Cryptography.X509Certificates.X509Extension ski = cert.Extensions[2];

			Assert.AreEqual(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, keyUsageEx.KeyUsages);
			Assert.IsTrue(basicConstraintEx.CertificateAuthority);
			Assert.AreEqual("C=US, O=TNT, CN=Secondary Trust Anchor", cert.Subject);
			Assert.AreEqual(cert.Subject, cert.Issuer);

			var skiCount = ski.Format(false).Length;
			Assert.AreEqual(ski.Format(false), aki.Format(false).Substring(6, skiCount));

			File.WriteAllBytes("CSR_TA_SS.cer", cert.Export(X509ContentType.Cert));
			File.WriteAllBytes("CSR_TA_SS.pfx", cert.Export(X509ContentType.Pfx, "P"));
		}

		[TestMethod]
		public void Certificate_CSR_SelfSigned_DomainBound()
		{
			X500DistinguishedName dn = new X500DistinguishedName("cn=domain.com,o=TNT,c=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectAlternativeName(new GeneralName(GeneralName.DnsName, dn.Name.Split(',')[0].Split('=')[1])));
			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(false)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate);

			System.Security.Cryptography.X509Certificates.X509Extension subAltNameEx = cert.Extensions[1];
			X509EnhancedKeyUsageExtension enhancedKUEx = cert.Extensions[2] as X509EnhancedKeyUsageExtension;
			X509BasicConstraintsExtension basicConstraintEx = cert.Extensions[4] as X509BasicConstraintsExtension;

			enhancedKUEx = cert.GetEnhancedKeyUsage();

			Assert.AreEqual("DNS Name=domain.com", subAltNameEx.Format(false));
			Assert.AreEqual(KeyPurposeID.IdKPEmailProtection.Id, enhancedKUEx.EnhancedKeyUsages[0].Value);
			Assert.IsFalse(basicConstraintEx.CertificateAuthority);
			Assert.AreEqual("C=US, O=TNT, CN=domain.com", cert.Issuer);
			Assert.AreEqual("C=US, O=TNT, CN=domain.com", cert.Subject);

			File.WriteAllBytes("CSR_SelfSigned_DomainBound.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_DomainBound()
		{
			X500DistinguishedName dn = new X500DistinguishedName("cn=domain.com,o=TNT,c=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectAlternativeName(new GeneralName(GeneralName.DnsName, dn.Name.Split(',')[0].Split('=')[1])));
			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(TA));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(false)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate, TA);

			Assert.AreEqual("CN=Trust Anchor, O=TNT, C=US", cert.Issuer);
			Assert.AreEqual("C=US, O=TNT, CN=domain.com", cert.Subject);

			File.WriteAllBytes("CSR_DomainBound.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_DomainBound_Without_KeyPair()
		{
			X500DistinguishedName dn = new X500DistinguishedName("cn=domain.com,o=TNT,c=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectAlternativeName(new GeneralName(GeneralName.DnsName, dn.Name.Split(',')[0].Split('=')[1])));
			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(TA));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(false)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.RequestCertificate(csr, m_EffectiveDate, m_ExpirationDate, TA, extensions);

			Assert.AreEqual("CN=Trust Anchor, O=TNT, C=US", cert.Issuer);
			Assert.AreEqual("C=US, O=TNT, CN=domain.com", cert.Subject);
			Assert.AreEqual(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, (cert.Extensions["2.5.29.15"] as X509KeyUsageExtension).KeyUsages);
			File.WriteAllBytes("CSR_DomainBound.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidParameterException))]
		public void CreateCertificate_Exception()
		{
			X500DistinguishedName dn = new X500DistinguishedName("cn=domain.com,o=TNT,c=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectAlternativeName(new GeneralName(GeneralName.DnsName, dn.Name.Split(',')[0].Split('=')[1])));
			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(TA));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(false)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.RequestCertificate(csr, m_EffectiveDate, m_ExpirationDate, null, null);

			Assert.AreEqual("CN=Trust Anchor, O=TNT, C=US", cert.Issuer);
			Assert.AreEqual("C=US, O=TNT, CN=domain.com", cert.Subject);

			File.WriteAllBytes("CSR_DomainBound.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_SelfSigned_AddressBound()
		{
			X500DistinguishedName dn = new X500DistinguishedName("cn=local@domain.com,o=TNT,c=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectAlternativeName(new GeneralName(GeneralName.Rfc822Name, dn.Name.Split(',')[0].Split('=')[1])));
			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(false)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate);

			System.Security.Cryptography.X509Certificates.X509Extension subAltNameEx = cert.Extensions[1];
			System.Security.Cryptography.X509Certificates.X509Extension aki = cert.Extensions[3];
			System.Security.Cryptography.X509Certificates.X509Extension ski = cert.Extensions[4];

			Assert.AreEqual("RFC822 Name=local@domain.com", subAltNameEx.Format(false));
			Assert.AreEqual("C=US, O=TNT, CN=local@domain.com", cert.Issuer);
			Assert.AreEqual("C=US, O=TNT, CN=local@domain.com", cert.Subject);

			var skiCount = ski.Format(false).Length;
			Assert.AreEqual(ski.Format(false), aki.Format(false).Substring(6, skiCount));

			File.WriteAllBytes("CSR_SelfSigned_AddressBound.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CSR_AddressBound()
		{
			X500DistinguishedName dn = new X500DistinguishedName("cn=local@domain.com,o=TNT,c=US");
			AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
			Extensions extensions = new Extensions();

			extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));
			extensions.Add(new TNT.Cryptography.Extension.SubjectAlternativeName(new GeneralName(GeneralName.Rfc822Name, dn.Name.Split(',')[0].Split('=')[1])));
			extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
			extensions.Add(new TNT.Cryptography.Extension.AuthorityKeyIdentifier(TA));
			extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
			extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(false)));
			List<Uri> uris = new List<Uri>(new Uri[] { new Uri("http://domain1.com"), new Uri("http://domain2.com") });
			extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(uris));

			Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(dn.Name, keyPair, extensions);
			X509Certificate2 cert = Certificate.CreateCertificate(csr, keyPair, m_EffectiveDate, m_ExpirationDate, TA);

			System.Security.Cryptography.X509Certificates.X509Extension ski = TA.Extensions[1];
			System.Security.Cryptography.X509Certificates.X509Extension aki = cert.Extensions[3];

			Assert.AreEqual("CN=Trust Anchor, O=TNT, C=US", cert.Issuer);
			Assert.AreEqual("C=US, O=TNT, CN=local@domain.com", cert.Subject);

			var skiCount = ski.Format(false).Length;
			Assert.AreEqual(ski.Format(false), aki.Format(false).Substring(6, skiCount));

			File.WriteAllBytes("CSR_AddressBound.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_LoadCSR()
		{
			Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest csr = null;
			try
			{
				csr = Certificate.LoadCSR("invalid.csr");
			}
			catch (Exception ex)
			{
				Assert.IsTrue(ex is FileNotFoundException);
			}

			csr = Certificate.LoadCSR("development.com.csr");

			Assert.IsNotNull(csr);

			Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo csrInfo = csr.GetCertificationRequestInfo();

			Assert.AreEqual("C=US,ST=Ut,L=SLC,O=Medicity,OU=Healthagen,CN=development.com", csrInfo.Subject.ToString());

			Certificate.SaveCSR(csr, "development.com.copy.csr");

			Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest csr_copy = Certificate.LoadCSR("development.com.copy.csr");

			Assert.AreEqual(csr, csr_copy);
		}

		[TestMethod]
		public void Certificate_CreateSigned()
		{
			string subjectDN = "CN=bogus@domain.com";

			X509Certificate2 cert = Certificate.CreateSigned(subjectDN, m_EffectiveDate, m_ExpirationDate, null, TA);
			Assert.IsNotNull(cert);
			Assert.AreEqual(subjectDN, cert.Subject);
			Assert.AreEqual(TA.Subject, cert.Issuer);
			Assert.AreEqual(m_EffectiveDate.ToString(), cert.GetEffectiveDateString());
			Assert.AreEqual(m_ExpirationDate.ToString(), cert.GetExpirationDateString());
			Assert.AreEqual(6, cert.Extensions.Count);
		}

		[TestMethod]
		public void Certificate_CreateSelfSigned()
		{
			string subjectDN = "CN=self.signed.cert@bogus.domain.com";

			X509Certificate2 cert = Certificate.CreateSelfSigned(subjectDN, m_EffectiveDate, m_ExpirationDate);
			Assert.IsNotNull(cert);
			Assert.AreEqual(subjectDN, cert.Subject);
			Assert.AreEqual(subjectDN, cert.Issuer);
			Assert.AreEqual(m_EffectiveDate.ToString(), cert.GetEffectiveDateString());
			Assert.AreEqual(m_ExpirationDate.ToString(), cert.GetExpirationDateString());

			File.WriteAllBytes("self.signed.cert.bogus.domain.com.cer", cert.Export(X509ContentType.Cert));
		}

		[TestMethod]
		public void Certificate_CreateSelfSigned_MultiThreads()
		{
			string subjectDN1 = "CN=self.signed.cert1@bogus.domain.com";
			string subjectDN2 = "CN=self.signed.cert2@bogus.domain.com";
			string subjectDN3 = "CN=self.signed.cert3@bogus.domain.com";
			string subjectDN4 = "CN=self.signed.cert4@bogus.domain.com";
			X509Certificate2 cert2 = null;
			X509Certificate2 cert3 = null;
			X509Certificate2 cert4 = null;

			Thread thread2 = new Thread(delegate ()
						{
							cert2 = Certificate.CreateSelfSigned(subjectDN2, m_EffectiveDate, m_ExpirationDate);
							//byte[] bytes2 = cert2.Export(X509ContentType.Pfx, "password");
							//System.IO.File.WriteAllBytes("cert2.pfx", bytes2);
						});

			Thread thread3 = new Thread(delegate ()
			{
				cert3 = Certificate.CreateSelfSigned(subjectDN3, m_EffectiveDate, m_ExpirationDate);
				//byte[] bytes3 = cert3.Export(X509ContentType.Pfx, "password");
				//System.IO.File.WriteAllBytes("cert3.pfx", bytes3);
			});

			Thread thread4 = new Thread(delegate ()
			{
				cert4 = Certificate.CreateSelfSigned(subjectDN4, m_EffectiveDate, m_ExpirationDate);
				//byte[] bytes4 = cert4.Export(X509ContentType.Pfx, "password");
				//System.IO.File.WriteAllBytes("cert4.pfx", bytes4);
			});

			thread2.Start();
			thread3.Start();
			thread4.Start();

			X509Certificate2 cert1 = Certificate.CreateSelfSigned(subjectDN1, m_EffectiveDate, m_ExpirationDate);

			// Wait for a while
			Thread.Sleep(1000);

			// If you use command line: certutil -dump "cert1.pfx", the result should contain a string of "Encryption test passed" at the end instead of failure.
			byte[] bytes1 = cert1.Export(X509ContentType.Pfx, "password");
			System.IO.File.WriteAllBytes("cert1.pfx", bytes1);

			Assert.IsNotNull(cert1);
			Assert.AreEqual(subjectDN1, cert1.Subject);
			Assert.AreEqual(subjectDN1, cert1.Issuer);
			Assert.AreEqual(m_EffectiveDate.ToString(), cert1.GetEffectiveDateString());
			Assert.AreEqual(m_ExpirationDate.ToString(), cert1.GetExpirationDateString());
		}

		[TestMethod]
		public void Certificate_ExportPFX()
		{
			try
			{
				string subjectDN = "CN=bogus@domain.com";

				X509Certificate2 cert = Certificate.CreateSigned(subjectDN, DateTime.Now, DateTime.Now.AddDays(2), null, TA);
				Certificate.Export("bogus.domain.com.pfx", cert, "password");

				X509Certificate2 pfxCert = new X509Certificate2("bogus.domain.com.pfx", "password");
				Assert.AreEqual(subjectDN, pfxCert.Subject);
				Assert.IsTrue(pfxCert.HasPrivateKey);
			}
			catch (Exception ex)
			{
				Assert.Fail(ex.ToString());
			}
		}

		[TestMethod]
		public void Certificate_ExportCER()
		{
			try
			{
				string subjectDN = "CN=bogus@domain.com";

				X509Certificate2 cert = Certificate.CreateSigned(subjectDN, DateTime.Now, DateTime.Now.AddDays(2), null, TA);
				Certificate.Export("bogus.domain.com.cer", cert);

				X509Certificate2 cerCert = new X509Certificate2("bogus.domain.com.cer");
				Assert.AreEqual(subjectDN, cerCert.Subject);
				Assert.IsFalse(cerCert.HasPrivateKey);
			}
			catch (Exception ex)
			{
				Assert.Fail(ex.ToString());
			}
		}

		public void Certificate_AddToStore()
		{
			X509Certificate2 cert = Certificate.CreateSigned("cn=added@by.certifcate.test", m_EffectiveDate, m_ExpirationDate, null, TA);

			Assert.IsNotNull(cert);

			Certificate.AddToStore(StoreName.My, StoreLocation.LocalMachine, cert);

			X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly);
			X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, true);

			Assert.AreEqual(1, certs.Count);
		}

		[TestMethod]
		public void Certificate_CreateCertificateAuthority()
		{
			var ca1Subject = new X509Name("cn=ca.one");
			var ca1 = Certificate.CreateCertificateAuthority(ca1Subject.ToString(), m_EffectiveDate, m_ExpirationDate);

			Assert.IsNotNull(ca1);
			Assert.AreEqual(ca1Subject.ToString(), ca1.Subject);
			Assert.AreEqual(ca1Subject.ToString(), ca1.Issuer);

			var ca2Subject = new X509Name("cn=ca.two");

			Uri[] uris = { new Uri("ldap://localhost/cn=test@myhealthisp.com,dc=myhealthisp,dc=com,o=TNT"), new Uri("http://domain.com/file.crl") };
			var ca2 = Certificate.CreateCertificateAuthority(ca2Subject.ToString(), m_EffectiveDate, m_ExpirationDate, uris.ToList(), ca1);

			Assert.IsNotNull(ca2);
			Assert.AreEqual(ca2Subject.ToString(), ca2.Subject);
			Assert.AreEqual(ca1Subject.ToString(), ca2.Issuer);

			var x = ca2.GetCrlDistributionPoints();
		}

		[TestMethod]
		public void Certificate_SignedWithCA()
		{
			var issuerDN = new X509Name("cn=ca.test");
			var subjectDN = new X509Name("cn=signedCert");

			var caCert = Certificate.CreateCertificateAuthority(issuerDN.ToString(), m_EffectiveDate, m_ExpirationDate);

			Assert.IsNotNull(caCert);

			var cert = Certificate.CreateSigned(subjectDN.ToString(), m_EffectiveDate, m_ExpirationDate, null, caCert);

			Assert.IsNotNull(cert);
			Assert.AreEqual(subjectDN.ToString(), cert.Subject);
			Assert.AreEqual(caCert.Subject, cert.Issuer);
		}

		[TestMethod]
		public void Certificate_Encrypt_Decrypt()
		{
			try
			{
				var caCert = Certificate.CreateCertificateAuthority("cn=testca", m_EffectiveDate, m_ExpirationDate);
				var cert = Certificate.CreateSigned("cn=testcert", m_EffectiveDate, m_ExpirationDate, null, caCert);

				RSACryptoServiceProvider rsaPublic = (RSACryptoServiceProvider)cert.PublicKey.Key;
				RSACryptoServiceProvider rsaPrivate = (RSACryptoServiceProvider)cert.PrivateKey;

				string txt2Encrypt = "Lorem ipsum dolor sit amet, tempor non coepit cognitionis huius";

				byte[] bytes2Encrypt = ASCIIEncoding.ASCII.GetBytes(txt2Encrypt);
				byte[] encryptedBytes = rsaPublic.Encrypt(bytes2Encrypt, false);

				SHA1Managed sha1 = new SHA1Managed();
				byte[] hash = sha1.ComputeHash(encryptedBytes);
				byte[] signedBytes = rsaPrivate.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));

				// Verify the signature with the hash
				Assert.IsTrue(rsaPublic.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signedBytes));

				byte[] decryptedBytes = rsaPrivate.Decrypt(encryptedBytes, false);
				string decryptedTxt = new ASCIIEncoding().GetString(decryptedBytes);

				Assert.AreEqual(txt2Encrypt, decryptedTxt);
			}
			catch (Exception ex)
			{
				Assert.Fail(ex.Message);
			}
		}

		[TestMethod]
		public void Certificate_AddRemoveFromStore()
		{
			X509Certificate2 cert = Certificate.CreateSelfSigned("CN=AddRemoveFromStoreTest", m_EffectiveDate, m_ExpirationDate);
			Certificate.AddToStore(StoreName.My, StoreLocation.LocalMachine, cert);

			X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly);
			var certs = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
			Assert.IsTrue(certs.Contains(cert));
			store.Close();

			Certificate.RemoveFromStore(StoreName.My, StoreLocation.LocalMachine, cert);
			certs = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
			Assert.IsFalse(certs.Contains(cert));
			store.Close();
		}

		[TestMethod]
		public void Certificate_Renew()
		{
			DateTime now = DateTime.Now;
			X509Certificate2 caCert = Certificate.CreateCertificateAuthority("cn=ca", now, now.AddYears(1));
			Uri[] uris = { new Uri("http://domain1.com"), new Uri("http://domain2.com"), new Uri("http://domain3.com") };
			X509Certificate2 signedCert = Certificate.CreateSigned("cn=cert", now, now.AddYears(1), uris.ToList(), caCert);
			X509Certificate2 renewedCert = Certificate.Renew(signedCert, now.AddYears(1), now.AddYears(2), caCert);

			Assert.AreEqual(signedCert.FriendlyName, renewedCert.FriendlyName); try
			{

				Assert.AreEqual(signedCert.Issuer, renewedCert.Issuer);
				Assert.AreEqual(signedCert.NotAfter, renewedCert.NotAfter.AddYears(-1));
				Assert.AreEqual(signedCert.NotBefore, renewedCert.NotBefore.AddYears(-1));
				Assert.AreEqual(signedCert.PrivateKey.ToXmlString(true), renewedCert.PrivateKey.ToXmlString(true));
				CollectionAssert.AreEqual(signedCert.PublicKey.EncodedKeyValue.RawData, renewedCert.PublicKey.EncodedKeyValue.RawData);
				Assert.AreNotEqual(signedCert.SerialNumber, renewedCert.SerialNumber);
				Assert.AreEqual(signedCert.SignatureAlgorithm.FriendlyName, renewedCert.SignatureAlgorithm.FriendlyName);
				Assert.AreEqual(signedCert.Subject, renewedCert.Subject);
				Assert.AreNotEqual(signedCert.Thumbprint, renewedCert.Thumbprint);
				Assert.AreEqual(signedCert.Version, renewedCert.Version);

				var cert1Crls = signedCert.GetCrlDistributionPoints();
				var cert2Crls = renewedCert.GetCrlDistributionPoints();
				CollectionAssert.AreEqual(cert1Crls, cert2Crls);
			}
			catch (Exception ex)
			{

				throw;
			}
		}

		public void Certificate_Encrypt_Decrypt_Sign()
		{
			var caCert = Certificate.CreateCertificateAuthority("cn=testca", m_EffectiveDate, m_ExpirationDate);
			var cert = Certificate.CreateSigned("cn=testcert", m_EffectiveDate, m_ExpirationDate, null, caCert);

			RSACryptoServiceProvider rsaPublic = (RSACryptoServiceProvider)cert.PublicKey.Key;
			RSACryptoServiceProvider rsaPrivate = (RSACryptoServiceProvider)cert.PrivateKey;

			string txt2Encrypt = "Lorem ipsum dolor sit amet, tempor non coepit cognitionis huius";
			byte[] bytes2Encrypt = ASCIIEncoding.ASCII.GetBytes(txt2Encrypt);

			byte[] encryptedBytes = EncryptMsg(bytes2Encrypt, cert);
			byte[] decryptedBytes = DecryptMsg(encryptedBytes);
		}

		/// <summary>
		/// Encrypt the message with the public key of the recipient. This is done by enveloping the 
		/// message by using a EnvelopedCms object.
		/// </summary>
		/// <param name="msg">Byte array containing the message to encrypt</param>
		/// <param name="recipientCert">Recipient's certificate</param>
		/// <returns>Array of bytes containing the encrypted message</returns>
		protected byte[] EncryptMsg(Byte[] msg, X509Certificate2 recipientCert)
		{
			//  Place message in a ContentInfo object. This is required to build an EnvelopedCms object.
			ContentInfo contentInfo = new ContentInfo(msg);

			//  Instantiate EnvelopedCms object with the ContentInfo above.
			//  Has default SubjectIdentifierType IssuerAndSerialNumber. Has default ContentEncryptionAlgorithm property value
			//  RSA_DES_EDE3_CBC.
			EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

			//  Formulate a CmsRecipient object that represents information about the recipient
			//  to encrypt the message for.
			CmsRecipient recip1 = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCert);

			//Console.Write("Encrypting data for a single recipient of " + "subject name {0} ... ", recip1.Certificate.SubjectName.Name);

			//  Encrypt the message for the recipient.
			envelopedCms.Encrypt(recip1);
			//Console.WriteLine("Done.");

			//  The encoded EnvelopedCms message contains the encrypted message and the information about each recipient that
			//  the message was enveloped for.
			return envelopedCms.Encode();
		}

		/// <summary>
		/// Decrypt the encoded EnvelopedCms message.
		/// </summary>
		/// <param name="encodedEnvelopedCms">Array of bytes containing the encrypted message</param>
		/// <returns>Array of bytes containing the decrypted message</returns>
		protected Byte[] DecryptMsg(byte[] encodedEnvelopedCms)
		{
			//  Prepare object in which to decode and decrypt.
			EnvelopedCms envelopedCms = new EnvelopedCms();

			//  Decode the message.
			envelopedCms.Decode(encodedEnvelopedCms);

			//  Display the number of recipients the message is enveloped for; it should be 1 for this example.
			//DisplayEnvelopedCms(envelopedCms, false);

			//  Decrypt the message for the single recipient. Note that the following call to the Decrypt method
			//  accomplishes the same result: envelopedCms.Decrypt();
			//Console.Write("Decrypting Data ... ");
			envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);
			//Console.WriteLine("Done.");

			return envelopedCms.Encode();
		}
	}
}
