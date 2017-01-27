using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TNT.Cryptography
{
	/// <summary>
	/// X509Certificate2 creator and manager
	/// </summary>
	public static class Certificate
	{
		private const int BIT_STRENGTH = 2048;
		private const string SIGNATURE_ALGORITHM = "SHA256WITHRSA";

		static readonly object _locker = new object();
		/// <summary>
		/// Creates a <see cref="Pkcs10CertificationRequest"/>
		/// </summary>
		/// <param name="subject">Subject value that should be set in the certificate</param>
		/// <param name="keyPair">Public/private key pair</param>
		/// <param name="asn1Set"><see cref="Asn1Set"/> representing the extensions that should be added to the certificate</param>
		/// <returns>Base64 encoded string representing a CSR</returns>
		public static string CreateCertificationRequest(string subject, AsymmetricCipherKeyPair keyPair, Asn1Set asn1Set = null)
		{
			Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(SIGNATURE_ALGORITHM, new X509Name(subject), keyPair.Public, asn1Set, keyPair.Private);
			return csr.ToBase64();
		}

		/// <summary>
		/// Creates a certificate signed by a certificate authority
		/// </summary>
		/// <param name="subjectDN">Subject name of the new certificate</param>
		/// <param name="effectiveDate">Start date certificate is valid</param>
		/// <param name="expirationDate">Date when certificate expires</param>
		/// <param name="crlUrls">List of <see cref="Uri"/> containing the Urls for the CRL Distribution Points</param>
		/// <param name="certificateAuthority">Certificate authority signing the certificate</param>
		/// <returns>X509Certificate2 signed by a certificate authority</returns>
		public static X509Certificate2 CreateSigned(string subjectDN, DateTime effectiveDate, DateTime expirationDate, List<Uri> crlUrls, X509Certificate2 certificateAuthority)
		{
			Org.BouncyCastle.X509.X509Certificate caCert = DotNetUtilities.FromX509Certificate(certificateAuthority);
			AsymmetricCipherKeyPair keyPair = CreateRSAKeyPair();
			X509Name x509SubjectDN = new X509Name(subjectDN);

			X509Certificate2 rtnCert = CreateCertificate(x509SubjectDN, effectiveDate, expirationDate, keyPair, caCert.SubjectDN,
																									 TransformRSAPrivateKey((RSACryptoServiceProvider)certificateAuthority.PrivateKey), (certGen, serialNumber) =>
				{
					IList cn = x509SubjectDN.GetValueList(X509Name.CN);

					if (cn.Count > 0)
					{
						if (Uri.CheckHostName(cn[0].ToString()) == UriHostNameType.Dns)
						{
							certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.DnsName, cn[0].ToString())));
						}
						else
						{
							try
							{
								MailAddress ma = new MailAddress(cn[0].ToString());
								certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.Rfc822Name, cn[0].ToString())));
							}
							catch { }
						}
					}

					certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
					//certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
					certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
					certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(keyPair.Public));
					certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
					certGen.AddCrlDistributionPoints(crlUrls);
				});

			rtnCert.PrivateKey = TransformRSAPrivateKey((RsaPrivateCrtKeyParameters)keyPair.Private);

			return rtnCert;
		}

		/// <summary>
		/// Creates a self-signed certificate
		/// </summary>
		/// <param name="subjectDN">Subject name of the new certificate</param>
		/// <param name="effectiveDate">Start date certificate is valid</param>
		/// <param name="expirationDate">Date when certificate expires</param>
		/// <returns>Self-signed X509Certificate2</returns>
		public static X509Certificate2 CreateSelfSigned(string subjectDN, DateTime effectiveDate, DateTime expirationDate)
		{
			AsymmetricCipherKeyPair keyPair = CreateRSAKeyPair();

			X509Certificate2 rtnCert = CreateCertificate(new X509Name(subjectDN), effectiveDate, expirationDate, keyPair, null, null, (certGen, serNum) =>
				{
					certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
					certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, true, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public)));
					certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(keyPair.Public));
				});

			rtnCert.PrivateKey = TransformRSAPrivateKey((RsaPrivateCrtKeyParameters)keyPair.Private);

			return rtnCert;
		}

		/// <summary>
		/// Creates a self-signed Certifiate Authority certificate
		/// </summary>
		/// <param name="subjectDN">Subject of the certificate</param>
		/// <param name="effectiveDate">Effective date of the certificate</param>
		/// <param name="expirationDate">Expirations date of the certificate</param>
		/// <param name="crlUrls">List of <see cref="Uri"/> containing the Urls for the CRL Distribution Points</param>
		/// <returns><see cref="X509Certificate2"/> representing a certificate authority</returns>
		public static X509Certificate2 CreateCertificateAuthority(string subjectDN, DateTime effectiveDate, DateTime expirationDate, List<Uri> crlUrls = null)
		{
			return CreateCertificateAuthority(subjectDN, effectiveDate, expirationDate, crlUrls, null);
		}

		/// <summary>
		/// Creates a signed certificate authority certificate
		/// </summary>
		/// <param name="subjectDN">Subject of the certificate</param>
		/// <param name="effectiveDate">Effective date of the certificate</param>
		/// <param name="expirationDate">Expirations date of the certificate</param>
		/// <param name="crlUrls">List of <see cref="Uri"/> containing the Urls for the CRL Distribution Points</param>
		/// <param name="certificateAuthority">Signing authority</param>
		/// <returns><see cref="X509Certificate2"/> representing a certificate authority</returns>
		public static X509Certificate2 CreateCertificateAuthority(string subjectDN, DateTime effectiveDate, DateTime expirationDate, List<Uri> crlUrls, X509Certificate2 certificateAuthority)
		{
			AsymmetricCipherKeyPair keyPair = CreateRSAKeyPair();
			X509Name issuerDN = null;
			RsaPrivateCrtKeyParameters signingKey = null;

			if (certificateAuthority != null)
			{
				Org.BouncyCastle.X509.X509Certificate caCert = DotNetUtilities.FromX509Certificate(certificateAuthority);
				issuerDN = caCert.SubjectDN;
				signingKey = TransformRSAPrivateKey((RSACryptoServiceProvider)certificateAuthority.PrivateKey);
			}

			X509Certificate2 rtnCert = CreateCertificate(new X509Name(subjectDN), effectiveDate, expirationDate, keyPair, issuerDN, signingKey, (certGen, serNum) =>
			{
				GeneralNames names = new GeneralNames(new GeneralName(new X509Name(subjectDN)));

				certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.CrlSign | KeyUsage.KeyCertSign));
				certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(names, serNum));
				certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
				certGen.AddCrlDistributionPoints(crlUrls);
			});

			rtnCert.PrivateKey = TransformRSAPrivateKey((RsaPrivateCrtKeyParameters)keyPair.Private);

			return rtnCert;
		}

		/// <summary>
		/// Creates a certificate signed by the <paramref name="ca"/> from a Base64 encoded PKCS#10 string (<paramref name="csr"/>)
		/// </summary>
		/// <param name="csr">Base64 encoded PKCS#10 string </param>
		/// <param name="effectiveDate">Start date certificate is valid</param>
		/// <param name="expirationDate">Date when certificate expires</param>
		/// <param name="ca">Certificate authority used to sign the certificate</param>
		/// <returns><see cref="X509Certificate2"/> certificate</returns>
		public static X509Certificate2 CreateCertificate(string csr, DateTime effectiveDate, DateTime expirationDate, X509Certificate2 ca)
		{
			return CreateCertificate(csr.ToPkcs10CertificationRequest(), effectiveDate, expirationDate, ca);
		}

		/// <summary>
		/// Creates a certificate given a <see cref="Pkcs10CertificationRequest"/> signed by a certificate authority
		/// </summary>
		/// <param name="csr">Certificate request</param>
		/// <param name="effectiveDate">Start date certificate is valid</param>
		/// <param name="expirationDate">Date when certificate expires</param>
		/// <param name="ca">Certificate authority</param>
		/// <returns><see cref="X509Certificate2"/> created from the <paramref name="csr"/> and signed by the <paramref name="ca"/></returns>
		public static X509Certificate2 CreateCertificate(Pkcs10CertificationRequest csr, DateTime effectiveDate, DateTime expirationDate, X509Certificate2 ca)
		{
			Org.BouncyCastle.X509.X509Certificate caCert = DotNetUtilities.FromX509Certificate(ca);

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			BigInteger serialNumber = CreateSerialNumber();

			certGen.SetSerialNumber(serialNumber);
			certGen.SetIssuerDN(caCert.SubjectDN);
			certGen.SetNotBefore(effectiveDate.ToUniversalTime());
			certGen.SetNotAfter(expirationDate.ToUniversalTime());
			certGen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
			certGen.SetPublicKey(csr.GetPublicKey());
			certGen.SetSignatureAlgorithm(SIGNATURE_ALGORITHM);

			CertificationRequestInfo info = csr.GetCertificationRequestInfo();

			Asn1Set asn1Set = info.Attributes;

			// Iterate through each extension and add it to the certificate
			for (int i = 0; i < asn1Set.Count; i++)
			{
				AttributePkcs attr = AttributePkcs.GetInstance(asn1Set[i]);

				if (attr != null && attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
				{
					X509Extensions extensions = X509Extensions.GetInstance(attr.AttrValues[0]);

					foreach (DerObjectIdentifier extOid in extensions.ExtensionOids)
					{
						Org.BouncyCastle.Asn1.X509.X509Extension ext = extensions.GetExtension(extOid);

						certGen.AddExtension(extOid, ext.IsCritical, ext.GetParsedValue());
					}
				}
			}

			Org.BouncyCastle.X509.X509Certificate bcCert = certGen.Generate(TransformRSAPrivateKey((RSACryptoServiceProvider)ca.PrivateKey));

			return new X509Certificate2(bcCert.GetEncoded());
		}

		/// <summary>
		/// Creates a <see cref="X509Certificate2"/> certificate
		/// </summary>
		/// <param name="subjectDN">Subject of the certificate</param>
		/// <param name="effectiveDate">Effective date of the certificate</param>
		/// <param name="expirationDate">Expirations date of the certificate</param>
		/// <param name="keyPair">Pair of keys used to create the certificate</param>
		/// <param name="issuerDN">Issuer DN (default: <paramref name="subjectDN"/>)</param>
		/// <param name="signingKey">Key used to sign certificate. When <paramref name="signingKey"/> is null, certificate is self-signed</param>
		/// <param name="extend">Can be provided to add extensions to a <see cref="X509V3CertificateGenerator"/></param>
		/// <returns><see cref="X509Certificate2"/> representing a certificate</returns>
		public static X509Certificate2 CreateCertificate(X509Name subjectDN, DateTime effectiveDate, DateTime expirationDate, AsymmetricCipherKeyPair keyPair, X509Name issuerDN = null,
			AsymmetricKeyParameter signingKey = null, Action<X509V3CertificateGenerator, BigInteger> extend = null)
		{
			if (issuerDN == null)
			{
				issuerDN = subjectDN;
			}

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			BigInteger serialNumber = CreateSerialNumber();

			certGen.SetSerialNumber(serialNumber);
			certGen.SetIssuerDN(issuerDN);

			// Converted time to Universal Time so that the time set when calling Generate is the same as the time specified
			certGen.SetNotBefore(effectiveDate.ToUniversalTime());
			certGen.SetNotAfter(expirationDate.ToUniversalTime());

			certGen.SetSubjectDN(subjectDN);
			certGen.SetPublicKey(keyPair.Public);
			certGen.SetSignatureAlgorithm(SIGNATURE_ALGORITHM);

			if (extend != null)
			{
				extend(certGen, serialNumber);
			}

			Org.BouncyCastle.X509.X509Certificate bcCert = certGen.Generate(signingKey == null ? keyPair.Private : signingKey);

			X509Certificate2 dotNetCert = new X509Certificate2(bcCert.GetEncoded());

			return dotNetCert;
		}

		/// <summary>
		/// Renews <paramref name="certificate". This keeps all but the serial number, effective date, and expiration date./>
		/// </summary>
		/// <param name="certificate">Certificate being renewed</param>
		/// <param name="effectiveDate">New effective date</param>
		/// <param name="expirationDate">New expiration date</param>
		/// <param name="caCertificate">Signing certificate</param>
		/// <returns>New <seealso cref="X509Certificate2"/> renewed from <paramref name="certificate"/></returns>
		public static X509Certificate2 Renew(X509Certificate2 certificate, DateTime effectiveDate, DateTime expirationDate,
																				 X509Certificate2 caCertificate)
		{
			AsymmetricKeyParameter signingKey = caCertificate == null ? null : Certificate.TransformRSAPrivateKey((RSACryptoServiceProvider)caCertificate.PrivateKey);
			var privateKeyParameter = TransformRSAPrivateKey((RSACryptoServiceProvider)certificate.PrivateKey);
			var bcCert = DotNetUtilities.FromX509Certificate(certificate);
			var publicKeyParameter = bcCert.GetPublicKey();
			AsymmetricCipherKeyPair keyPair = new AsymmetricCipherKeyPair(publicKeyParameter, privateKeyParameter);

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			BigInteger serialNumber = CreateSerialNumber();

			certGen.SetSerialNumber(serialNumber);
			certGen.SetIssuerDN(bcCert.IssuerDN);

			// Converted time to Universal Time so that the time set when calling Generate is the same as the time specified
			certGen.SetNotBefore(effectiveDate.ToUniversalTime());
			certGen.SetNotAfter(expirationDate.ToUniversalTime());

			certGen.SetSubjectDN(bcCert.SubjectDN);
			certGen.SetPublicKey(keyPair.Public);
			certGen.SetSignatureAlgorithm(SIGNATURE_ALGORITHM);

			// Copy all extensions
			foreach (var ext in certificate.Extensions)
			{
				certGen.CopyAndAddExtension(ext.Oid.Value, ext.Critical, bcCert);
			}

			Org.BouncyCastle.X509.X509Certificate bcNewCert = certGen.Generate(signingKey == null ? keyPair.Private : signingKey);

			X509Certificate2 dotNetCert = new X509Certificate2(bcNewCert.GetEncoded());

			// Restore private key
			dotNetCert.PrivateKey = certificate.PrivateKey;

			return dotNetCert;
		}

		#region Export

		/// <summary>
		/// Exports a public key certificate
		/// </summary>
		/// <param name="path">Location where certificate is saved</param>
		/// <param name="certificate">Certificate to export</param>
		public static void Export(string path, X509Certificate2 certificate)
		{
			StringBuilder sb = new StringBuilder();
			sb.AppendLine("-----BEGIN CERTIFICATE-----");
			sb.AppendLine(certificate.ToBase64());
			sb.AppendLine("-----END CERTIFICATE-----");

			File.WriteAllText(path, sb.ToString());
		}

		/// <summary>
		/// Exports a public/private key certificate
		/// </summary>
		/// <param name="path">Location where certificate is saved</param>
		/// <param name="certificate">Certificate to export</param>
		/// <param name="password">Password used to protect file</param>
		public static void Export(string path, X509Certificate2 certificate, string password)
		{
			byte[] bytes = certificate.Export(X509ContentType.Pfx, password);
			File.WriteAllBytes(path, bytes);
		}

		#endregion

		#region AddToStore

		/// <summary>
		/// Adds <paramref name="certificate"/> to the certificate store given a <paramref name="storeName"/> and <paramref name="storeLocation"/>
		/// </summary>
		/// <param name="storeName"><see cref="StoreName"/></param>
		/// <param name="storeLocation"><see cref="StoreLocation"/></param>
		/// <param name="certificate"><see cref="X509Certificate2"/> that should be added to the certificate store</param>
		public static void AddToStore(StoreName storeName, StoreLocation storeLocation, X509Certificate2 certificate)
		{
			AddToStore(storeName.ToString(), storeLocation, certificate);
		}

		/// <summary>
		/// Adds <paramref name="certificate"/> to the certificate stored specified by <paramref name="storeName"/>
		/// </summary>
		/// <param name="storeName">Name of certificate store</param>
		/// <param name="storeLocation">Location of the certificate store</param>
		/// <param name="certificate"><see cref="X509Certificate2"/> certificate that should be added to the store</param>
		public static void AddToStore(string storeName, StoreLocation storeLocation, X509Certificate2 certificate)
		{
			X509Store store = new X509Store(storeName, storeLocation);
			store.Open(OpenFlags.ReadWrite);
			store.Add(certificate);
			store.Close();
		}

		#endregion

		#region RemoveFromStore

		/// <summary>
		/// Removes <paramref name="certificate"/> from the certificate store given a <paramref name="storeName"/> and <paramref name="storeLocation"/>
		/// </summary>
		/// <param name="storeName"><see cref="StoreName"/></param>
		/// <param name="storeLocation"><see cref="StoreLocation"/></param>
		/// <param name="certificate"><see cref="X509Certificate2"/> that should be removed from the certificate store</param>
		public static void RemoveFromStore(StoreName storeName, StoreLocation storeLocation, X509Certificate2 certificate)
		{
			RemoveFromStore(storeName.ToString(), storeLocation, certificate);
		}

		/// <summary>
		/// Removes <paramref name="certificate"/> from the certificate stored specified by <paramref name="storeName"/>
		/// </summary>
		/// <param name="storeName">Name of certificate store</param>
		/// <param name="storeLocation">Location of the certificate store</param>
		/// <param name="certificate"><see cref="X509Certificate2"/> certificate that should be removed to the store</param>
		public static void RemoveFromStore(string storeName, StoreLocation storeLocation, X509Certificate2 certificate)
		{
			X509Store store = new X509Store(storeName, storeLocation);
			store.Open(OpenFlags.ReadWrite);
			store.Remove(certificate);
			store.Close();
		}

		#endregion

		/// <summary>
		/// Loads a CSR from disk into a <see cref="Pkcs10CertificationRequest"/>
		/// </summary>
		/// <param name="fileName">Path to the CSR file</param>
		/// <returns><see cref="Pkcs10CertificationRequest"/></returns>
		public static Pkcs10CertificationRequest LoadCSR(string fileName)
		{
			using (TextReader tr = File.OpenText(fileName))
			{
				PemReader pr = new Org.BouncyCastle.OpenSsl.PemReader(tr);
				return pr.ReadObject() as Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest;
			}
		}

		/// <summary>
		/// Saves a <see cref="Pkcs10CertificationRequest"/> to <paramref name="fileName"/>
		/// </summary>
		/// <param name="csr"><see cref="Pkcs10CertificationRequest"/></param>
		/// <param name="fileName">Name of file</param>
		public static void SaveCSR(Pkcs10CertificationRequest csr, string fileName)
		{
			File.WriteAllText(fileName, csr.ToBase64());
		}

		#region Private

		/// <summary>
		/// Creates a serial number
		/// </summary>
		/// <returns>Serial number</returns>
		private static BigInteger CreateSerialNumber()
		{
			BigInteger serialNumber = BigInteger.ProbablePrime(120, new Random());
			return serialNumber;
		}

		/// <summary>
		/// Creates a RSA key pair
		/// </summary>
		/// <returns>RSA key pair</returns>
		public static AsymmetricCipherKeyPair CreateRSAKeyPair()
		{
			AsymmetricCipherKeyPair keyPair = null;
			lock(_locker)
			{
				var kpGen = new RsaKeyPairGenerator();
				kpGen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), BIT_STRENGTH));
				keyPair = kpGen.GenerateKeyPair();
			}
			return keyPair;
		}

		/// <summary>
		/// Converts an RsaPrivateCrtKeyParameter to an RSACryptoServiceProvider
		/// </summary>
		/// <param name="keyParams">Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters</param>
		/// <returns>System.Security.Cryptography.RSACryptoServiceProvider</returns>
		public static RSACryptoServiceProvider TransformRSAPrivateKey(RsaPrivateCrtKeyParameters keyParams)
		{
			RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(keyParams);
			CspParameters cspParameters = new CspParameters();
			cspParameters.KeyContainerName = "MyKeyContainer";
			RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(BIT_STRENGTH, cspParameters);
			rsaKey.ImportParameters(rsaParameters);
			return rsaKey;
		}

		/// <summary>
		/// Converts an RSACryptoServiceProvider to an RsaPrivateCrtKeyParameters
		/// </summary>
		/// <param name="privateKey">System.Security.Cryptography.RSACryptoServiceProvider</param>
		/// <returns>Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters</returns>
		private static RsaPrivateCrtKeyParameters TransformRSAPrivateKey(RSACryptoServiceProvider privateKey)
		{
			RSACryptoServiceProvider prov = privateKey as RSACryptoServiceProvider;
			RSAParameters parameters = prov.ExportParameters(true);
			return new RsaPrivateCrtKeyParameters(new BigInteger(1, parameters.Modulus),
																						new BigInteger(1, parameters.Exponent),
																						new BigInteger(1, parameters.D),
																						new BigInteger(1, parameters.P),
																						new BigInteger(1, parameters.Q),
																						new BigInteger(1, parameters.DP),
																						new BigInteger(1, parameters.DQ),
																						new BigInteger(1, parameters.InverseQ));
		}

		#endregion
	}
}
