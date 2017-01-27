using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace TNT.Cryptography
{
	/// <summary>
	/// Extension methods
	/// </summary>
	public static class Extensions
	{
		/// <summary>
		/// Converts an <see cref="X509Certificate2"/> to a base64 encoded string
		/// </summary>
		/// <param name="certificate"><see cref="X509Certificate2"/> that should be converted</param>
		/// <returns>Base64 encoded string representing the certificate</returns>
		public static string ToBase64(this X509Certificate2 certificate)
		{
			return Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks);
		}

		/// <summary>
		/// Indicates whether a certificate is a certificate authority
		/// </summary>
		/// <param name="certificate"><seealso cref="X509Certificate2"/> to check</param>
		/// <returns>True if the basic contraint's CertificateAuthority extension is true</returns>
		public static bool IsCertificateAuthority(this X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				return false;
			}

			X509BasicConstraintsExtension basicContraint = certificate.Extensions[X509Extensions.BasicConstraints.ToString()] as X509BasicConstraintsExtension;
			return basicContraint != null ? basicContraint.CertificateAuthority : false;
		}

		/// <summary>
		/// Gets the CRL URLs from the CRL Distribution Points extension
		/// </summary>
		/// <param name="certificate"><seealso cref="X509Certificate2"/></param>
		/// <returns>CRL URLs from the CRL Distribution Points extension</returns>
		public static List<Uri> GetCrlDistributionPoints(this X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				return new List<Uri>();
			}

			Org.BouncyCastle.X509.X509Certificate caCert = DotNetUtilities.FromX509Certificate(certificate);

			return GetCrlDistributionPoints(caCert);
		}

		/// <summary>
		/// Adds the CRL URLs to the CRL Distirbution Points extension
		/// </summary>
		/// <param name="certGen"><see cref="X509V3CertificateGenerator"/></param>
		/// <param name="crlUrls">List of <seealso cref="Uri"/></param>
		public static void AddCrlDistributionPoints(this X509V3CertificateGenerator certGen, List<Uri> crlUrls)
		{
			if (crlUrls != null)
			{
				List<DistributionPoint> distributionPoints = new List<DistributionPoint>();

				foreach (Uri url in crlUrls)
				{
					GeneralName gn = new GeneralName(GeneralName.UniformResourceIdentifier, url.ToString());
					DistributionPointName distributionPointname = new DistributionPointName(DistributionPointName.FullName, gn);
					distributionPoints.Add(new DistributionPoint(distributionPointname, null, null));
				}

				certGen.AddExtension(X509Extensions.CrlDistributionPoints, true, new CrlDistPoint(distributionPoints.ToArray()));
			}
		}

		/// <summary>
		/// Gets the CRL URLs from the CRL Distribution Points extension
		/// </summary>
		/// <param name="certificate"><seealso cref="Org.BouncyCastle.X509.X509Certificate"/></param>
		/// <returns>CRL URLs from the CRL Distribution Points extension</returns>
		public static List<Uri> GetCrlDistributionPoints(this Org.BouncyCastle.X509.X509Certificate certificate)
		{
			List<Uri> crlUrls = new List<Uri>();

			if (certificate == null)
			{
				return crlUrls;
			}

			var cdpExtention =certificate.GetExtensionValue(X509Extensions.CrlDistributionPoints);

			if (cdpExtention == null)
			{
				return crlUrls;
			}

			byte[] crldpExt = cdpExtention.GetDerEncoded();

			if (crldpExt == null)
			{
				return crlUrls;
			}

			Asn1InputStream oAsnInStream = new Asn1InputStream(crldpExt);
			var derObjCrlDP = oAsnInStream.ReadObject();
			DerOctetString dosCrlDP = (DerOctetString)derObjCrlDP;
			byte[] crldpExtOctets = dosCrlDP.GetOctets();
			Asn1InputStream oAsnInStream2 = new Asn1InputStream(crldpExtOctets);
			var derObj2 = oAsnInStream2.ReadObject();
			CrlDistPoint distPoint = CrlDistPoint.GetInstance(derObj2);

			foreach (DistributionPoint dp in distPoint.GetDistributionPoints())
			{
				DistributionPointName dpn = dp.DistributionPointName;
				// Look for URIs in fullName
				if (dpn != null)
				{
					if (dpn.GetType() == typeof(Org.BouncyCastle.Asn1.X509.DistributionPointName)) 
					{
						GeneralName[] genNames = GeneralNames.GetInstance(dpn.Name).GetNames();
						// Look for an URI
						for (int j = 0; j < genNames.Length; j++)
						{
							if (genNames[j].TagNo== GeneralName.UniformResourceIdentifier)
							{
								Uri uri;
								String url = DerIA5String.GetInstance(genNames[j].Name).GetString();
								if (Uri.TryCreate(url, UriKind.Absolute, out uri))
								{
									crlUrls.Add(uri);
								}
							}
						}
					}
				}
			}

			return crlUrls;
		}
	}
}
