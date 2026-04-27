using NUnit.Framework.Legacy;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class ExtensionMethodsTests
{
    private static DateTime EffectiveDate => DateTime.Now;
    private static DateTime ExpirationDate => DateTime.Now.AddDays(2);

    private static X509Certificate2 CreateCertificate(string subject, bool isCA = false, List<Uri> crlUrls = null,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.None, bool includeEnhancedKeyUsage = false,
        X509Certificate2 ca = null)
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        Extensions extensions = new Extensions();

        if (isCA)
        {
            extensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.CrlSign | KeyUsage.KeyCertSign));
            extensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(true)));
        }
        else if (keyUsage != X509KeyUsageFlags.None)
        {
            int bcKeyUsage = 0;
            if (keyUsage.HasFlag(X509KeyUsageFlags.DigitalSignature)) bcKeyUsage |= KeyUsage.DigitalSignature;
            if (keyUsage.HasFlag(X509KeyUsageFlags.KeyEncipherment)) bcKeyUsage |= KeyUsage.KeyEncipherment;
            extensions.Add(new TNT.Cryptography.Extension.KeyUsage(bcKeyUsage));
        }

        if (includeEnhancedKeyUsage)
        {
            extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection));
        }

        if (crlUrls != null)
        {
            extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(crlUrls));
        }

        Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(subject, keyPair, extensions);
        return Certificate.CreateCertificate(csr, keyPair, EffectiveDate, ExpirationDate, ca);
    }

    #region ToBase64

    [Test]
    public void ToBase64_ReturnsNonEmptyString()
    {
        X509Certificate2 cert = CreateCertificate("CN=test");
        string base64 = cert.ToBase64();

        Assert.IsNotNull(base64);
        Assert.IsNotEmpty(base64);
    }

    [Test]
    public void ToBase64_RoundTrips()
    {
        X509Certificate2 cert = CreateCertificate("CN=test");
        string base64 = cert.ToBase64();
        // Strip line breaks and decode — should reconstruct the same cert bytes
        byte[] decoded = Convert.FromBase64String(base64.Replace(Environment.NewLine, "").Replace("\n", ""));
        X509Certificate2 restored = new X509Certificate2(decoded);

        Assert.AreEqual(cert.Thumbprint, restored.Thumbprint);
    }

    #endregion

    #region IsCertificateAuthority

    [Test]
    public void IsCertificateAuthority_NullCertificate_ReturnsFalse()
    {
        X509Certificate2 cert = null;
        Assert.IsFalse(cert.IsCertificateAuthority());
    }

    [Test]
    public void IsCertificateAuthority_LeafCertificate_ReturnsFalse()
    {
        X509Certificate2 cert = CreateCertificate("CN=leaf");
        Assert.IsFalse(cert.IsCertificateAuthority());
    }

    [Test]
    public void IsCertificateAuthority_CACertificate_ReturnsTrue()
    {
        X509Certificate2 cert = CreateCertificate("CN=ca", isCA: true);
        Assert.IsTrue(cert.IsCertificateAuthority());
    }

    #endregion

    #region GetCrlDistributionPoints (X509Certificate2)

    [Test]
    public void GetCrlDistributionPoints_NullCertificate_ReturnsEmptyList()
    {
        X509Certificate2 cert = null;
        List<Uri> urls = cert.GetCrlDistributionPoints();

        Assert.IsNotNull(urls);
        Assert.AreEqual(0, urls.Count);
    }

    [Test]
    public void GetCrlDistributionPoints_NoCrlExtension_ReturnsEmptyList()
    {
        X509Certificate2 cert = CreateCertificate("CN=nocrl");
        List<Uri> urls = cert.GetCrlDistributionPoints();

        Assert.IsNotNull(urls);
        Assert.AreEqual(0, urls.Count);
    }

    [Test]
    public void GetCrlDistributionPoints_WithCrlUrls_ReturnsExpectedUrls()
    {
        List<Uri> expectedUrls = new List<Uri>
        {
            new Uri("http://crl.domain1.com/crl.crl"),
            new Uri("http://crl.domain2.com/crl.crl")
        };
        X509Certificate2 cert = CreateCertificate("CN=withcrl", crlUrls: expectedUrls);
        List<Uri> actualUrls = cert.GetCrlDistributionPoints();

        Assert.AreEqual(expectedUrls.Count, actualUrls.Count);
        CollectionAssert.AreEquivalent(expectedUrls.Select(u => u.ToString()), actualUrls.Select(u => u.ToString()));
    }

    #endregion

    #region GetEnhancedKeyUsage

    [Test]
    public void GetEnhancedKeyUsage_NullCertificate_ReturnsNull()
    {
        X509Certificate2 cert = null;
        Assert.IsNull(cert.GetEnhancedKeyUsage());
    }

    [Test]
    public void GetEnhancedKeyUsage_NoExtension_ReturnsNull()
    {
        X509Certificate2 cert = CreateCertificate("CN=noeku");
        Assert.IsNull(cert.GetEnhancedKeyUsage());
    }

    [Test]
    public void GetEnhancedKeyUsage_WithExtension_ReturnsExtension()
    {
        X509Certificate2 cert = CreateCertificate("CN=witheku", includeEnhancedKeyUsage: true);
        X509EnhancedKeyUsageExtension eku = cert.GetEnhancedKeyUsage();

        Assert.IsNotNull(eku);
        Assert.AreEqual(KeyPurposeID.IdKPEmailProtection.Id, eku.EnhancedKeyUsages[0].Value);
    }

    #endregion

    #region GetKeyUsage

    [Test]
    public void GetKeyUsage_NullCertificate_ReturnsNone()
    {
        X509Certificate2 cert = null;
        Assert.AreEqual(X509KeyUsageFlags.None, cert.GetKeyUsage());
    }

    [Test]
    public void GetKeyUsage_NoExtension_ReturnsNone()
    {
        X509Certificate2 cert = CreateCertificate("CN=nokeyusage");
        Assert.AreEqual(X509KeyUsageFlags.None, cert.GetKeyUsage());
    }

    [Test]
    public void GetKeyUsage_WithDigitalSignature_ReturnsDigitalSignature()
    {
        X509Certificate2 cert = CreateCertificate("CN=ds", keyUsage: X509KeyUsageFlags.DigitalSignature);
        X509KeyUsageFlags flags = cert.GetKeyUsage();

        Assert.IsTrue(flags.HasFlag(X509KeyUsageFlags.DigitalSignature));
    }

    [Test]
    public void GetKeyUsage_WithKeyEncipherment_ReturnsKeyEncipherment()
    {
        X509Certificate2 cert = CreateCertificate("CN=ke", keyUsage: X509KeyUsageFlags.KeyEncipherment);
        X509KeyUsageFlags flags = cert.GetKeyUsage();

        Assert.IsTrue(flags.HasFlag(X509KeyUsageFlags.KeyEncipherment));
    }

    #endregion

    #region AddCrlDistributionPoints

    private static X509Certificate2 BuildCertWithCertGen(Action<X509V3CertificateGenerator> configure)
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
        certGen.SetIssuerDN(new X509Name("CN=test"));
        certGen.SetSubjectDN(new X509Name("CN=test"));
        certGen.SetNotBefore(DateTime.UtcNow);
        certGen.SetNotAfter(DateTime.UtcNow.AddDays(2));
        certGen.SetPublicKey(keyPair.Public);
        certGen.SetSignatureAlgorithm("SHA256WITHRSA");
        configure(certGen);
        Org.BouncyCastle.X509.X509Certificate bcCert = certGen.Generate(keyPair.Private);
        return new X509Certificate2(bcCert.GetEncoded());
    }

    [Test]
    public void AddCrlDistributionPoints_NullUrls_AddsNoExtension()
    {
        X509Certificate2 cert = BuildCertWithCertGen(certGen =>
        {
            certGen.AddCrlDistributionPoints(null);
        });

        List<Uri> urls = cert.GetCrlDistributionPoints();
        Assert.AreEqual(0, urls.Count);
    }

    [Test]
    public void AddCrlDistributionPoints_WithUrls_AddsExpectedUrls()
    {
        List<Uri> expectedUrls = new List<Uri>
        {
            new Uri("http://crl.domain1.com/crl.crl"),
            new Uri("http://crl.domain2.com/crl.crl"),
            new Uri("ldap://crl.domain3.com/crl.crl")
        };

        X509Certificate2 cert = BuildCertWithCertGen(certGen =>
        {
            certGen.AddCrlDistributionPoints(expectedUrls);
        });

        List<Uri> actualUrls = cert.GetCrlDistributionPoints();

        Assert.AreEqual(expectedUrls.Count, actualUrls.Count);
        CollectionAssert.AreEquivalent(expectedUrls.Select(u => u.ToString()), actualUrls.Select(u => u.ToString()));
    }

    #endregion
}
