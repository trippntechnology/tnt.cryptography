using NUnit.Framework.Legacy;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class CertificateAdditionalTests
{
    private DateTime EffectiveDate;
    private DateTime ExpirationDate;

    [SetUp]
    public void SetUp()
    {
        EffectiveDate = DateTime.Now;
        ExpirationDate = EffectiveDate.AddDays(2);
    }

    private X509Certificate2 CreateSelfSignedCert(string subject, List<Uri> crlUrls = null)
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        Extensions extensions = new Extensions();
        extensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(keyPair.Public));
        if (crlUrls != null)
            extensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(crlUrls));
        Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest(subject, keyPair, extensions);
        return Certificate.CreateCertificate(csr, keyPair, EffectiveDate, ExpirationDate);
    }

    private (X509Certificate2 ca, X509Certificate2 cert) CreateCaAndSignedCert(string caSubject, string certSubject, List<Uri> crlUrls = null)
    {
        AsymmetricCipherKeyPair caKeyPair = Certificate.CreateRSAKeyPair();
        Extensions caExtensions = new Extensions();
        caExtensions.Add(new TNT.Cryptography.Extension.KeyUsage(KeyUsage.CrlSign | KeyUsage.KeyCertSign));
        caExtensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(caKeyPair.Public));
        caExtensions.Add(new TNT.Cryptography.Extension.BasicConstraints(new BasicConstraints(true)));
        Pkcs10CertificationRequest caCsr = Certificate.CreateCertificationRequest(caSubject, caKeyPair, caExtensions);
        X509Certificate2 ca = Certificate.CreateCertificate(caCsr, caKeyPair, EffectiveDate, ExpirationDate);

        AsymmetricCipherKeyPair certKeyPair = Certificate.CreateRSAKeyPair();
        Extensions certExtensions = new Extensions();
        certExtensions.Add(new TNT.Cryptography.Extension.SubjectKeyIdentifier(certKeyPair.Public));
        if (crlUrls != null)
            certExtensions.Add(new TNT.Cryptography.Extension.CrlDistributionPoints(crlUrls));
        Pkcs10CertificationRequest certCsr = Certificate.CreateCertificationRequest(certSubject, certKeyPair, certExtensions);
        X509Certificate2 cert = Certificate.CreateCertificate(certCsr, certKeyPair, EffectiveDate, ExpirationDate, ca);

        return (ca, cert);
    }

    #region CreateCertificationRequest

    [Test]
    public void CreateCertificationRequest_WithoutExtensions_ReturnsValidCsr()
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest("CN=test", keyPair);

        Assert.IsNotNull(csr);
        Assert.IsTrue(csr.Verify());
        Assert.AreEqual("CN=test", csr.GetCertificationRequestInfo().Subject.ToString());
    }

    [Test]
    public void CreateCertificationRequest_WithExtensions_IncludesExtensionsInCsr()
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        Extensions extensions = new Extensions();
        extensions.Add(new TNT.Cryptography.Extension.ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));

        Pkcs10CertificationRequest csr = Certificate.CreateCertificationRequest("CN=test", keyPair, extensions);

        Assert.IsNotNull(csr);
        Assert.IsTrue(csr.Verify());
        // Attributes set should contain the extension request
        Assert.Greater(csr.GetCertificationRequestInfo().Attributes.Count, 0);
    }

    #endregion

    #region CreateRSAKeyPair

    [Test]
    public void CreateRSAKeyPair_ReturnsNonNullKeyPair()
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();

        Assert.IsNotNull(keyPair);
        Assert.IsNotNull(keyPair.Public);
        Assert.IsNotNull(keyPair.Private);
    }

    [Test]
    public void CreateRSAKeyPair_ReturnsDifferentKeysEachCall()
    {
        AsymmetricCipherKeyPair keyPair1 = Certificate.CreateRSAKeyPair();
        AsymmetricCipherKeyPair keyPair2 = Certificate.CreateRSAKeyPair();

        RsaKeyParameters pub1 = (RsaKeyParameters)keyPair1.Public;
        RsaKeyParameters pub2 = (RsaKeyParameters)keyPair2.Public;

        Assert.AreNotEqual(pub1.Modulus, pub2.Modulus);
    }

    #endregion

    #region TransformRSAPrivateKey

    [Test]
    public void TransformRSAPrivateKey_FromRsaPrivateCrtKeyParameters_ReturnsUsableProvider()
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        RsaPrivateCrtKeyParameters bcPrivateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

        RSACryptoServiceProvider provider = Certificate.TransformRSAPrivateKey(bcPrivateKey);

        Assert.IsNotNull(provider);
        Assert.IsFalse(provider.PublicOnly);

        // Verify it can sign and verify data
        byte[] data = System.Text.Encoding.UTF8.GetBytes("test data");
        byte[] signature = provider.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.IsTrue(provider.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public void TransformRSAPrivateKey_FromRSACryptoServiceProvider_ReturnsMatchingBcKey()
    {
        AsymmetricCipherKeyPair keyPair = Certificate.CreateRSAKeyPair();
        RsaPrivateCrtKeyParameters originalBcKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

        // Round-trip: BC -> CSP -> BC
        RSACryptoServiceProvider csp = Certificate.TransformRSAPrivateKey(originalBcKey);
        RsaPrivateCrtKeyParameters roundTrippedKey = Certificate.TransformRSAPrivateKey(csp);

        Assert.AreEqual(originalBcKey.Modulus, roundTrippedKey.Modulus);
        Assert.AreEqual(originalBcKey.Exponent, roundTrippedKey.Exponent);
        Assert.AreEqual(originalBcKey.Exponent, roundTrippedKey.Exponent);
        Assert.AreEqual(originalBcKey.P, roundTrippedKey.P);
        Assert.AreEqual(originalBcKey.Q, roundTrippedKey.Q);
    }

    #endregion

    #region Export

    [Test]
    public void Export_PublicCert_WritesPemFile()
    {
        string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.cer");
        try
        {
            X509Certificate2 cert = CreateSelfSignedCert("CN=exporttest");
            Certificate.Export(path, cert);

            Assert.IsTrue(File.Exists(path));
            string contents = File.ReadAllText(path);
            Assert.IsTrue(contents.Contains("-----BEGIN CERTIFICATE-----"));
            Assert.IsTrue(contents.Contains("-----END CERTIFICATE-----"));

            // Verify the exported cert round-trips
            string base64 = contents
                .Replace("-----BEGIN CERTIFICATE-----", "")
                .Replace("-----END CERTIFICATE-----", "")
                .Trim();
            X509Certificate2 restored = new X509Certificate2(Convert.FromBase64String(base64));
            Assert.AreEqual(cert.Thumbprint, restored.Thumbprint);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Test]
    public void Export_PfxWithPassword_WritesLoadablePfxFile()
    {
        string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pfx");
        const string password = "TestP@ssw0rd!";
        try
        {
            X509Certificate2 cert = CreateSelfSignedCert("CN=pfxexporttest");
            Certificate.Export(path, cert, password);

            Assert.IsTrue(File.Exists(path));
            X509Certificate2 loaded = new X509Certificate2(path, password);
            Assert.AreEqual(cert.Subject, loaded.Subject);
            Assert.AreEqual(cert.Thumbprint, loaded.Thumbprint);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    #endregion

    #region AddToStore / RemoveFromStore

    [Test]
    public void AddToStore_StoreName_And_RemoveFromStore_StoreName_RoundTrip()
    {
        X509Certificate2 cert = CreateSelfSignedCert("CN=StoreTestByEnum");
        try
        {
            Certificate.AddToStore(StoreName.My, StoreLocation.CurrentUser, cert);

            using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            Assert.IsTrue(store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0);
        }
        finally
        {
            Certificate.RemoveFromStore(StoreName.My, StoreLocation.CurrentUser, cert);

            using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            Assert.AreEqual(0, store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count);
        }
    }

    [Test]
    public void AddToStore_StringName_And_RemoveFromStore_StringName_RoundTrip()
    {
        X509Certificate2 cert = CreateSelfSignedCert("CN=StoreTestByString");
        try
        {
            Certificate.AddToStore("My", StoreLocation.CurrentUser, cert);

            using X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            Assert.IsTrue(store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0);
        }
        finally
        {
            Certificate.RemoveFromStore("My", StoreLocation.CurrentUser, cert);

            using X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            Assert.AreEqual(0, store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count);
        }
    }

    #endregion

    #region Renew

    [Test]
    public void Renew_SelfSigned_UpdatesDatesAndPreservesPrivateKey()
    {
        DateTime now = DateTime.Now;
        X509Certificate2 original = CreateSelfSignedCert("CN=renewtest");

        DateTime newEffective = now.AddYears(1);
        DateTime newExpiration = now.AddYears(2);
        X509Certificate2 renewed = Certificate.Renew(original, newEffective, newExpiration, null);

        Assert.IsNotNull(renewed);
        Assert.AreEqual(original.Subject, renewed.Subject);
        Assert.AreEqual(original.Issuer, renewed.Issuer);
        Assert.AreEqual(newEffective.ToString(), renewed.NotBefore.ToString());
        Assert.AreEqual(newExpiration.ToString(), renewed.NotAfter.ToString());
        Assert.AreNotEqual(original.SerialNumber, renewed.SerialNumber);
        Assert.AreNotEqual(original.Thumbprint, renewed.Thumbprint);
        Assert.IsTrue(renewed.HasPrivateKey);
        CollectionAssert.AreEqual(original.PublicKey.EncodedKeyValue.RawData, renewed.PublicKey.EncodedKeyValue.RawData);
    }

    [Test]
    public void Renew_CaSigned_PreservesIssuerAndExtensions()
    {
        DateTime now = DateTime.Now;
        List<Uri> crlUrls = new List<Uri> { new Uri("http://crl.domain.com/crl.crl") };
        var (ca, cert) = CreateCaAndSignedCert("CN=renewca", "CN=renewleaf", crlUrls);

        DateTime newEffective = now.AddYears(1);
        DateTime newExpiration = now.AddYears(2);
        X509Certificate2 renewed = Certificate.Renew(cert, newEffective, newExpiration, ca);

        Assert.AreEqual(cert.Subject, renewed.Subject);
        Assert.AreEqual(cert.Issuer, renewed.Issuer);
        Assert.AreEqual(newEffective.ToString(), renewed.NotBefore.ToString());
        Assert.AreEqual(newExpiration.ToString(), renewed.NotAfter.ToString());
        Assert.AreNotEqual(cert.SerialNumber, renewed.SerialNumber);

        CollectionAssert.AreEqual(
            cert.GetCrlDistributionPoints().Select(u => u.ToString()),
            renewed.GetCrlDistributionPoints().Select(u => u.ToString()));
    }

    #endregion
}
