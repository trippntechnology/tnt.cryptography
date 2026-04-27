using NUnit.Framework.Legacy;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
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

#pragma warning disable NUnit1032
    protected static X509Certificate2 TA
#pragma warning restore NUnit1032
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

    [OneTimeSetUp]
    public void Initialize()
    {
        m_EffectiveDate = DateTime.Now;
        m_ExpirationDate = m_EffectiveDate.AddDays(2);
    }

    [TearDown]
    public void Cleanup()
    {
        _TA?.Dispose();
        _TA = null;
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

    [Test]
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

    [Test]
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

    [Test]
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

    [Test]
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

    [Test]
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

    [Test]
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

    [Test]
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

    [Test]
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

        Assert.Throws<InvalidParameterException>(() =>
            Certificate.RequestCertificate(csr, m_EffectiveDate, m_ExpirationDate, null, null));
    }

    [Test]
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

    [Test]
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

    [Test]
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

    protected byte[] EncryptMsg(Byte[] msg, X509Certificate2 recipientCert)
    {
        ContentInfo contentInfo = new ContentInfo(msg);
        EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);
        CmsRecipient recip1 = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCert);
        envelopedCms.Encrypt(recip1);
        return envelopedCms.Encode();
    }

    protected Byte[] DecryptMsg(byte[] encodedEnvelopedCms)
    {
        EnvelopedCms envelopedCms = new EnvelopedCms();
        envelopedCms.Decode(encodedEnvelopedCms);
        envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);
        return envelopedCms.Encode();
    }
}
