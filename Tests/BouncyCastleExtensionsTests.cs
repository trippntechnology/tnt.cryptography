using System.Diagnostics.CodeAnalysis;
using TNT.Cryptography;

namespace Tests
{
	[ExcludeFromCodeCoverage]
	[TestClass]
	public class BouncyCastleExtensionsTests
	{
		private const String base64Csr = @"-----BEGIN CERTIFICATE REQUEST-----
MIIDXjCCAscCAQAwajELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlV0MQwwCgYDVQQH
DANTTEMxETAPBgNVBAoMCE1lZGljaXR5MRMwEQYDVQQLDApIZWFsdGhhZ2VuMRgw
FgYDVQQDDA9kZXZlbG9wbWVudC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
AoGBAPlKmMMbg0tPFx82xShqlNSeE3GwtIpzCkq3/N/fCHh3w7ZFJhWQRxdb5XC+
M5tuxX8ZnMJHyx1lL71AzirZjEZngvUo075amoPzkeyt/hThsYJ8olcaUQ1/V669
03V5CVoAPqMNNtVNZKThWYlXFE5JVwqfMcCgmo4aiSOamiDRAgMBAAGgggGyMBoG
CisGAQQBgjcNAgMxDBYKNi4xLjc2MDEuMjBOBgkrBgEEAYI3FRQxQTA/AgEFDB5M
VFAtU3RyaXBwLm1lZHNsYy5tZWRpY2l0eS5jb20MDU1FRFNMQ1xzdHJpcHAMC0lu
ZXRNZ3IuZXhlMHIGCisGAQQBgjcNAgIxZDBiAgEBHloATQBpAGMAcgBvAHMAbwBm
AHQAIABSAFMAQQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBh
AHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIDAQAwgc8GCSqGSIb3DQEJDjGBwTCB
vjAOBgNVHQ8BAf8EBAMCBPAwEwYDVR0lBAwwCgYIKwYBBQUHAwEweAYJKoZIhvcN
AQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFl
AwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUr
DgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUzELFHOdeVLuh266CARk7d/4XZk8w
DQYJKoZIhvcNAQEFBQADgYEAyjd0ObUM+CdqYzE3GmlJA3XDIlQnMkjrhgIYp749
3TWGcKySgFXTZOqFvRDaW9CGJocV5/yIBLApR8vixsBIMhraUahcUYS3pEJNsj9+
57Ar4jAYnd+w27g4c9lD4yOlSZ5N19RvGTow/w0Pwu1sZds6zw+kJnebc0dxySv7
Mwo=
-----END CERTIFICATE REQUEST-----
";

		[TestMethod]
		public void ToPkcs10CertificationRequest_Tests()
		{
			string? csr;

			using (var stream = File.OpenText("development.com.csr"))
			{
				csr = stream?.ReadToEnd();
			}

			Assert.IsNotNull(csr);

			var foo = csr.ToPkcs10CertificationRequest();
			Assert.AreEqual("#03818100CA377439B50CF8276A6331371A69490375C32254273248EB860218A7BE3DDD358670AC928055D364EA85BD10DA5BD086268715E7FC8804B02947CBE2C6C048321ADA51A85C5184B7A4424DB23F7EE7B02BE230189DDFB0DBB83873D943E323A5499E4DD7D46F193A30FF0D0FC2ED6C65DB3ACF0FA426779B734771C92BFB330A",
				foo.Signature.ToString());
		}

		[TestMethod]
		public void ToBase64_Tests()
		{
			string? csr;

			using (var stream = File.OpenText("development.com.csr"))
			{
				csr = stream?.ReadToEnd();
			}

			Assert.IsNotNull(csr);

			var pkcsCertReq = csr.ToPkcs10CertificationRequest();
			var base64 = pkcsCertReq.ToBase64();

			Assert.AreEqual(base64Csr, base64);
		}
	}
}
