# TNT.Cryptography

`TNT.Cryptography` is a .NET cryptography utility library developed by Tripp'n Technology, LLC. It provides developer-friendly abstractions and helper classes for symmetric and asymmetric encryption, key derivation, X.509 certificate generation, Certificate Signing Request (CSR) creation, and certificate store management.

---

## Features

- **Symmetric Encryption (AES)**
  - Encrypt and decrypt raw byte arrays.
  - Directly serialize, encrypt, decrypt, and deserialize .NET objects to and from Base64-encoded strings.
- **Key & IV Management**
  - Derive keys from passwords using PBKDF2 (`Rfc2898DeriveBytes`) with configurable salt, iterations, hash algorithms, and key sizes (128, 192, 256 bits).
  - Generate and manage initialization vectors (IVs).
  - Encapsulate key and IV configurations in `CipherAttributes`, with built-in JSON serialization.
- **Asymmetric Encryption (RSA)**
  - 2048-bit RSA encryption and decryption.
  - Automatic key pair generation or import from XML.
  - Automated block chunking to encrypt and decrypt arbitrary-length text.
- **X.509 Certificate & CSR Management (BouncyCastle Integration)**
  - Generate RSA key pairs.
  - Create and serialize PKCS#10 Certificate Signing Requests (CSRs) to/from PEM Base64.
  - Issue self-signed certificates or certificates signed by a Certificate Authority (CA).
  - Renew certificates while preserving existing extensions and properties.
  - Export certificates as PEM (`.crt`) or password-protected PKCS#12 (`.pfx`).
  - Add and remove certificates from Windows certificate stores (`X509Store`).
- **Strongly-Typed Certificate Extensions**
  - Built-in helpers for `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, `SubjectAlternativeName`, `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`, and `CrlDistributionPoints`.
  - Convenient extension methods on `X509Certificate2` to inspect CA status, CRL endpoints, and key usage.
- **Text Framing & Formatting Utilities**
  - Format Base64 and ciphertext with line-length wrapping and `--- BEGIN ---` / `--- END ---` delimiters.

---

## Installation

Install the package via the .NET CLI:

```bash
dotnet add package TNT.Cryptography
```

Or via the NuGet Package Manager Console:

```powershell
Install-Package TNT.Cryptography
```

---

## Quick Start & Usage Examples

### 1. Symmetric Encryption & Object Serialization

`SymmetricCipher` operates using `CipherAttributes`, which combines a `CipherKey` and an `InitializationVector`.

#### Encrypting and Decrypting Byte Arrays

```csharp
using TNT.Cryptography;
using System.Text;

// Derive a 256-bit key from a password
var cipherKey = CipherKey.Create("MySecretPassword", saltSize: 16, iterations: 10000);

// Generate a random 16-character initialization vector
var iv = InitializationVector.Create(16);

// Bundle key and IV into CipherAttributes
var attributes = new CipherAttributes(cipherKey, iv);
var cipher = new SymmetricCipher(attributes);

// Encrypt
byte[] plainBytes = Encoding.UTF8.GetBytes("Hello, secure world!");
byte[] encryptedBytes = cipher.Encrypt(plainBytes);

// Decrypt
byte[] decryptedBytes = cipher.Decrypt(encryptedBytes);
string result = Encoding.UTF8.GetString(decryptedBytes);
```

#### Encrypting and Decrypting Objects Directly

`SymmetricCipher` can serialize an object to JSON and encrypt it into a Base64 string in a single step:

```csharp
public record UserCredentials(string Username, string Token);

var credentials = new UserCredentials("admin", "secret-token-123");

// Encrypt object -> Base64 string
string encryptedPayload = cipher.Encrypt(credentials);

// Decrypt Base64 string -> object
UserCredentials? decrypted = cipher.Decrypt<UserCredentials>(encryptedPayload);
```

#### Serializing Cipher Attributes for Reuse

`CipherAttributes` can be serialized to JSON and stored for configuration:

```csharp
string jsonConfig = attributes.ToString();

// Later or on another system:
CipherAttributes restored = JsonSerializer.Deserialize<CipherAttributes>(jsonConfig)!;
var restoreCipher = new SymmetricCipher(restored);
```

---

### 2. Formatted Ciphertext with Tags

Use `FormatUtils` to wrap Base64 ciphertext into line-wrapped blocks bordered by `--- BEGIN ---` and `--- END ---` tags:

```csharp
using TNT.Cryptography;

string base64Data = Convert.ToBase64String(encryptedBytes);

// Wrap lines at 80 characters with delimiter headers
List<string> formattedLines = FormatUtils.FormatWithTags(base64Data, maxLineLength: 80);

// Strip delimiters and unwrap back to original Base64 string
string cleanBase64 = FormatUtils.RemoveTags(formattedLines);
```

---

### 3. Asymmetric Encryption (RSA)

`Asymmetric` wraps RSA encryption and handles block chunking automatically:

```csharp
using TNT.Cryptography;

// Generate a new 2048-bit RSA key pair
var rsa = new Asymmetric();

// Encrypt plaintext using the public key
string message = "Confidential message to encrypt with RSA";
byte[] cipherBytes = rsa.Encrypt(message);

// Decrypt ciphertext using the private key
string decryptedMessage = rsa.Decrypt(cipherBytes);

// Export keys as XML for storage
string publicKeyXml = rsa.PublicKey.ToString();
string privateKeyXml = rsa.PrivateKey.ToString();
```

You can also instantiate `Asymmetric` with existing public or private XML keys:

```csharp
var encryptorOnly = new Asymmetric(publicKey: XDocument.Parse(publicKeyXml));
var decryptorOnly = new Asymmetric(privateKey: XDocument.Parse(privateKeyXml));
```

---

### 4. X.509 Certificate & CSR Generation

Generate RSA key pairs, create PKCS#10 certificate requests (CSRs) with extensions, and issue certificates signed by a Certificate Authority or self-signed:

```csharp
using System.Security.Cryptography.X509Certificates;
using TNT.Cryptography;
using TNT.Cryptography.Extension;
using Org.BouncyCastle.Asn1.X509;

// 1. Generate RSA Key Pair
var keyPair = Certificate.CreateRSAKeyPair();

// 2. Configure X.509 Extensions
var extensions = new Extensions
{
    new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign),
    new BasicConstraints(new Org.BouncyCastle.Asn1.X509.BasicConstraints(true)),
    new SubjectKeyIdentifier(keyPair.Public),
    new SubjectAlternativeName(new GeneralNames(new GeneralName(GeneralName.DnsName, "localhost")))
};

// 3. Create Certificate Signing Request (CSR)
var csr = Certificate.CreateCertificationRequest("CN=My Certificate Authority, O=TNT, C=US", keyPair, extensions);

// Save or convert CSR to Base64 PEM string
string csrPem = csr.ToBase64();

// 4. Issue Certificate
DateTime notBefore = DateTime.UtcNow;
DateTime notAfter = notBefore.AddYears(2);

// Create self-signed root / CA certificate
X509Certificate2 caCertificate = Certificate.CreateCertificate(csr, keyPair, notBefore, notAfter);

// 5. Export Certificate
// Export public certificate as PEM (.crt)
Certificate.Export("ca.crt", caCertificate);

// Export certificate and private key as PKCS#12 (.pfx)
Certificate.Export("ca.pfx", caCertificate, "P@ssword123");
```

#### Certificate Store Operations

```csharp
// Install to CurrentUser\My
Certificate.AddToStore(StoreName.My, StoreLocation.CurrentUser, caCertificate);

// Remove from CurrentUser\My
Certificate.RemoveFromStore(StoreName.My, StoreLocation.CurrentUser, caCertificate);
```

---

## Core Classes Overview

| Class | Namespace | Purpose |
|---|---|---|
| `SymmetricCipher` | `TNT.Cryptography` | AES symmetric encryption and decryption for raw bytes and serialized objects. |
| `BaseCipher` | `TNT.Cryptography` | Abstract base class defining common cipher operations (`Encrypt`, `Decrypt`). |
| `CipherKey` | `TNT.Cryptography` | Represents a Base64-encoded key; includes PBKDF2 password derivation factory methods. |
| `InitializationVector` | `TNT.Cryptography` | Encapsulates an initialization vector with random generation utilities. |
| `CipherAttributes` | `TNT.Cryptography` | Key and IV container; serializable to JSON for storage and transmission. |
| `Asymmetric` | `TNT.Cryptography` | 2048-bit RSA wrapper supporting key pair generation, XML keys, and chunked string encryption. |
| `Certificate` | `TNT.Cryptography` | Static manager for creating key pairs, CSRs, X.509 certificates, renewals, and store management. |
| `FormatUtils` | `TNT.Cryptography` | Utilities to wrap and unwrap text with `--- BEGIN ---` and `--- END ---` delimiters. |
| `Extensions` | `TNT.Cryptography` | Collection of X.509 certificate extensions with implicit conversion to BouncyCastle `Asn1Set`. |
| `ExtensionMethods` | `TNT.Cryptography` | Extension methods for `X509Certificate2` and BouncyCastle generator classes. |
| `BouncyCastleExtensions` | `TNT.Cryptography` | Helper extension methods for `Pkcs10CertificationRequest` PEM conversion. |

---

## Target Framework & Dependencies

- **Target Framework:** `.NET 10.0`
- **Dependencies:**
  - `Portable.BouncyCastle` (1.9.0)

---

## License & Author

- **Author:** Tripp'n Technology, LLC.
- **Copyright:** Copyright © Tripp'n Technology, LLC. All rights reserved.
