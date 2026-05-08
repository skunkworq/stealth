# Root CA Certificate Chain Spoofing

## Overview

Different operating systems and browsers trust different Root Certificate Authorities (CAs). When spoofing browser fingerprints, the certificate chain sent during TLS handshake is a fingerprinting vector that can reveal:
- Operating system (Windows, macOS, Linux, iOS, Android)
- Browser type (Chrome, Firefox, Safari, Edge)
- Geographic location (some CAs are region-specific)
- Enterprise vs Consumer (enterprise often uses custom/internal CAs)

## Platform-Specific Root CAs

### Windows (Microsoft Trusted Root Program)

**Default Root CAs:**
- **DigiCert Inc** - Most common on Windows
- **GlobalSign** - European, also common
- **Go Daddy** - Consumer/SMB focus
- **Microsoft** - For Microsoft services
- **Entrust** - Enterprise focus
- **Symantec/VeriSign** - Legacy enterprise

**Characteristics:**
- RSA 2048-bit keys most common
- SHA-256 signatures (SHA-1 deprecated)
- OCSP stapling supported
- Certificate chains typically 2-3 levels deep

**Example Chain (coles.com.au):**
```
Root: DigiCert Inc
  └── Intermediate: Thawte RSA CA 2018
        └── Leaf: www.coles.com.au (Coles Supermarkets Australia)
```

### macOS/iOS (Apple Root Certificate Program)

**Default Root CAs:**
- **Apple Inc.** - Apple's own root
- **DigiCert Inc** - Also trusted on Apple
- **GlobalSign** - Common alternative

**Characteristics:**
- Apple is aggressively moving to ECC (P-256)
- Strict certificate transparency requirements
- Shorter validity periods (1 year typical)
- EV certificates show company name in Safari

**Example Chain:**
```
Root: Apple Inc.
  └── Intermediate: Apple Public EV Server RSA CA 1
        └── Leaf: www.example.com
```

### Linux (Mozilla/System CA Store)

**Default Root CAs:**
- **ISRG Root X1** (Let's Encrypt) - Most common on Linux
- **DigiCert Inc** - Also present
- **GlobalSign** - Alternative

**Characteristics:**
- Let's Encrypt is the dominant free CA
- 4096-bit RSA or ECDSA P-256
- 90-day certificate validity (short!)
- Automatic renewal (certbot)

**Example Chain:**
```
Root: ISRG Root X1 (Internet Security Research Group)
  └── Intermediate: R3
        └── Leaf: www.example.com
```

### Android (Google Trust Services)

**Default Root CAs:**
- **GTS Root R1** (Google Trust Services)
- **GlobalSign** - Alternative
- **DigiCert** - Also present

**Characteristics:**
- Google is pushing for ECC
- RSA 4096-bit or ECDSA P-384
- Certificate transparency required

**Example Chain:**
```
Root: GTS Root R1 (Google Trust Services)
  └── Intermediate: GTS CA 1C3
        └── Leaf: www.example.com
```

## Certificate Details as Fingerprint

### Key Identifiers

1. **Issuer Organization**
   - Windows: "DigiCert Inc", "Microsoft Corporation"
   - macOS: "Apple Inc."
   - Linux: "Internet Security Research Group"
   - Android: "Google Trust Services"

2. **Key Algorithm & Size**
   - Windows: RSA 2048 (legacy) / RSA 4096 / ECDSA P-256
   - macOS: ECDSA P-256 (increasingly common)
   - Linux: RSA 4096 or ECDSA P-256
   - Android: ECDSA P-384 or RSA 4096

3. **Signature Algorithm**
   - SHA-256 with RSA (most common)
   - SHA-384 with RSA (high security)
   - SHA-256 with ECDSA (modern)

4. **Validity Period**
   - Enterprise: 1-2 years
   - Let's Encrypt: 90 days
   - Apple: 1 year max

5. **Extensions**
   - OCSP Must-Staple (modern browsers)
   - Certificate Transparency (SCT timestamps)
   - Subject Alternative Names (SANs)

## Coles.com.au Analysis

The certificate you downloaded shows:

```
Root CA:
  CN: DigiCert Inc
  O:  DigiCert Inc  
  OU: www.digicert.com
  
Intermediate CA:
  CN: Thawte RSA CA 2018
  O:  DigiCert Inc
  OU: www.digicert.com
  
Leaf Certificate:
  CN: www.coles.com.au
  O:  Coles Supermarkets Australia Pty Ltd
  C:  AU (Australia)
  
Validity: Apr 30, 2025 - Apr 15, 2026 (~1 year)
Public Key: 9b5984f48e8ccae2d6e0d3692bcd862aab03ae969091898640b883c4b96e43b3
```

**What this tells us:**
- **Target Market**: Windows users (DigiCert is Windows default)
- **Enterprise Grade**: Thawte intermediate + 1-year validity
- **Australian Business**: Country code AU, local business name
- **Standard Security**: RSA 2048-bit, SHA-256

## Implementation

### Tools Created

1. **scanciphers** - Scan remote sites for cipher suites
   ```bash
   ./build/scanciphers -host www.coles.com.au
   ```

2. **gencert** - Show platform-specific CA configurations
   ```bash
   ./build/gencert -platform windows -browser chrome
   ```

### Configuration System

The `brws/config/certificate.go` file provides:

```go
// Platform-specific root CA presets
config.PlatformRootCAs["windows"] // DigiCert
config.PlatformRootCAs["macos"]   // Apple
config.PlatformRootCAs["linux"]   // ISRG/Let's Encrypt
config.PlatformRootCAs["ios"]     // Apple (ECC)
config.PlatformRootCAs["android"] // Google

// Browser-specific intermediate CAs
config.BrowserIntermediateCAs["chrome"]  // Google Trust Services
config.BrowserIntermediateCAs["firefox"] // DigiCert
config.BrowserIntermediateCAs["safari"]  // Apple
config.BrowserIntermediateCAs["edge"]    // Microsoft
```

### Coles-Specific Config

```go
var ColesCertificateConfig = &CertificateChainConfig{
    Platform: "windows",
    Browser:  "chrome",
    RootCA: RootCAConfig{
        CommonName:   "DigiCert Inc",
        Organization: "DigiCert Inc",
        Country:      "US",
    },
    IntermediateCA: IntermediateCAConfig{
        CommonName: "Thawte RSA CA 2018",
        Organization: "DigiCert Inc",
    },
    LeafCert: LeafCertConfig{
        CommonName:   "www.coles.com.au",
        Organization: "Coles Supermarkets Australia Pty Ltd",
        Country:      "AU",
    },
}
```

## Why This Matters for Spoofing

### Detection Vectors

1. **Certificate Transparency Logs**
   - Real certificates are logged publicly
   - Self-signed certs won't appear in logs
   - Missing SCT (Signed Certificate Timestamp) is suspicious

2. **Root CA Trust Store**
   - Browser knows which CAs it trusts
   - Unknown issuer = warning page
   - Must use well-known CA names

3. **Certificate Pinning**
   - Some apps pin specific certificates
   - Facebook, Twitter, banking apps
   - Must match exact public key hash

4. **Timing Analysis**
   - OCSP checks to specific URLs
   - CRL downloads from specific CDPs
   - Different CAs = different infrastructure

### Best Practices

1. **Use Real CA Names**
   - Match platform-appropriate root CA
   - Use known intermediate CAs
   - Match organizational structure

2. **Match Key Algorithms**
   - Windows: RSA 2048 (common)
   - macOS: ECC P-256 (modern)
   - Linux: RSA 4096 (paranoid)

3. **Set Appropriate Validity**
   - Match platform norms (90 days - 2 years)
   - Set realistic issue/expiry dates
   - Don't use 100-year certificates

4. **Include Required Extensions**
   - Subject Alternative Names (SANs)
   - Key Usage / Extended Key Usage
   - OCSP and CRL distribution points

## Future Work

1. **Certificate Generation**
   - Implement actual crypto to generate certs
   - Sign with spoofed CA chain
   - Match exact binary format

2. **OCSP/CRL Simulation**
   - Mock OCSP responders
   - Serve CRL lists
   - Handle stapling correctly

3. **Transparency Logs**
   - Add fake SCT timestamps
   - Query real CT logs
   - Pre-certificate handling

4. **Platform Detection**
   - Auto-detect target platform
   - Suggest appropriate CA chain
   - Validate against real browsers
