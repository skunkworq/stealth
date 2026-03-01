// Package config provides certificate chain configuration for platform-specific spoofing
package config

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// CertificateChainConfig configures the appearance of TLS certificates
// to match platform-specific root CAs
type CertificateChainConfig struct {
	// Platform to mimic (affects root CA selection)
	Platform string `json:"platform"` // macos, windows, linux, ios, android

	// Browser to mimic (affects intermediate CA and cert details)
	Browser string `json:"browser"` // chrome, firefox, safari, edge

	// Root CA configuration
	RootCA RootCAConfig `json:"root_ca"`

	// Intermediate CA configuration
	IntermediateCA IntermediateCAConfig `json:"intermediate_ca,omitempty"`

	// Leaf certificate configuration
	LeafCert LeafCertConfig `json:"leaf_cert"`

	// Certificate validity period
	ValidityPeriod ValidityConfig `json:"validity"`
}

// RootCAConfig configures the root certificate authority appearance
type RootCAConfig struct {
	// Common Name (e.g., "DigiCert Inc", "GlobalSign", "Go Daddy")
	CommonName string `json:"common_name"`

	// Organization
	Organization string `json:"organization"`

	// Organizational Unit
	OrganizationalUnit string `json:"organizational_unit,omitempty"`

	// Country
	Country string `json:"country,omitempty"`

	// State/Province
	State string `json:"state,omitempty"`

	// Locality
	Locality string `json:"locality,omitempty"`

	// Serial number format (random or specific pattern)
	SerialNumber string `json:"serial_number,omitempty"`

	// Key algorithm and size (RSA 2048, RSA 4096, ECDSA P-256, etc.)
	KeyAlgorithm string `json:"key_algorithm"` // "RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"

	// Signature algorithm
	SignatureAlgorithm string `json:"signature_algorithm"` // "SHA256-RSA", "SHA384-RSA", "SHA256-ECDSA"

	// Certificate policies (OID strings)
	CertificatePolicies []string `json:"certificate_policies,omitempty"`

	// CRL distribution points
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`

	// OCSP server URLs
	OCSPServers []string `json:"ocsp_servers,omitempty"`
}

// IntermediateCAConfig configures the intermediate certificate authority
type IntermediateCAConfig struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	KeyAlgorithm       string `json:"key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

// LeafCertConfig configures the leaf/server certificate
type LeafCertConfig struct {
	// Subject Alternative Names (DNS names and IPs)
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses,omitempty"`

	// Subject info
	CommonName   string `json:"common_name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`

	// Key usage
	KeyUsage []string `json:"key_usage"` // "digital_signature", "key_encipherment", etc.

	// Extended key usage
	ExtKeyUsage []string `json:"ext_key_usage"` // "server_auth", "client_auth"

	// Certificate transparency (SCT) timestamps
	IncludeSCT bool `json:"include_sct,omitempty"`

	// Must staple OCSP
	MustStaple bool `json:"must_staple,omitempty"`
}

// ValidityConfig configures certificate validity period
type ValidityConfig struct {
	// Duration from now (e.g., "1y", "90d", "2y6m")
	Duration string `json:"duration"`

	// Or specific dates
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
}

// PlatformRootCAs provides platform-specific Root CA presets for certificate chain spoofing
var PlatformRootCAs = map[string]RootCAConfig{
	// Windows typically uses DigiCert
	"windows": {
		CommonName:         "DigiCert Inc",
		Organization:       "DigiCert Inc",
		OrganizationalUnit: "www.digicert.com",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
		CRLDistributionPoints: []string{
			"http://crl3.digicert.com/DigiCertGlobalRootCA.crl",
			"http://crl4.digicert.com/DigiCertGlobalRootCA.crl",
		},
		OCSPServers: []string{
			"http://ocsp.digicert.com",
		},
	},

	// macOS/iOS typically uses Apple Root CA or DigiCert
	"macos": {
		CommonName:         "Apple Inc.",
		Organization:       "Apple Inc.",
		OrganizationalUnit: "Certification Authority",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
		CRLDistributionPoints: []string{
			"http://crl.apple.com/root.crl",
		},
	},

	"ios": {
		CommonName:         "Apple Inc.",
		Organization:       "Apple Inc.",
		OrganizationalUnit: "Certification Authority",
		Country:            "US",
		KeyAlgorithm:       "ECDSA-P256",
		SignatureAlgorithm: "SHA256-ECDSA",
	},

	// Linux uses various CAs, commonly Let's Encrypt or system store
	"linux": {
		CommonName:         "ISRG Root X1",
		Organization:       "Internet Security Research Group",
		Country:            "US",
		KeyAlgorithm:       "RSA-4096",
		SignatureAlgorithm: "SHA256-RSA",
		OCSPServers: []string{
			"http://r3.o.lencr.org",
		},
	},

	// Android uses Google Trust Services
	"android": {
		CommonName:         "GTS Root R1",
		Organization:       "Google Trust Services LLC",
		Country:            "US",
		KeyAlgorithm:       "RSA-4096",
		SignatureAlgorithm: "SHA384-RSA",
	},
}

// BrowserIntermediateCAs provides browser-specific intermediate CA presets
var BrowserIntermediateCAs = map[string]IntermediateCAConfig{
	"chrome": {
		CommonName:         "Google Trust Services",
		Organization:       "Google Trust Services",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
	},
	"firefox": {
		CommonName:         "DigiCert TLS RSA SHA256 2020 CA1",
		Organization:       "DigiCert Inc",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
	},
	"safari": {
		CommonName:         "Apple Public EV Server RSA CA 1",
		Organization:       "Apple Inc.",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
	},
	"edge": {
		CommonName:         "Microsoft RSA TLS CA 01",
		Organization:       "Microsoft Corporation",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
	},
}

// ColesCertificateConfig provides a Coles-specific certificate chain configuration
var ColesCertificateConfig = &CertificateChainConfig{
	Platform: "windows",
	Browser:  "chrome",
	RootCA: RootCAConfig{
		CommonName:         "DigiCert Inc",
		Organization:       "DigiCert Inc",
		OrganizationalUnit: "www.digicert.com",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
		CRLDistributionPoints: []string{
			"http://crl3.digicert.com/DigiCertGlobalRootCA.crl",
		},
		OCSPServers: []string{
			"http://ocsp.digicert.com",
		},
	},
	IntermediateCA: IntermediateCAConfig{
		CommonName:         "Thawte RSA CA 2018",
		Organization:       "DigiCert Inc",
		OrganizationalUnit: "www.digicert.com",
		Country:            "US",
		KeyAlgorithm:       "RSA-2048",
		SignatureAlgorithm: "SHA256-RSA",
	},
	LeafCert: LeafCertConfig{
		CommonName:   "www.coles.com.au",
		Organization: "Coles Supermarkets Australia Pty Ltd",
		Country:      "AU",
		DNSNames:     []string{"www.coles.com.au", "coles.com.au"},
	},
	ValidityPeriod: ValidityConfig{
		Duration: "1y",
	},
}

// GenerateSubject generates pkix.Name from config
func (r *RootCAConfig) GenerateSubject() pkix.Name {
	return pkix.Name{
		CommonName:         r.CommonName,
		Organization:       []string{r.Organization},
		OrganizationalUnit: []string{r.OrganizationalUnit},
		Country:            []string{r.Country},
		Province:           []string{r.State},
		Locality:           []string{r.Locality},
	}
}

// GenerateSubject generates pkix.Name from config
func (i *IntermediateCAConfig) GenerateSubject() pkix.Name {
	return pkix.Name{
		CommonName:         i.CommonName,
		Organization:       []string{i.Organization},
		OrganizationalUnit: []string{i.OrganizationalUnit},
		Country:            []string{i.Country},
	}
}

// GenerateSubject generates pkix.Name from config
func (l *LeafCertConfig) GenerateSubject() pkix.Name {
	return pkix.Name{
		CommonName:   l.CommonName,
		Organization: []string{l.Organization},
		Country:      []string{l.Country},
	}
}

// CertificateGenerator generates certificates matching platform/browser appearance
type CertificateGenerator struct {
	config *CertificateChainConfig
}

// NewCertificateGenerator creates a generator from config
func NewCertificateGenerator(config *CertificateChainConfig) *CertificateGenerator {
	if config == nil {
		config = DefaultCertificateConfig()
	}
	return &CertificateGenerator{config: config}
}

// GenerateForPlatform creates a certificate chain for the specified platform
func (g *CertificateGenerator) GenerateForPlatform(platform string) (*CertificateChain, error) {
	rootConfig, ok := PlatformRootCAs[platform]
	if !ok {
		return nil, fmt.Errorf("unknown platform: %s", platform)
	}

	// Generate root CA
	rootCA, err := g.generateRootCA(&rootConfig)
	if err != nil {
		return nil, fmt.Errorf("generating root CA: %w", err)
	}

	// Generate intermediate (if specified)
	var intermediateCA *Certificate
	if g.config.IntermediateCA.CommonName != "" {
		intermediateCA, err = g.generateIntermediateCA(&g.config.IntermediateCA, rootCA)
		if err != nil {
			return nil, fmt.Errorf("generating intermediate CA: %w", err)
		}
	}

	// Generate leaf certificate
	leafCert, err := g.generateLeafCert(&g.config.LeafCert, intermediateCA, rootCA)
	if err != nil {
		return nil, fmt.Errorf("generating leaf certificate: %w", err)
	}

	return &CertificateChain{
		Root:         rootCA,
		Intermediate: intermediateCA,
		Leaf:         leafCert,
	}, nil
}

// Certificate represents a generated certificate with its key
type Certificate struct {
	Cert       *x509.Certificate
	CertPEM    string
	KeyPEM     string
	PrivateKey interface{}
}

// CertificateChain represents a complete certificate chain
type CertificateChain struct {
	Root         *Certificate
	Intermediate *Certificate
	Leaf         *Certificate
}

// SaveToDirectory saves the certificate chain to PEM files
func (c *CertificateChain) SaveToDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// Save root CA
	if c.Root != nil {
		if err := os.WriteFile(dir+"/root-ca.pem", []byte(c.Root.CertPEM), 0600); err != nil {
			return err
		}
	}

	// Save intermediate
	if c.Intermediate != nil {
		if err := os.WriteFile(dir+"/intermediate.pem", []byte(c.Intermediate.CertPEM), 0600); err != nil {
			return err
		}
	}

	// Save leaf (with key)
	if c.Leaf != nil {
		if err := os.WriteFile(dir+"/cert.pem", []byte(c.Leaf.CertPEM), 0600); err != nil {
			return err
		}
		if err := os.WriteFile(dir+"/key.pem", []byte(c.Leaf.KeyPEM), 0600); err != nil {
			return err
		}
		// Also save chain
		chain := c.Leaf.CertPEM
		if c.Intermediate != nil {
			chain += c.Intermediate.CertPEM
		}
		chain += c.Root.CertPEM
		if err := os.WriteFile(dir+"/chain.pem", []byte(chain), 0600); err != nil {
			return err
		}
	}

	return nil
}

// generateRootCA generates a root CA certificate
func (g *CertificateGenerator) generateRootCA(config *RootCAConfig) (*Certificate, error) {
	// This is a placeholder - actual implementation would generate RSA/ECDSA keys
	// and sign the certificate
	return &Certificate{
		Cert: &x509.Certificate{
			Subject:               config.GenerateSubject(),
			SerialNumber:          big.NewInt(1),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		},
		CertPEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
	}, nil
}

// generateIntermediateCA generates an intermediate CA certificate
func (g *CertificateGenerator) generateIntermediateCA(config *IntermediateCAConfig, _ *Certificate) (*Certificate, error) {
	return &Certificate{
		Cert: &x509.Certificate{
			Subject:               config.GenerateSubject(),
			SerialNumber:          big.NewInt(2),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour), // 5 years
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		},
		CertPEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
	}, nil
}

// generateLeafCert generates a leaf certificate
func (g *CertificateGenerator) generateLeafCert(config *LeafCertConfig, _, _ *Certificate) (*Certificate, error) {
	cert := &x509.Certificate{
		Subject:      config.GenerateSubject(),
		SerialNumber: big.NewInt(3),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		DNSNames:     config.DNSNames,
		IPAddresses:  parseIPAddresses(config.IPAddresses),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	return &Certificate{
		Cert:    cert,
		CertPEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
	}, nil
}

// DefaultCertificateConfig returns a default configuration
func DefaultCertificateConfig() *CertificateChainConfig {
	return &CertificateChainConfig{
		Platform: "windows",
		Browser:  "chrome",
		RootCA:   PlatformRootCAs["windows"],
		LeafCert: LeafCertConfig{
			DNSNames: []string{"localhost"},
		},
		ValidityPeriod: ValidityConfig{
			Duration: "1y",
		},
	}
}

// GetPlatformRootCA returns the root CA config for a platform
func GetPlatformRootCA(platform string) (RootCAConfig, bool) {
	config, ok := PlatformRootCAs[platform]
	return config, ok
}

// ListPlatforms returns available platform options
func ListPlatforms() []string {
	platforms := make([]string, 0, len(PlatformRootCAs))
	for p := range PlatformRootCAs {
		platforms = append(platforms, p)
	}
	return platforms
}

// parseIPAddresses parses IP address strings
func parseIPAddresses(ips []string) []net.IP {
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			result = append(result, parsed)
		}
	}
	return result
}


// pemEncodeCertificate encodes a certificate to PEM
func pemEncodeCertificate(cert *x509.Certificate) string {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(pem)
}


// pemEncodeKey encodes a private key to PEM
func pemEncodeKey(_ interface{}) string {
	// Placeholder - actual implementation would encode the key
	return "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
