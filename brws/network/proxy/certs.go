// Package proxy provides certificate management for MITM proxy
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Platform configs for realistic certificate chains
type platformConfig struct {
	RootCA       pkix.Name
	Intermediate pkix.Name
	Leaf         pkix.Name
	KeyUsage     x509.KeyUsage
}

// Realistic CA configurations to mimic major providers
var platformConfigs = map[string]platformConfig{
	"digicert": {
		RootCA: pkix.Name{
			CommonName:         "DigiCert Global Root CA",
			Organization:       []string{"DigiCert Inc"},
			OrganizationalUnit: []string{"www.digicert.com"},
			Country:            []string{"US"},
		},
		Intermediate: pkix.Name{
			CommonName:         "DigiCert TLS RSA SHA256 2020 CA1",
			Organization:       []string{"DigiCert Inc"},
			OrganizationalUnit: []string{"www.digicert.com"},
			Country:            []string{"US"},
		},
		Leaf: pkix.Name{
			Organization: []string{"Cloudflare, Inc."},
			Country:      []string{"US"},
		},
	},
	"letsencrypt": {
		RootCA: pkix.Name{
			CommonName:   "ISRG Root X1",
			Organization: []string{"Internet Security Research Group"},
			Country:      []string{"US"},
		},
		Intermediate: pkix.Name{
			CommonName:   "R3",
			Organization: []string{"Let's Encrypt"},
			Country:      []string{"US"},
		},
		Leaf: pkix.Name{
			Organization: []string{},
		},
	},
	"google": {
		RootCA: pkix.Name{
			CommonName:   "GTS Root R1",
			Organization: []string{"Google Trust Services LLC"},
			Country:      []string{"US"},
		},
		Intermediate: pkix.Name{
			CommonName:   "GTS CA 1C3",
			Organization: []string{"Google Trust Services LLC"},
			Country:      []string{"US"},
		},
		Leaf: pkix.Name{
			Organization: []string{"Google LLC"},
		},
	},
	"amazon": {
		RootCA: pkix.Name{
			CommonName:   "Amazon Root CA 1",
			Organization: []string{"Amazon"},
			Country:      []string{"US"},
		},
		Intermediate: pkix.Name{
			CommonName:   "Amazon RSA 2048 M02",
			Organization: []string{"Amazon"},
			Country:      []string{"US"},
		},
		Leaf: pkix.Name{
			Organization: []string{"Amazon.com, Inc."},
		},
	},
}

// sanitizePath validates and cleans a file path to prevent directory traversal
func sanitizePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid path contains directory traversal: %s", path)
	}
	return cleanPath, nil
}

// CertificateManager manages CA and generates per-host certificates
type CertificateManager struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	interCert *x509.Certificate
	interKey  *rsa.PrivateKey
	certCache map[string]*tls.Certificate
	mu        sync.RWMutex
	platform  string
}

// NewCertificateManager creates a certificate manager
func NewCertificateManager(caCertFile, caKeyFile string) (*CertificateManager, error) {
	cm := &CertificateManager{
		certCache: make(map[string]*tls.Certificate),
		platform:  "digicert", // Default to most common
	}

	// Load or generate CA
	if caCertFile != "" && caKeyFile != "" {
		if err := cm.loadCA(caCertFile, caKeyFile); err != nil {
			return nil, err
		}
	} else {
		if err := cm.generateRealisticCA(); err != nil {
			return nil, err
		}
	}

	return cm, nil
}

// loadCA loads CA certificate and key from files
func (cm *CertificateManager) loadCA(certFile, keyFile string) error {
	safeCertFile, err := sanitizePath(certFile)
	if err != nil {
		return err
	}
	safeKeyFile, err := sanitizePath(keyFile)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(safeCertFile) //nolint:gosec // Path already sanitized above
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(safeKeyFile) //nolint:gosec // Path already sanitized above
	if err != nil {
		return fmt.Errorf("reading CA key: %w", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	// Parse key
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing CA key: %w", err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA key is not RSA")
		}
	}

	cm.caCert = cert
	cm.caKey = key

	// Generate intermediate for realistic chain
	if err := cm.generateIntermediate(); err != nil {
		return fmt.Errorf("generating intermediate: %w", err)
	}

	return nil
}

// generateRealisticCA generates a CA that mimics real certificate authorities
func (cm *CertificateManager) generateRealisticCA() error {
	config := platformConfigs[cm.platform]

	// Generate root CA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               config.RootCA,
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour), // Backdated for realism
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	cm.caCert = cert
	cm.caKey = key

	// Generate intermediate CA for realistic chain
	if err := cm.generateIntermediate(); err != nil {
		return fmt.Errorf("generating intermediate: %w", err)
	}

	return nil
}

// generateIntermediate creates an intermediate CA certificate
func (cm *CertificateManager) generateIntermediate() error {
	config := platformConfigs[cm.platform]

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating intermediate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               config.Intermediate,
		NotBefore:             time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &key.PublicKey, cm.caKey)
	if err != nil {
		return fmt.Errorf("creating intermediate cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing intermediate cert: %w", err)
	}

	cm.interCert = cert
	cm.interKey = key

	return nil
}

// GetCertificate gets or generates a certificate for a host
func (cm *CertificateManager) GetCertificate(host string) (*tls.Certificate, error) {
	// Check cache first
	cm.mu.RLock()
	if cert, ok := cm.certCache[host]; ok {
		cm.mu.RUnlock()
		return cert, nil
	}
	cm.mu.RUnlock()

	// Generate new certificate
	cert, err := cm.generateHostCertificate(host)
	if err != nil {
		return nil, err
	}

	// Cache it
	cm.mu.Lock()
	cm.certCache[host] = cert
	cm.mu.Unlock()

	return cert, nil
}

// generateHostCertificate generates a leaf certificate for a host
func (cm *CertificateManager) generateHostCertificate(host string) (*tls.Certificate, error) {
	config := platformConfigs[cm.platform]

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating host key: %w", err)
	}

	// Determine if host is IP or DNS name
	ips := []net.IP{}
	dnsNames := []string{}

	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		dnsNames = append(dnsNames, host)
		// Add www variant if not already present
		if host[:4] != "www." {
			dnsNames = append(dnsNames, "www."+host)
		}
		// Add wildcard
		dnsNames = append(dnsNames, "*."+host)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	// Create realistic leaf subject
	subject := config.Leaf
	subject.CommonName = host

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour), // 90 days like Let's Encrypt
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}

	// Sign with intermediate, not root
	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.interCert, &key.PublicKey, cm.interKey)
	if err != nil {
		return nil, fmt.Errorf("creating host cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, cm.interCert.Raw, cm.caCert.Raw},
		PrivateKey:  key,
	}, nil
}

// SaveCA saves the CA certificate and key to files
func (cm *CertificateManager) SaveCA(certFile, keyFile string) error {
	safeCertFile, err := sanitizePath(certFile)
	if err != nil {
		return err
	}
	safeKeyFile, err := sanitizePath(keyFile)
	if err != nil {
		return err
	}
	// Save certificate
	certOut, err := os.Create(safeCertFile) //nolint:gosec // Path already sanitized above
	if err != nil {
		return fmt.Errorf("creating cert file: %w", err)
	}
	defer func() { _ = certOut.Close() }()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}); err != nil {
		return fmt.Errorf("encoding cert: %w", err)
	}

	// Save key
	keyOut, err := os.Create(safeKeyFile) //nolint:gosec // Path already sanitized above
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer func() { _ = keyOut.Close() }()

	keyBytes := x509.MarshalPKCS1PrivateKey(cm.caKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("encoding key: %w", err)
	}

	return nil
}

// GetCACertPEM returns the CA certificate in PEM format
func (cm *CertificateManager) GetCACertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}))
}

// GetCACert returns the CA certificate
func (cm *CertificateManager) GetCACert() *x509.Certificate {
	return cm.caCert
}
