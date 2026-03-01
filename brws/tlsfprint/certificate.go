package tlsfprint

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
)

type CertificateFingerprint struct {
	SPKIHash           string
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          int64
	NotAfter           int64
	KeyUsage           []string
	ExtKeyUsage        []string
	DNSNames           []string
	IPAddresses        []string
	IsCA               bool
	SignatureAlgorithm string
	PublicKeyAlgorithm string
}

func ParseCertificateFingerprint(certPEM string) (*CertificateFingerprint, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM")
	}

	return ParseCertificateDer(block.Bytes)
}

func ParseCertificateDer(certDER []byte) (*CertificateFingerprint, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateFingerprint{
		SPKIHash:           CalculateSPKIHash(cert),
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore.Unix(),
		NotAfter:           cert.NotAfter.Unix(),
		KeyUsage:           keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageToStrings(cert.ExtKeyUsage),
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipsToStrings(cert.IPAddresses),
		IsCA:               cert.IsCA,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}, nil
}

func CalculateSPKIHash(cert *x509.Certificate) string {
	spki := cert.RawSubjectPublicKeyInfo
	hash := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func CalculateSPKIHashFromDER(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return CalculateSPKIHash(cert), nil
}

func keyUsageToStrings(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "nonRepudiation")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "cRLSign")
	}
	return usages
}

func extKeyUsageToStrings(eku []x509.ExtKeyUsage) []string {
	var usages []string
	//nolint:exhaustive // Only handle common ExtKeyUsage values
	for _, e := range eku {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "timeStamping")
		}
	}
	return usages
}

func ipsToStrings(ips []net.IP) []string {
	var result []string
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result
}

func (f *CertificateFingerprint) ToJA3C() string {
	spki := f.SPKIHash
	if len(spki) > 16 {
		spki = spki[:16]
	}
	serial := f.SerialNumber
	if len(serial) > 8 {
		serial = serial[:8]
	}
	parts := []string{
		spki,
		f.Subject,
		f.Issuer,
		serial,
	}
	return strings.Join(parts, ",")
}

func (f *CertificateFingerprint) IsExpired() bool {
	return f.NotAfter < 0
}

func (f *CertificateFingerprint) Valid() bool {
	now := GetCurrentTimestamp()
	return f.NotBefore <= now && now <= f.NotAfter
}

func GetCurrentTimestamp() int64 {
	return now().Unix()
}

func now() timestampFunc {
	return timestampFunc{}
}

type timestampFunc struct{}

func (timestampFunc) Unix() int64 {
	return currentTime()
}

func currentTime() int64 {
	return 0
}

type CertificateChain struct {
	Chain []CertificateFingerprint
	Depth int
}

func ParsePEMCertificateChain(certsPEM string) (*CertificateChain, error) {
	var chain CertificateChain

	for {
		block, rest := pem.Decode([]byte(certsPEM))
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			fp, err := ParseCertificateDer(block.Bytes)
			if err != nil {
				return nil, err
			}
			chain.Chain = append(chain.Chain, *fp)
		}

		certsPEM = string(rest)
		if len(rest) == 0 {
			break
		}
	}

	chain.Depth = len(chain.Chain)
	return &chain, nil
}

func (c *CertificateChain) GetLeaf() *CertificateFingerprint {
	if len(c.Chain) == 0 {
		return nil
	}
	return &c.Chain[0]
}

func (c *CertificateChain) GetRoot() *CertificateFingerprint {
	if len(c.Chain) == 0 {
		return nil
	}
	return &c.Chain[len(c.Chain)-1]
}

func (c *CertificateChain) GetIntermediate(index int) *CertificateFingerprint {
	if index <= 0 || index >= len(c.Chain)-1 {
		return nil
	}
	return &c.Chain[index]
}

func (c *CertificateChain) IsValid() bool {
	if len(c.Chain) == 0 {
		return false
	}

	for i, cert := range c.Chain {
		if i == len(c.Chain)-1 {
			if !cert.IsCA {
				return false
			}
		}
		if !cert.Valid() {
			return false
		}
	}

	return true
}

func (c *CertificateChain) ToSPKIList() []string {
	var list []string
	for _, cert := range c.Chain {
		spki := cert.SPKIHash
		if len(spki) > 16 {
			spki = spki[:16]
		}
		list = append(list, spki)
	}
	return list
}

type ServerCertificateFingerprint struct {
	CertificateFingerprint
	ServerName  string
	TLSVersion  uint16
	CipherSuite uint16
}

func (f *ServerCertificateFingerprint) ToFingerprintString() string {
	return fmt.Sprintf("%s|%s|%04x|%04x",
		f.SPKIHash[:12],
		f.ServerName,
		f.TLSVersion,
		f.CipherSuite)
}

type ClientCertificateFingerprint struct {
	CertificateFingerprint
	SupportedIssuers []string
}

func (f *ClientCertificateFingerprint) HasCertificate() bool {
	return len(f.SPKIHash) > 0
}

type CertificateComparator struct {
	observed *CertificateFingerprint
	expected *CertificateFingerprint
}

func NewCertificateComparator(observed, expected *CertificateFingerprint) *CertificateComparator {
	return &CertificateComparator{
		observed: observed,
		expected: expected,
	}
}

func (c *CertificateComparator) Compare() bool {
	if c.observed == nil || c.expected == nil {
		return false
	}
	return c.observed.SPKIHash == c.expected.SPKIHash
}

func (c *CertificateComparator) GetDifferences() []string {
	var diffs []string
	if c.observed == nil || c.expected == nil {
		return []string{"nil certificate"}
	}
	if c.observed.SPKIHash != c.expected.SPKIHash {
		diffs = append(diffs, "SPKI hash mismatch")
	}
	if c.observed.Subject != c.expected.Subject {
		diffs = append(diffs, fmt.Sprintf("subject: %s != %s", c.observed.Subject, c.expected.Subject))
	}
	if c.observed.Issuer != c.expected.Issuer {
		diffs = append(diffs, fmt.Sprintf("issuer: %s != %s", c.observed.Issuer, c.expected.Issuer))
	}
	return diffs
}

type CertificateMatcher struct {
	knownSPKIs map[string]string
}

func NewCertificateMatcher() *CertificateMatcher {
	return &CertificateMatcher{
		knownSPKIs: make(map[string]string),
	}
}

func (m *CertificateMatcher) Register(spkiHash, name string) {
	hash := spkiHash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	m.knownSPKIs[hash] = name
}

func (m *CertificateMatcher) Match(cert *CertificateFingerprint) (string, bool) {
	shortHash := cert.SPKIHash
	if len(shortHash) > 16 {
		shortHash = shortHash[:16]
	}
	name, ok := m.knownSPKIs[shortHash]
	return name, ok
}

func (m *CertificateMatcher) MatchFromChain(chain *CertificateChain) (string, bool) {
	leaf := chain.GetLeaf()
	if leaf == nil {
		return "", false
	}
	return m.Match(leaf)
}
