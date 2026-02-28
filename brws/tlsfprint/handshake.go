// Package tlsfprint provides TLS fingerprinting capabilities.
//nolint:gosec // G505: crypto/sha1 used intentionally for TLS fingerprinting
package tlsfprint

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type TLSHandshake struct {
	Timestamp         time.Time
	TraceID           string
	ClientHello       *ClientHelloInfo
	ServerHello       *ServerHelloInfo
	Certificate       *CertificateChainInfo
	SessionID         string
	Protocol          string
	CipherSuite       uint16
	IsResumed         bool
	HandshakeDuration time.Duration
	Extensions        []ExtensionInfo
	Warnings          []string
	Errors            []string
}

type ClientHelloInfo struct {
	Raw                  []byte
	Version              uint16
	VersionStr           string
	Random               [32]byte
	SessionID            []byte
	CipherSuites         []uint16
	CipherSuiteNames     []string
	CompressionMethods   []uint8
	ExtensionsList       []uint16
	Extensions           []ExtensionInfo
	SupportedVersions    []uint16
	SupportedGroups      []uint16
	SignatureAlgorithms  []uint16
	ALPN                 []string
	SNI                  string
	ECPoints             []uint8
	SupportedVersionsStr string
	GreaseDetected       bool
	JA3                  string
	JA4                  string
}

type ServerHelloInfo struct {
	Raw              []byte
	Version          uint16
	VersionStr       string
	Random           [32]byte
	SessionID        []byte
	CipherSuite      uint16
	CipherSuiteName  string
	Compression      uint8
	ExtensionsList   []uint16
	Extensions       []ExtensionInfo
	ALPN             string
	SupportedVersion string
}

type ExtensionInfo struct {
	Type     uint16
	TypeStr  string
	Name     string
	Data     []byte
	IsGrease bool
	Value    string
}

type CertificateChainInfo struct {
	Chain              []CertificateInfo
	ChainLength        int
	FingerprintSHA1    string
	FingerprintSHA256  string
	Issuer             string
	Subject            string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	KeySize            int
	IsSelfSigned       bool
	ValidationErrors   []string
}

type CertificateInfo struct {
	Raw                []byte
	FingerprintSHA1    string
	FingerprintSHA256  string
	Subject            string
	Issuer             string
	SerialNumber       *big.Int
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	KeySize            int
	IsCA               bool
	BasicConstraints   string
	Extensions         []CertificateExtension
}

type CertificateExtension struct {
	OID      string
	Name     string
	Critical bool
	Value    string
}

func ParseClientHello(raw []byte, version uint16) (*ClientHelloInfo, error) {
	ch := &ClientHelloInfo{
		Raw:        raw,
		Version:    version,
		VersionStr: VersionToString(version),
	}

	ch.JA3 = CalculateJA3FromParsed(
		ch.VersionStr,
		ch.CipherSuites,
		ch.ExtensionsList,
		ch.SupportedGroups,
		ch.SignatureAlgorithms,
		ch.ALPN,
	)

	return ch, nil
}

func ParseServerHello(raw []byte) (*ServerHelloInfo, error) {
	sh := &ServerHelloInfo{
		Raw:        raw,
		Version:    0x0303,
		VersionStr: "TLS 1.2",
	}

	return sh, nil
}

func ParseCertificateChain(certs []tls.Certificate) *CertificateChainInfo {
	if len(certs) == 0 {
		return nil
	}

	chain := &CertificateChainInfo{
		Chain:       make([]CertificateInfo, 0),
		ChainLength: len(certs),
	}

	var allRaw []byte
	for _, cert := range certs {
		allRaw = append(allRaw, cert.Certificate[0]...)
	}

	if len(allRaw) > 0 {
		sha1Hash := sha1.Sum(allRaw)
		chain.FingerprintSHA1 = hex.EncodeToString(sha1Hash[:])
		sha256Hash := sha256.Sum256(allRaw)
		chain.FingerprintSHA256 = hex.EncodeToString(sha256Hash[:])
	}

	for i, cert := range certs {
		if len(cert.Certificate) == 0 {
			continue
		}

		certInfo := ParseCertificate(cert.Certificate[0])
		chain.Chain = append(chain.Chain, certInfo)

		if i == 0 {
			chain.Issuer = certInfo.Issuer
			chain.Subject = certInfo.Subject
			chain.NotBefore = certInfo.NotBefore
			chain.NotAfter = certInfo.NotAfter
			chain.PublicKeyAlgorithm = certInfo.PublicKeyAlgorithm
			chain.SignatureAlgorithm = certInfo.SignatureAlgorithm
			chain.KeySize = certInfo.KeySize

			if certInfo.Subject == certInfo.Issuer {
				chain.IsSelfSigned = true
			}
		}
	}

	return chain
}

func ParseCertificate(derBytes []byte) CertificateInfo {
	certInfo := CertificateInfo{
		Raw: derBytes,
	}

	sha1Hash := sha1.Sum(derBytes)
	certInfo.FingerprintSHA1 = hex.EncodeToString(sha1Hash[:])
	sha256Hash := sha256.Sum256(derBytes)
	certInfo.FingerprintSHA256 = hex.EncodeToString(sha256Hash[:])

	return certInfo
}

type TLSAnalyzer struct {
	handshakes []TLSHandshake
	traceIDGen *traceIDGenerator
}

func NewTLSAnalyzer() *TLSAnalyzer {
	return &TLSAnalyzer{
		handshakes: make([]TLSHandshake, 0),
		traceIDGen: newTraceIDGenerator(),
	}
}

func (a *TLSAnalyzer) RecordClientHello(info *ClientHelloInfo) string {
	traceID := a.traceIDGen.Next()
	handshake := TLSHandshake{
		Timestamp:   time.Now(),
		TraceID:     traceID,
		ClientHello: info,
		Protocol:    info.VersionStr,
		CipherSuite: 0,
	}

	a.handshakes = append(a.handshakes, handshake)
	return traceID
}

func (a *TLSAnalyzer) RecordServerHello(traceID string, info *ServerHelloInfo) error {
	for i := range a.handshakes {
		if a.handshakes[i].TraceID == traceID {
			a.handshakes[i].ServerHello = info
			a.handshakes[i].CipherSuite = info.CipherSuite
			a.handshakes[i].Protocol = info.VersionStr
			return nil
		}
	}
	return fmt.Errorf("trace not found: %s", traceID)
}

func (a *TLSAnalyzer) RecordCertificate(traceID string, chain *CertificateChainInfo) error {
	for i := range a.handshakes {
		if a.handshakes[i].TraceID == traceID {
			a.handshakes[i].Certificate = chain
			return nil
		}
	}
	return fmt.Errorf("trace not found: %s", traceID)
}

func (a *TLSAnalyzer) GetHandshake(traceID string) *TLSHandshake {
	for _, h := range a.handshakes {
		if h.TraceID == traceID {
			return &h
		}
	}
	return nil
}

func (a *TLSAnalyzer) GetAllHandshakes() []TLSHandshake {
	return a.handshakes
}

func (a *TLSAnalyzer) GetRecentHandshakes(count int) []TLSHandshake {
	if count > len(a.handshakes) {
		count = len(a.handshakes)
	}
	return a.handshakes[len(a.handshakes)-count:]
}

func (a *TLSAnalyzer) GetUniqueCipherSuites() map[uint16]int {
	suites := make(map[uint16]int)
	for _, h := range a.handshakes {
		if h.CipherSuite != 0 {
			suites[h.CipherSuite]++
		}
	}
	return suites
}

func (a *TLSAnalyzer) GetUniqueProtocols() map[string]int {
	protocols := make(map[string]int)
	for _, h := range a.handshakes {
		if h.Protocol != "" {
			protocols[h.Protocol]++
		}
	}
	return protocols
}

func (a *TLSAnalyzer) GetCertificateFingerprints() []string {
	fingerprints := make([]string, 0)
	seen := make(map[string]bool)
	for _, h := range a.handshakes {
		if h.Certificate != nil && h.Certificate.FingerprintSHA256 != "" {
			if !seen[h.Certificate.FingerprintSHA256] {
				fingerprints = append(fingerprints, h.Certificate.FingerprintSHA256)
				seen[h.Certificate.FingerprintSHA256] = true
			}
		}
	}
	return fingerprints
}

func VersionToString(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func CipherSuiteToString(suite uint16) string {
	switch suite {
	case 0x0005:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case 0x000a:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x002f:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0x003c:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x009c:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009d:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case 0xc007:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case 0xc009:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case 0xc00a:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case 0xc011:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case 0xc012:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0xc013:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case 0xc014:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case 0xc023:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case 0xc024:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	case 0xc027:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case 0xc028:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case 0xcca8:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xcca9:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xccaa:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0x1304:
		return "TLS_AES_128_CCM_SHA256"
	case 0x1305:
		return "TLS_AES_128_CCM_8_SHA256"
	default:
		return fmt.Sprintf("0x%04x", suite)
	}
}

func ExtensionToString(extType uint16) string {
	switch extType {
	case 0:
		return "server_name"
	case 1:
		return "max_fragment_length"
	case 2:
		return "client_certificate_url"
	case 3:
		return "trusted_ca_keys"
	case 4:
		return "truncated_hmac"
	case 5:
		return "status_request"
	case 6:
		return "user_mapping"
	case 7:
		return "client_authz"
	case 8:
		return "server_authz"
	case 9:
		return "cert_type"
	case 10:
		return "supported_groups"
	case 11:
		return "ec_point_formats"
	case 13:
		return "signature_algorithms"
	case 16:
		return "application_layer_protocol_negotiation"
	case 17:
		return "status_request_v2"
	case 21:
		return "padding"
	case 23:
		return "extended_master_secret"
	case 27:
		return "compress_certificate"
	case 28:
		return "record_size_limit"
	case 29:
		return "password_secret"
	case 33:
		return "delegated_credentials"
	case 34:
		return "max_early_data_size"
	case 35:
		return "early_data"
	case 41:
		return "pre_shared_key"
	case 42:
		return "early_data_indication"
	case 43:
		return "supported_versions"
	case 44:
		return "cookie"
	case 45:
		return "psk_key_exchange_modes"
	case 46:
		return "certificate_authorities"
	case 47:
		return "oid_filters"
	case 48:
		return "post_handshake_auth"
	case 49:
		return "signature_algorithms_cert"
	case 50:
		return "key_share"
	case 51:
		return "renegotiation_info"
	case 0x0a0a:
		return "grease"
	case 0x1a1a:
		return "grease"
	case 0x2a2a:
		return "grease"
	case 0x3a3a:
		return "grease"
	case 0x4a4a:
		return "grease"
	case 0x5a5a:
		return "grease"
	case 0x6a6a:
		return "grease"
	case 0x7a7a:
		return "grease"
	case 0x8a8a:
		return "grease"
	case 0x9a9a:
		return "grease"
	case 0xaaaa:
		return "grease"
	case 0xbaba:
		return "grease"
	case 0xcaca:
		return "grease"
	case 0xdada:
		return "grease"
	case 0xeaea:
		return "grease"
	default:
		return fmt.Sprintf("0x%04x", extType)
	}
}

func IsGreaseValue(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a
}

func DetectTLSVersionFingerprint(clientHello *ClientHelloInfo) string {
	versions := clientHello.SupportedVersions
	if len(versions) == 0 {
		return clientHello.VersionStr
	}

	var versionsStr []string
	for _, v := range versions {
		versionsStr = append(versionsStr, VersionToString(v))
	}
	return strings.Join(versionsStr, ", ")
}

func CalculateJA3FromParsed(version string, ciphers []uint16, exts []uint16, groups []uint16, sigs []uint16, alpn []string) string {
	var parts []string

	parts = append(parts, version)

	var cipherStrs []string
	for _, c := range ciphers {
		cipherStrs = append(cipherStrs, fmt.Sprintf("%d", c))
	}
	parts = append(parts, strings.Join(cipherStrs, "-"))

	var extStrs []string
	for _, e := range exts {
		extStrs = append(extStrs, fmt.Sprintf("%d", e))
	}
	parts = append(parts, strings.Join(extStrs, "-"))

	if len(groups) > 0 {
		var groupStrs []string
		for _, g := range groups {
			groupStrs = append(groupStrs, fmt.Sprintf("%d", g))
		}
		parts = append(parts, strings.Join(groupStrs, "-"))
	} else {
		parts = append(parts, "")
	}

	if len(sigs) > 0 {
		var sigStrs []string
		for _, s := range sigs {
			sigStrs = append(sigStrs, fmt.Sprintf("%d", s))
		}
		parts = append(parts, strings.Join(sigStrs, "-"))
	} else {
		parts = append(parts, "")
	}

	if len(alpn) > 0 {
		parts = append(parts, strings.Join(alpn, ","))
	} else {
		parts = append(parts, "")
	}

	return strings.Join(parts, ",")
}

type traceIDGenerator struct {
	counter int
}

func newTraceIDGenerator() *traceIDGenerator {
	return &traceIDGenerator{counter: 0}
}

func (g *traceIDGenerator) Next() string {
	g.counter++
	return fmt.Sprintf("%016x-%d", time.Now().UnixNano(), g.counter)
}

type TLSHandshakeSummary struct {
	TotalHandshakes    int
	Successful         int
	Failed             int
	UniqueCiphers      int
	UniqueProtocols    int
	UniqueCertificates int
	MostCommonCipher   uint16
	MostCommonProtocol string
	TLS12Count         int
	TLS13Count         int
	ResumedCount       int
}

func (a *TLSAnalyzer) GetSummary() TLSHandshakeSummary {
	summary := TLSHandshakeSummary{
		TotalHandshakes: len(a.handshakes),
	}

	ciphers := a.GetUniqueCipherSuites()
	summary.UniqueCiphers = len(ciphers)

	protocols := a.GetUniqueProtocols()
	summary.UniqueProtocols = len(protocols)

	certs := a.GetCertificateFingerprints()
	summary.UniqueCertificates = len(certs)

	var maxCipherCount int
	var maxProtocolCount int
	for cipher, count := range ciphers {
		if count > maxCipherCount {
			maxCipherCount = count
			summary.MostCommonCipher = cipher
		}
	}
	for protocol, count := range protocols {
		if count > maxProtocolCount {
			maxProtocolCount = count
			summary.MostCommonProtocol = protocol
		}
		switch protocol {
		case "TLS 1.2":
			summary.TLS12Count = count
		case "TLS 1.3":
			summary.TLS13Count = count
		}
	}

	for _, h := range a.handshakes {
		if h.CipherSuite != 0 {
			summary.Successful++
		}
		if h.IsResumed {
			summary.ResumedCount++
		}
	}

	return summary
}
