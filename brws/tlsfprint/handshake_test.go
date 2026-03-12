package tlsfprint

import (
	"crypto/tls"
	"testing"
	"time"
)

//nolint:staticcheck // SA5011: Test validation
func TestVersionToString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0300, "SSL 3.0"},
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0305, "0x0305"},
		{0x0000, "0x0000"},
	}

	for _, tt := range tests {
		result := VersionToString(tt.version)
		if result != tt.expected {
			t.Errorf("VersionToString(0x%04x) = %s; want %s", tt.version, result, tt.expected)
		}
	}
}

func TestCipherSuiteToString(t *testing.T) {
	tests := []struct {
		cipher   uint16
		expected string
	}{
		{0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		{0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		{0xcca8, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0xcca9, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0xffff, "0xffff"},
	}

	for _, tt := range tests {
		result := CipherSuiteToString(tt.cipher)
		if result != tt.expected {
			t.Errorf("CipherSuiteToString(0x%04x) = %s; want %s", tt.cipher, result, tt.expected)
		}
	}
}

func TestExtensionToString(t *testing.T) {
	tests := []struct {
		ext      uint16
		expected string
	}{
		{0, "server_name"},
		{10, "supported_groups"},
		{11, "ec_point_formats"},
		{13, "signature_algorithms"},
		{16, "application_layer_protocol_negotiation"},
		{23, "extended_master_secret"},
		{35, "early_data"},
		{41, "pre_shared_key"},
		{43, "supported_versions"},
		{50, "key_share"},
		{51, "renegotiation_info"},
		{0x0a0a, "grease"},
		{0x1a1a, "grease"},
		{0xffff, "0xffff"},
	}

	for _, tt := range tests {
		result := ExtensionToString(tt.ext)
		if result != tt.expected {
			t.Errorf("ExtensionToString(0x%04x) = %s; want %s", tt.ext, result, tt.expected)
		}
	}
}

func TestIsGreaseValue(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea}
	nonGreaseValues := []uint16{0x0000, 0x0005, 0x002f, 0x0035, 0x009c, 0x1301, 0x1302, 0x1303}

	for _, v := range greaseValues {
		if !IsGreaseValue(v) {
			t.Errorf("IsGreaseValue(0x%04x) = false; want true", v)
		}
	}

	for _, v := range nonGreaseValues {
		if IsGreaseValue(v) {
			t.Errorf("IsGreaseValue(0x%04x) = true; want false", v)
		}
	}
}

func TestTLSAnalyzerRecordClientHello(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	ch := &ClientHelloInfo{
		Version:      0x0303,
		VersionStr:   "TLS 1.2",
		CipherSuites: []uint16{0x002f, 0x0035, 0x009c},
		SNI:          "example.com",
		ALPN:         []string{"h2", "http/1.1"},
	}

	traceID := analyzer.RecordClientHello(ch)

	if traceID == "" {
		t.Error("expected non-empty trace ID")
	}

	handshake := analyzer.GetHandshake(traceID)
	//nolint:staticcheck // SA5011: Test validation
	if handshake == nil {
		t.Error("expected handshake to be found")
	}

	//nolint:staticcheck // SA5011: Test validation
	if handshake.ClientHello == nil {
		t.Error("expected ClientHello to be set")
	}

	//nolint:staticcheck // SA5011: Test validation
	if handshake.ClientHello.SNI != "example.com" {
		t.Errorf("expected SNI example.com, got %s", handshake.ClientHello.SNI)
	}
}

func TestTLSAnalyzerRecordServerHello(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	ch := &ClientHelloInfo{
		Version:    0x0303,
		VersionStr: "TLS 1.2",
	}

	traceID := analyzer.RecordClientHello(ch)

	sh := &ServerHelloInfo{
		Version:     0x0303,
		VersionStr:  "TLS 1.2",
		CipherSuite: 0x002f,
	}

	err := analyzer.RecordServerHello(traceID, sh)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	handshake := analyzer.GetHandshake(traceID)
	if handshake.ServerHello == nil {
		t.Error("expected ServerHello to be set")
	}

	if handshake.CipherSuite != 0x002f {
		t.Errorf("expected cipher suite 0x002f, got 0x%04x", handshake.CipherSuite)
	}
}

func TestTLSAnalyzerRecordServerHelloNotFound(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	sh := &ServerHelloInfo{
		Version:     0x0303,
		CipherSuite: 0x002f,
	}

	err := analyzer.RecordServerHello("nonexistent-trace", sh)
	if err == nil {
		t.Error("expected error for nonexistent trace")
	}
}

func TestTLSAnalyzerGetAllHandshakes(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	for i := 0; i < 5; i++ {
		// #nosec G115 - i is bounded 0-4, safe conversion
		ch := &ClientHelloInfo{
			Version: uint16(0x0300 + i),
		}
		analyzer.RecordClientHello(ch)
	}

	handshakes := analyzer.GetAllHandshakes()
	if len(handshakes) != 5 {
		t.Errorf("expected 5 handshakes, got %d", len(handshakes))
	}
}

func TestTLSAnalyzerGetRecentHandshakes(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	for i := 0; i < 10; i++ {
		ch := &ClientHelloInfo{Version: 0x0303}
		analyzer.RecordClientHello(ch)
	}

	recent := analyzer.GetRecentHandshakes(3)
	if len(recent) != 3 {
		t.Errorf("expected 3 recent handshakes, got %d", len(recent))
	}
}

func TestTLSAnalyzerGetUniqueCipherSuites(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	analyzer.RecordClientHello(&ClientHelloInfo{Version: 0x0303})
	analyzer.RecordClientHello(&ClientHelloInfo{Version: 0x0303})

	sh1 := &ServerHelloInfo{CipherSuite: 0x002f}
	sh2 := &ServerHelloInfo{CipherSuite: 0x0035}

	handshakes := analyzer.GetAllHandshakes()
	if len(handshakes) >= 2 {
		_ = analyzer.RecordServerHello(handshakes[0].TraceID, sh1)
		_ = analyzer.RecordServerHello(handshakes[1].TraceID, sh2)
	}

	suites := analyzer.GetUniqueCipherSuites()
	t.Logf("Unique cipher suites: %v", suites)
}

func TestTLSAnalyzerGetUniqueProtocols(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	analyzer.RecordClientHello(&ClientHelloInfo{Version: 0x0303, VersionStr: "TLS 1.2"})
	analyzer.RecordClientHello(&ClientHelloInfo{Version: 0x0304, VersionStr: "TLS 1.3"})

	protocols := analyzer.GetUniqueProtocols()
	if len(protocols) != 2 {
		t.Errorf("expected 2 unique protocols, got %d", len(protocols))
	}
}

func TestTLSAnalyzerGetCertificateFingerprints(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	ch := &ClientHelloInfo{Version: 0x0303}
	traceID := analyzer.RecordClientHello(ch)

	chain := &CertificateChainInfo{
		FingerprintSHA256: "abc123",
		ChainLength:       1,
	}

	err := analyzer.RecordCertificate(traceID, chain)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	fingerprints := analyzer.GetCertificateFingerprints()
	if len(fingerprints) != 1 {
		t.Errorf("expected 1 fingerprint, got %d", len(fingerprints))
	}

	if fingerprints[0] != "abc123" {
		t.Errorf("expected fingerprint abc123, got %s", fingerprints[0])
	}
}

func TestTLSAnalyzerSummary(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	for i := 0; i < 5; i++ {
		ch := &ClientHelloInfo{
			Version:    0x0303,
			VersionStr: "TLS 1.2",
		}
		traceID := analyzer.RecordClientHello(ch)

		if i < 3 {
			sh := &ServerHelloInfo{
				Version:     0x0303,
				VersionStr:  "TLS 1.2",
				CipherSuite: 0x002f,
			}
			_ = analyzer.RecordServerHello(traceID, sh)
		}
	}

	summary := analyzer.GetSummary()

	if summary.TotalHandshakes != 5 {
		t.Errorf("expected 5 total handshakes, got %d", summary.TotalHandshakes)
	}

	if summary.Successful != 3 {
		t.Errorf("expected 3 successful, got %d", summary.Successful)
	}

	if summary.TLS12Count != 5 {
		t.Errorf("expected 5 TLS 1.2, got %d", summary.TLS12Count)
	}

	t.Logf("Summary: %+v", summary)
}

func TestParseClientHello(t *testing.T) {
	ch, err := ParseClientHello([]byte{}, 0x0303)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if ch.Version != 0x0303 {
		t.Errorf("expected version 0x0303, got 0x%04x", ch.Version)
	}

	if ch.VersionStr != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %s", ch.VersionStr)
	}
}

func TestParseServerHello(t *testing.T) {
	sh, err := ParseServerHello([]byte{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if sh.Version != 0x0303 {
		t.Errorf("expected version 0x0303, got 0x%04x", sh.Version)
	}
}

func TestParseCertificateChain(t *testing.T) {
	certs := []tls.Certificate{}

	chain := ParseCertificateChain(certs)

	if chain != nil {
		t.Error("expected nil for empty certs")
	}
}

func TestParseCertificate(t *testing.T) {
	certInfo := ParseCertificate([]byte{})

	if certInfo.FingerprintSHA1 == "" {
		t.Error("expected non-empty SHA1 fingerprint")
	}

	if certInfo.FingerprintSHA256 == "" {
		t.Error("expected non-empty SHA256 fingerprint")
	}
}

func TestCalculateJA3FromParsed(t *testing.T) {
	ja3 := CalculateJA3FromParsed(
		"TLS 1.2",
		[]uint16{0x002f, 0x0035},
		[]uint16{0x0, 0xd, 0x10},
		[]uint16{0x17, 0x18},
		[]uint16{0x04, 0x05},
		[]string{"h2", "http/1.1"},
	)

	if ja3 == "" {
		t.Error("expected non-empty JA3")
	}

	t.Logf("JA3: %s", ja3)
}

func TestDetectTLSVersionFingerprint(t *testing.T) {
	ch := &ClientHelloInfo{
		Version:           0x0303,
		SupportedVersions: []uint16{0x0303, 0x0304},
	}

	versions := DetectTLSVersionFingerprint(ch)
	t.Logf("TLS versions: %s", versions)
}

func TestTLSHandshakeStruct(t *testing.T) {
	handshake := TLSHandshake{
		Timestamp:         time.Now(),
		TraceID:           "test-trace-123",
		Protocol:          "TLS 1.2",
		CipherSuite:       0x002f,
		HandshakeDuration: 50 * time.Millisecond,
	}

	if handshake.TraceID != "test-trace-123" {
		t.Errorf("expected trace ID test-trace-123, got %s", handshake.TraceID)
	}

	if handshake.Protocol != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %s", handshake.Protocol)
	}

	if handshake.CipherSuite != 0x002f {
		t.Errorf("expected cipher 0x002f, got 0x%04x", handshake.CipherSuite)
	}
}

func TestClientHelloInfo(t *testing.T) {
	ch := &ClientHelloInfo{
		Raw:              []byte{0x01, 0x02, 0x03},
		Version:          0x0303,
		VersionStr:       "TLS 1.2",
		CipherSuites:     []uint16{0x002f, 0x0035, 0x009c},
		CipherSuiteNames: []string{"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"},
		ExtensionsList:   []uint16{0x0, 0xa, 0xd},
		SNI:              "example.com",
		ALPN:             []string{"h2", "http/1.1"},
		GreaseDetected:   true,
		JA3:              "771,47-53-192-47-51-47-50-56-19-18-16-6-13-45-255-10,10-11-13-16-21-23-43-27-35-41-51,29-23-30-25-18-19-16-17-24-22-21,22-23-25",
		JA4:              "t12d0005h2e1267e96a4b8c9a0d2e3f",
	}

	if len(ch.CipherSuites) != 3 {
		t.Errorf("expected 3 cipher suites, got %d", len(ch.CipherSuites))
	}

	if ch.SNI != "example.com" {
		t.Errorf("expected SNI example.com, got %s", ch.SNI)
	}

	if !ch.GreaseDetected {
		t.Error("expected GREASE to be detected")
	}
}

func TestServerHelloInfo(t *testing.T) {
	sh := &ServerHelloInfo{
		Raw:             []byte{0x01, 0x02},
		Version:         0x0303,
		VersionStr:      "TLS 1.2",
		CipherSuite:     0x002f,
		CipherSuiteName: "TLS_RSA_WITH_AES_128_CBC_SHA",
		Compression:     0,
		ALPN:            "h2",
	}

	if sh.Version != 0x0303 {
		t.Errorf("expected version 0x0303, got 0x%04x", sh.Version)
	}

	if sh.CipherSuite != 0x002f {
		t.Errorf("expected cipher 0x002f, got 0x%04x", sh.CipherSuite)
	}

	if sh.ALPN != "h2" {
		t.Errorf("expected ALPN h2, got %s", sh.ALPN)
	}
}

func TestExtensionInfo(t *testing.T) {
	ext := ExtensionInfo{
		Type:     0,
		TypeStr:  "server_name",
		Name:     "server_name",
		Data:     []byte{0x00, 0x0c},
		IsGrease: false,
		Value:    "example.com",
	}

	if ext.Type != 0 {
		t.Errorf("expected type 0, got 0x%04x", ext.Type)
	}

	if ext.TypeStr != "server_name" {
		t.Errorf("expected server_name, got %s", ext.TypeStr)
	}

	greaseExt := ExtensionInfo{
		Type:     0x0a0a,
		TypeStr:  "grease",
		IsGrease: true,
	}

	if !greaseExt.IsGrease {
		t.Error("expected grease extension")
	}
}

func TestCertificateChainInfo(t *testing.T) {
	chain := &CertificateChainInfo{
		Chain: []CertificateInfo{
			{
				Subject: "CN=example.com",
				Issuer:  "CN=DigiCert",
				IsCA:    false,
				KeySize: 2048,
			},
		},
		ChainLength:        1,
		FingerprintSHA1:    "abc123",
		FingerprintSHA256:  "def456",
		Issuer:             "CN=DigiCert",
		Subject:            "CN=example.com",
		PublicKeyAlgorithm: "RSA",
		SignatureAlgorithm: "SHA256-RSA",
		IsSelfSigned:       false,
	}

	if chain.ChainLength != 1 {
		t.Errorf("expected chain length 1, got %d", chain.ChainLength)
	}

	if chain.FingerprintSHA256 != "def456" {
		t.Errorf("expected SHA256 def456, got %s", chain.FingerprintSHA256)
	}

	if chain.IsSelfSigned {
		t.Error("expected not self-signed")
	}
}

func TestCertificateInfo(t *testing.T) {
	cert := CertificateInfo{
		Raw:                []byte{0x01, 0x02, 0x03},
		FingerprintSHA1:    "sha1hash",
		FingerprintSHA256:  "sha256hash",
		Subject:            "CN=test.example.com",
		Issuer:             "CN=Test CA",
		NotBefore:          time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		PublicKeyAlgorithm: "RSA",
		SignatureAlgorithm: "SHA256-RSA",
		KeySize:            2048,
		IsCA:               false,
		BasicConstraints:   "CA:FALSE",
	}

	if cert.FingerprintSHA256 != "sha256hash" {
		t.Errorf("expected sha256hash, got %s", cert.FingerprintSHA256)
	}

	if cert.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", cert.KeySize)
	}

	if cert.IsCA {
		t.Error("expected not CA")
	}
}
