package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mustGenCert generates a self-signed ECDSA P-256 certificate valid for
// 127.0.0.1 and localhost, suitable for use in hermetic TLS test servers.
func mustGenCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// startTLSServer starts a TLS server with precise version and cipher control.
// cfg.Certificates must be set before calling; use mustGenCert to generate one.
// The server is registered for cleanup on t and returned so callers can get its address.
func startTLSServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

// TestClassifyCipher verifies the cipher metadata table for known and unknown IDs.
func TestClassifyCipher(t *testing.T) {
	// RC4 (0x0005) → insecure, no forward secrecy.
	rc4 := ClassifyCipher(0x0005)
	if rc4.Strength != StrengthInsecure {
		t.Errorf("0x0005: want strength=%q, got %q", StrengthInsecure, rc4.Strength)
	}
	if rc4.ForwardSecrecy {
		t.Error("0x0005: want ForwardSecrecy=false, got true")
	}

	// ECDHE-RSA-AES128-GCM-SHA256 (0xc02f) → recommended, forward secrecy.
	ecdhe := ClassifyCipher(0xc02f)
	if ecdhe.Strength != StrengthRecommended {
		t.Errorf("0xc02f: want strength=%q, got %q", StrengthRecommended, ecdhe.Strength)
	}
	if !ecdhe.ForwardSecrecy {
		t.Error("0xc02f: want ForwardSecrecy=true, got false")
	}

	// TLS 1.3 AES-128-GCM (0x1301) → recommended.
	tls13 := ClassifyCipher(0x1301)
	if tls13.Strength != StrengthRecommended {
		t.Errorf("0x1301: want strength=%q, got %q", StrengthRecommended, tls13.Strength)
	}

	// Unknown cipher (0xffff) → non-empty Name, weak strength.
	unknown := ClassifyCipher(0xffff)
	if unknown.Name == "" {
		t.Error("0xffff: want non-empty Name for unknown cipher, got empty string")
	}
	if unknown.Strength != StrengthWeak {
		t.Errorf("0xffff: want strength=%q for unknown cipher, got %q", StrengthWeak, unknown.Strength)
	}
}

// TestEnumerateVersions_TLS12Only starts a TLS 1.2-only server and asserts
// that EnumerateVersions reports TLS 1.2 as supported and TLS 1.3 as not.
func TestEnumerateVersions_TLS12Only(t *testing.T) {
	cert := mustGenCert(t)
	srv := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting addr: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	versions, reachable, err := EnumerateVersions(ctx, host, port)
	if err != nil {
		t.Fatalf("EnumerateVersions: %v", err)
	}

	if !reachable {
		t.Fatal("expected server to be reachable")
	}

	byVersion := make(map[TLSVersion]VersionSupport, len(versions))
	for _, v := range versions {
		byVersion[v.Version] = v
	}

	if !byVersion[VersionTLS12].Supported {
		t.Error("expected TLS 1.2 to be supported, got false")
	}

	if byVersion[VersionTLS13].Supported {
		t.Error("expected TLS 1.3 to be NOT supported (TLS 1.2-only server), got true")
	}

	if byVersion[VersionTLS12].NegotiatedCipher == 0 {
		t.Error("expected non-zero NegotiatedCipher for supported TLS 1.2")
	}
}

// TestEnumerateCiphers_Pinned starts a TLS 1.2 server pinned to one cipher
// and asserts that EnumerateCiphers discovers exactly that cipher.
// We use TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 because mustGenCert produces
// an ECDSA certificate; RSA cipher suites would be rejected with an ECDSA cert.
func TestEnumerateCiphers_Pinned(t *testing.T) {
	const pinnedCipher = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

	cert := mustGenCert(t)
	srv := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{pinnedCipher},
	})

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting addr: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	budget := &Budget{Remaining: 20}

	ciphers, err := EnumerateCiphers(ctx, host, port, VersionTLS12, budget)
	if err != nil {
		t.Fatalf("EnumerateCiphers: %v", err)
	}

	if len(ciphers) != 1 {
		t.Fatalf("expected exactly 1 cipher, got %d: %+v", len(ciphers), ciphers)
	}

	if ciphers[0].ID != uint16(pinnedCipher) {
		t.Errorf("expected cipher ID 0x%04x, got 0x%04x (%s)", pinnedCipher, ciphers[0].ID, ciphers[0].Name)
	}

	if ciphers[0].Name == "" {
		t.Error("expected non-empty cipher name")
	}
}

// TestBuildChain verifies that BuildChain populates CertInfo correctly.
// We construct a CA→leaf chain in-memory and verify both entries.
func TestBuildChain(t *testing.T) {
	// Generate CA key + cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Generate leaf key + cert signed by CA.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Build a fake tls.ConnectionState with leaf-first ordering.
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, caCert},
	}

	chain := BuildChain(state)
	if chain == nil {
		t.Fatal("expected non-nil CertChain, got nil")
	}

	if len(chain.Certs) != 2 {
		t.Fatalf("expected 2 CertInfos, got %d", len(chain.Certs))
	}

	leaf := chain.Certs[0]
	ca := chain.Certs[1]

	if leaf.IsCA {
		t.Error("leaf cert: want IsCA=false, got true")
	}

	if !ca.IsCA {
		t.Error("CA cert: want IsCA=true, got false")
	}

	if leaf.SHA256Fingerprint == "" {
		t.Error("leaf cert: want non-empty SHA256Fingerprint")
	}
}

// TestScan_Unreachable verifies Scan returns Partial=true and no panic
// when the target port is not listening.
func TestScan_Unreachable(t *testing.T) {
	// Grab an ephemeral port then immediately close it so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := ln.Addr().String()
	ln.Close()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting addr: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, _ := Scan(ctx, host, port, Options{
		MaxHandshakes:     5,
		EnumerateVersions: true,
		EnumerateCiphers:  false,
		ScanCertChain:     false,
	})

	if result == nil {
		t.Fatal("expected non-nil result even on unreachable host")
	}

	if !result.Partial {
		t.Error("expected Partial=true for unreachable host, got false")
	}
}
