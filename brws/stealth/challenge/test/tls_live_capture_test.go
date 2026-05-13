package challenge_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/fingerprint/lab"
	"github.com/skunkworq/stealth/brws/fingerprint/tls/parser"
	"github.com/skunkworq/stealth/brws/core/types"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// TestTLS_LiveCapture_GoDefault captures Go's default TLS fingerprint and
// verifies the shield detects it.
func TestTLS_LiveCapture_GoDefault(t *testing.T) {
	captured := make(chan *tlsparser.ClientHello, 1)

	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	captureLn := &lab.CapturingListener{
		Listener: ln,
		OnClientHello: func(ch *tlsparser.ClientHello, _ *types.CompleteFingerprint) {
			select {
			case captured <- ch:
			default:
			}
		},
	}

	tlsLn := tls.NewListener(captureLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
		}),
	}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	addr := ln.Addr().String()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + addr + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case ch := <-captured:
		fp := ch.ToFingerprint()
		t.Logf("Go Default TLS Captured:")
		t.Logf("  Ciphers: %d (GREASE: %d)", len(fp.CipherSuites), len(fp.GREASE))
		t.Logf("  Extensions: %d", len(fp.Extensions))
		t.Logf("  JA3: %s", fp.JA3Hash)
		t.Logf("  JA4: %s", fp.JA4)

		analysis := challenge.AnalyzeTLSDeep(fp, "chrome")
		t.Logf("\n%s", challenge.FormatTLSAnalysis(analysis))

		if !analysis.IsGoTLS {
			// Go TLS fingerprint may vary by version, but should have low match and no GREASE
			if analysis.GREASEScore < 0.9 {
				t.Error("expected no GREASE in Go TLS")
			}
		}
		if analysis.BotScore < 0.50 {
			t.Errorf("expected Go TLS bot score >= 0.50, got %.3f", analysis.BotScore)
		}

		reports := challenge.CompareTLSToBaselines(fp)
		for _, r := range reports {
			t.Logf("  vs %-15s cipher=%.0f%% ext=%.0f%%", r.Baseline, r.CipherSimilarity*100, r.ExtSimilarity*100)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello capture")
	}
}

// TestTLS_LiveCapture_uTLS_Chrome captures uTLS Chrome fingerprint and
// compares it against baselines.
func TestTLS_LiveCapture_uTLS_Chrome(t *testing.T) {
	captured := make(chan *tlsparser.ClientHello, 1)

	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	captureLn := &lab.CapturingListener{
		Listener: ln,
		OnClientHello: func(ch *tlsparser.ClientHello, _ *types.CompleteFingerprint) {
			select {
			case captured <- ch:
			default:
			}
		},
	}

	tlsLn := tls.NewListener(captureLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
		}),
	}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	if err := uConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	reqStr := fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port)
	if _, err := uConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4096)
	_, _ = uConn.Read(buf)
	_ = uConn.Close()

	select {
	case ch := <-captured:
		fp := ch.ToFingerprint()
		t.Logf("uTLS Chrome Captured:")
		t.Logf("  Ciphers: %d (GREASE: %d)", len(fp.CipherSuites), len(fp.GREASE))
		t.Logf("  Extensions: %d", len(fp.Extensions))
		t.Logf("  JA3: %s", fp.JA3Hash)
		t.Logf("  JA4: %s", fp.JA4)

		hasALPS := false
		hasCertCompress := false
		for _, ext := range fp.Extensions {
			if ext.Type == 0x44cd {
				hasALPS = true
			}
			if ext.Type == 0x001b {
				hasCertCompress = true
			}
		}
		t.Logf("  Has ALPS: %v", hasALPS)
		t.Logf("  Has cert_compress: %v", hasCertCompress)

		analysis := challenge.AnalyzeTLSDeep(fp, "chrome")
		t.Logf("\n%s", challenge.FormatTLSAnalysis(analysis))

		if analysis.IsGoTLS {
			t.Error("uTLS Chrome should NOT be detected as Go TLS")
		}

		if analysis.IsUTLS {
			t.Logf("NOTE: uTLS detected — shield can distinguish from real Chrome")
		} else {
			t.Logf("uTLS passes TLS detection (score=%.3f)", analysis.BotScore)
		}

		reports := challenge.CompareTLSToBaselines(fp)
		for _, r := range reports {
			t.Logf("  vs %-15s cipher=%.0f%% ext=%.0f%%", r.Baseline, r.CipherSimilarity*100, r.ExtSimilarity*100)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello capture")
	}
}

// TestTLS_LiveCapture_Comparison runs Go default and uTLS side by side.
func TestTLS_LiveCapture_Comparison(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	captures := make(chan *tlsparser.ClientHello, 10)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	captureLn := &lab.CapturingListener{
		Listener: ln,
		OnClientHello: func(ch *tlsparser.ClientHello, _ *types.CompleteFingerprint) {
			captures <- ch
		},
	}

	tlsLn := tls.NewListener(captureLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
		}),
	}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	addr := ln.Addr().String()
	host, _, _ := net.SplitHostPort(addr)

	// 1. Go default TLS
	goClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := goClient.Get("https://" + addr + "/go")
	if err != nil {
		t.Fatalf("go request: %v", err)
	}
	_ = resp.Body.Close()

	// 2. uTLS Chrome
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, _ = uConn.Write([]byte("GET /utls HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"))
	buf := make([]byte, 4096)
	_, _ = uConn.Read(buf)
	_ = uConn.Close()

	time.Sleep(200 * time.Millisecond)

	var allCaptures []*tlsparser.ClientHello
	for {
		select {
		case c := <-captures:
			allCaptures = append(allCaptures, c)
		default:
			goto done
		}
	}
done:

	if len(allCaptures) < 2 {
		t.Fatalf("expected 2 captures, got %d", len(allCaptures))
	}

	goTLS := allCaptures[0].ToFingerprint()
	utlsTLS := allCaptures[1].ToFingerprint()

	goAnalysis := challenge.AnalyzeTLSDeep(goTLS, "chrome")
	utlsAnalysis := challenge.AnalyzeTLSDeep(utlsTLS, "chrome")

	t.Logf("\n=== TLS FINGERPRINT COMPARISON ===")
	t.Logf("%-20s %-15s %-15s", "", "Go Default", "uTLS Chrome")
	t.Logf("%-20s %-15d %-15d", "Cipher Count", len(goTLS.CipherSuites), len(utlsTLS.CipherSuites))
	t.Logf("%-20s %-15d %-15d", "Extension Count", len(goTLS.Extensions), len(utlsTLS.Extensions))
	t.Logf("%-20s %-15d %-15d", "GREASE Count", len(goTLS.GREASE), len(utlsTLS.GREASE))
	t.Logf("%-20s %-15s %-15s", "JA3", goTLS.JA3Hash[:12]+"…", utlsTLS.JA3Hash[:12]+"…")
	t.Logf("%-20s %-15.3f %-15.3f", "Bot Score", goAnalysis.BotScore, utlsAnalysis.BotScore)
	t.Logf("%-20s %-15v %-15v", "Is Go TLS", goAnalysis.IsGoTLS, utlsAnalysis.IsGoTLS)
	t.Logf("%-20s %-15v %-15v", "Is uTLS", goAnalysis.IsUTLS, utlsAnalysis.IsUTLS)
	t.Logf("%-20s %-15.0f%% %-15.0f%%", "Chrome Match", goAnalysis.MatchScore*100, utlsAnalysis.MatchScore*100)

	if goAnalysis.BotScore < 0.50 {
		t.Errorf("Go default should have high bot score, got %.3f", goAnalysis.BotScore)
	}
	if utlsAnalysis.BotScore > goAnalysis.BotScore {
		t.Errorf("uTLS should have lower bot score than Go default: %.3f > %.3f",
			utlsAnalysis.BotScore, goAnalysis.BotScore)
	}
}
