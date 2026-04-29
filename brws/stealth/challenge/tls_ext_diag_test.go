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

func TestTLS_ExtensionOrderDiag(t *testing.T) {
	captured := make(chan *tlsparser.ClientHello, 1)
	cert := mustGenCert(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	captureLn := &lab.CapturingListener{
		Listener: ln,
		OnClientHello: func(ch *tlsparser.ClientHello, _ *types.CompleteFingerprint) {
			select {
			case captured <- ch:
			default:
			}
		},
	}
	tlsLn := tls.NewListener(captureLn, &tls.Config{Certificates: []tls.Certificate{cert}})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)

	conn, _ := net.Dial("tcp", addr)
	uConn := utls.UClient(conn, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	_ = uConn.Handshake()
	_, _ = uConn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port)))
	buf := make([]byte, 4096)
	_, _ = uConn.Read(buf)
	_ = uConn.Close()

	ch := <-captured
	fp := ch.ToFingerprint()

	baseline := challenge.Chrome146Baseline()

	t.Logf("=== uTLS Extension Order ===")
	for i, ext := range fp.Extensions {
		grease := ""
		if ext.IsGREASE {
			grease = " [GREASE]"
		}
		t.Logf("  %2d: 0x%04x %-40s%s", i+1, ext.Type, ext.Name, grease)
	}

	t.Logf("\n=== Chrome 146 Baseline Extension Order ===")
	for i, ext := range baseline.ExtensionOrder {
		t.Logf("  %2d: 0x%04x", i+1, ext)
	}

	// Find what's different
	utlsExts := make([]uint16, 0)
	for _, e := range fp.Extensions {
		if !e.IsGREASE {
			utlsExts = append(utlsExts, e.Type)
		}
	}

	t.Logf("\n=== Non-GREASE Extension Comparison ===")
	t.Logf("uTLS count: %d, Chrome baseline count: %d", len(utlsExts), len(baseline.ExtensionOrder))

	utlsSet := make(map[uint16]bool)
	for _, e := range utlsExts {
		utlsSet[e] = true
	}
	blSet := make(map[uint16]bool)
	for _, e := range baseline.ExtensionOrder {
		blSet[e] = true
	}

	for _, e := range baseline.ExtensionOrder {
		if !utlsSet[e] {
			t.Logf("  MISSING in uTLS: 0x%04x", e)
		}
	}
	for _, e := range utlsExts {
		if !blSet[e] {
			t.Logf("  EXTRA in uTLS: 0x%04x", e)
		}
	}
}

func mustGenCert(t *testing.T) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	c, _ := tls.X509KeyPair(certPEM, keyPEM)
	return c
}
