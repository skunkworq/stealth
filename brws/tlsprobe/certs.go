package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"time"
)

// CertInfo holds parsed information about a single X.509 certificate.
type CertInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	SHA256Fingerprint  string
	IsCA               bool
	IsValid            bool
}

// CertChain holds the full certificate chain extracted from a TLS connection.
type CertChain struct {
	Certs       []CertInfo
	Verified    bool
	OCSPStapled bool
}

// BuildChain converts the certificates from a tls.ConnectionState into a
// CertChain. The peer certificate slice is leaf-first, matching TLS wire order.
// Returns nil if state is nil or has no peer certificates.
func BuildChain(state *tls.ConnectionState) *CertChain {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}

	chain := &CertChain{
		Verified:    len(state.VerifiedChains) > 0,
		OCSPStapled: len(state.OCSPResponse) > 0,
		Certs:       make([]CertInfo, 0, len(state.PeerCertificates)),
	}

	now := time.Now()
	for _, c := range state.PeerCertificates {
		fp := sha256.Sum256(c.Raw)
		info := CertInfo{
			Subject:            c.Subject.String(),
			Issuer:             c.Issuer.String(),
			SerialNumber:       c.SerialNumber.String(),
			NotBefore:          c.NotBefore,
			NotAfter:           c.NotAfter,
			DNSNames:           c.DNSNames,
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
			PublicKeyBits:      publicKeyBits(c.PublicKey),
			SHA256Fingerprint:  hex.EncodeToString(fp[:]),
			IsCA:               c.IsCA,
			IsValid:            now.After(c.NotBefore) && now.Before(c.NotAfter),
		}
		chain.Certs = append(chain.Certs, info)
	}

	return chain
}

// publicKeyBits returns the key size in bits for RSA and ECDSA public keys.
// Returns 0 for unsupported key types.
func publicKeyBits(pub interface{}) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}

// ScanCertChain opens two TLS connections to host:port: one with
// InsecureSkipVerify=true to inspect the raw certificate chain (works even for
// self-signed certs), and a second with normal verification to determine whether
// the chain is trusted by the system root pool. Returns nil on dial failure.
func ScanCertChain(ctx context.Context, host, port string) *CertChain {
	const fallbackTimeout = 10 * time.Second
	dialer := &net.Dialer{Timeout: fallbackTimeout}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	// Step 1: inspect-only dial — gather chain even for invalid/self-signed certs.
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // #nosec G402 -- intentional inspect-only dial; we are INSPECTING, not trusting
	})
	if err != nil {
		return nil
	}
	state := conn.ConnectionState()
	chain := BuildChain(&state)
	conn.Close() // #nosec G104 -- best-effort teardown; error is not actionable here

	if chain == nil {
		return nil
	}

	// Step 2: verification dial to determine whether the chain is trusted.
	connVerify, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		ServerName: host,
	})
	if err == nil {
		chain.Verified = true
		connVerify.Close() // #nosec G104 -- best-effort teardown
	}

	return chain
}
