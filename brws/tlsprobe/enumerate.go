package tlsprobe

import (
	"context"
	"net"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// VersionSupport records whether the server accepted a specific TLS version.
type VersionSupport struct {
	Version          TLSVersion
	Supported        bool
	NegotiatedCipher uint16
}

// SupportedCipher is a cipher suite observed as accepted by the server under a given version.
type SupportedCipher struct {
	CipherInfo
	TLSVersion TLSVersion
}

// Budget tracks the remaining number of TLS handshakes allowed for a scan
// to bound latency on slow/adversarial hosts.
type Budget struct {
	Remaining int
}

// take decrements the budget and reports whether the slot was available.
// Returns false (and does not decrement) when the budget is exhausted.
func (b *Budget) take() bool {
	if b.Remaining <= 0 {
		return false
	}
	b.Remaining--

	return true
}

// curatedCiphers12 is the candidate set offered when probing TLS 1.2.
var curatedCiphers12 = []uint16{
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	utls.TLS_RSA_WITH_AES_128_CBC_SHA,
	utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// curatedCiphers13 is the candidate set offered when probing TLS 1.3.
var curatedCiphers13 = []uint16{
	utls.TLS_AES_128_GCM_SHA256,
	utls.TLS_AES_256_GCM_SHA384,
	utls.TLS_CHACHA20_POLY1305_SHA256,
}

// containsUint16 reports whether v is present in s.
func containsUint16(s []uint16, v uint16) bool {
	for _, id := range s {
		if id == v {
			return true
		}
	}

	return false
}

// buildHelloSpec constructs a utls.ClientHelloSpec offering the given TLS
// version and cipher suite list. ServerName is NOT set here — callers must
// set utls.Config.ServerName on the connection config before applying the spec.
func buildHelloSpec(vers uint16, ciphers []uint16) *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin:   utls.VersionTLS10,
		TLSVersMax:   utls.VersionTLS13,
		CipherSuites: ciphers,
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedVersionsExtension{Versions: []uint16{vers}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
			}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}
}

// probeVersion attempts a TLS handshake against host:port offering only the
// given TLS version. Returns (negotiated cipher, true, nil) on success,
// (0, false, nil) if the server refused the version or negotiated differently,
// or (0, false, err) on a network/dial error.
func probeVersion(ctx context.Context, host, port string, vers uint16) (uint16, bool, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()

	cfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // #nosec G402 -- intentional: we want handshake params even on untrusted certs
	}
	uconn := utls.UClient(conn, cfg, utls.HelloCustom)

	// Include both TLS 1.3 and TLS 1.2 ciphers so the server can pick what it
	// supports for the offered version. Use slices.Concat to avoid aliasing the
	// package-level slice.
	allCiphers := slices.Concat(curatedCiphers13, curatedCiphers12)
	spec := buildHelloSpec(vers, allCiphers)

	if err := uconn.ApplyPreset(spec); err != nil {
		return 0, false, err
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		// Handshake refusal means the version is not supported — not a fatal error.
		return 0, false, nil //nolint:nilerr
	}

	cs := uconn.ConnectionState()
	// Verify the server actually negotiated the version we offered.
	// A compliant server should only pick the offered version; if it picked
	// something else, treat this as "not supported".
	if cs.Version != vers {
		return 0, false, nil
	}

	return cs.CipherSuite, true, nil
}

// EnumerateVersions probes TLS 1.0–1.3 (one connection each) and returns a
// slice indicating which versions the server accepts. reachable is false only
// when a network/dial error occurs on the very first probe.
func EnumerateVersions(ctx context.Context, host, port string) (versions []VersionSupport, reachable bool, err error) {
	candidates := []struct {
		vers TLSVersion
	}{
		{VersionTLS10},
		{VersionTLS11},
		{VersionTLS12},
		{VersionTLS13},
	}

	results := make([]VersionSupport, 0, len(candidates))
	hostReachable := true

	for _, c := range candidates {
		cipher, supported, probeErr := probeVersion(ctx, host, port, uint16(c.vers))
		if probeErr != nil {
			hostReachable = false

			return results, hostReachable, probeErr
		}

		vs := VersionSupport{
			Version:   c.vers,
			Supported: supported,
		}
		if supported {
			vs.NegotiatedCipher = cipher
		}

		results = append(results, vs)
	}

	return results, hostReachable, nil
}

// EnumerateCiphers discovers which cipher suites the server will negotiate for
// a given TLS version using the iterative-removal (greedy enumeration) method.
// Each iteration opens a new connection offering all remaining candidates; on
// success the negotiated cipher is recorded and removed from the candidate list.
// Stops when the server refuses to negotiate any remaining candidate, the budget
// is exhausted, or the server picks a cipher not in the offered set (misbehaving
// server guard). The budget is shared with the caller and decremented per handshake.
func EnumerateCiphers(ctx context.Context, host, port string, v TLSVersion, budget *Budget) ([]SupportedCipher, error) {
	var candidates []uint16
	if v == VersionTLS13 {
		candidates = append([]uint16(nil), curatedCiphers13...)
	} else {
		candidates = append([]uint16(nil), curatedCiphers12...)
	}

	var found []SupportedCipher

	for len(candidates) > 0 {
		if !budget.take() {
			break
		}

		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return found, err
		}

		cfg := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // #nosec G402 -- intentional: enumeration probe
		}
		uconn := utls.UClient(conn, cfg, utls.HelloCustom)

		spec := buildHelloSpec(uint16(v), candidates)

		applyErr := uconn.ApplyPreset(spec)
		if applyErr != nil {
			conn.Close() // #nosec G104 -- best-effort teardown; error is not actionable here
			return found, applyErr
		}

		handshakeErr := uconn.HandshakeContext(ctx)
		if handshakeErr != nil {
			// No common cipher — enumeration is complete.
			conn.Close() // #nosec G104 -- best-effort teardown
			break
		}

		cs := uconn.ConnectionState()
		negotiated := cs.CipherSuite
		conn.Close() // #nosec G104 -- best-effort teardown after successful handshake

		// Guard against misbehaving servers that pick a cipher outside the offered
		// set — this would otherwise cause an infinite loop recording the same cipher
		// on every iteration.
		if !containsUint16(candidates, negotiated) {
			break
		}

		info := ClassifyCipher(negotiated)
		found = append(found, SupportedCipher{
			CipherInfo: info,
			TLSVersion: v,
		})

		// Remove the negotiated cipher from candidates so the next iteration
		// forces the server to pick a different one.
		next := candidates[:0]
		for _, id := range candidates {
			if id != negotiated {
				next = append(next, id)
			}
		}

		candidates = next
	}

	return found, nil
}

// tlsVersionFromSuffix maps version display strings back to TLSVersion constants.
// Used by Scan when iterating VersionSupport results.
func tlsVersionFromSuffix(s string) TLSVersion {
	switch s {
	case "TLS 1.3":
		return VersionTLS13
	case "TLS 1.2":
		return VersionTLS12
	case "TLS 1.1":
		return VersionTLS11
	default:
		return VersionTLS10
	}
}
