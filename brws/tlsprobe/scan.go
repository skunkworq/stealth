package tlsprobe

import "context"

// Options configures which probes Scan performs.
type Options struct {
	// MaxHandshakes bounds the total number of TLS connections opened. Defaults to 30.
	MaxHandshakes int
	// EnumerateVersions enables TLS version probing (TLS 1.0–1.3).
	EnumerateVersions bool
	// EnumerateCiphers enables greedy cipher enumeration for each supported version.
	EnumerateCiphers bool
	// ScanCertChain enables certificate chain extraction and verification.
	ScanCertChain bool
}

// Result holds the output of a Scan call.
type Result struct {
	Versions []VersionSupport
	Ciphers  []SupportedCipher
	Chain    *CertChain
	// Partial is true when the budget was exhausted or the host was unreachable
	// mid-scan; results reflect whatever was collected before stopping.
	Partial bool
}

// Scan orchestrates the requested probes against host:port with a single shared
// Budget. All version probes and cipher enumeration handshakes decrement the
// same budget; when it hits zero Partial is set and Scan returns early.
//
// Clean budget accounting: one Budget{Remaining: MaxHandshakes} is created;
// every actual TLS handshake calls budget.take() exactly once. There is no
// pre-decrement/re-add accounting.
func Scan(ctx context.Context, host, port string, opts Options) (*Result, error) {
	maxHS := opts.MaxHandshakes
	if maxHS <= 0 {
		maxHS = 30
	}

	budget := &Budget{Remaining: maxHS}
	result := &Result{}

	// ── Certificate chain scan (no budget cost — two dials, not handshakes under
	// our enumeration budget; cert scan has its own fixed 2-dial cost and is
	// quick). We count it as 1 budget slot to bound total connection count.
	if opts.ScanCertChain {
		if !budget.take() {
			result.Partial = true
			return result, nil
		}

		result.Chain = ScanCertChain(ctx, host, port)
	}

	// ── Version enumeration ──────────────────────────────────────────────────
	if opts.EnumerateVersions || opts.EnumerateCiphers {
		// Check budget for version probes (4 versions × 1 handshake each).
		const numVersions = 4
		for range numVersions {
			if !budget.take() {
				result.Partial = true
				return result, nil
			}
		}

		versions, reachable, err := EnumerateVersions(ctx, host, port)
		result.Versions = versions

		if err != nil {
			if !reachable {
				result.Partial = true
			}

			return result, err
		}
	}

	// ── Cipher enumeration (per supported version) ───────────────────────────
	if opts.EnumerateCiphers {
		for _, vs := range result.Versions {
			if !vs.Supported {
				continue
			}

			v := tlsVersionFromSuffix(vs.Version.String())

			ciphers, cipherErr := EnumerateCiphers(ctx, host, port, v, budget)
			result.Ciphers = append(result.Ciphers, ciphers...)

			if cipherErr != nil {
				result.Partial = true
				return result, cipherErr
			}

			if budget.Remaining == 0 {
				result.Partial = true
				return result, nil
			}
		}
	}

	return result, nil
}
