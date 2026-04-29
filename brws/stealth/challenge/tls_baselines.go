package challenge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/skunkworq/stealth/brws/core/types"
)

// TLSReferenceBaseline represents a reference TLS fingerprint for a known browser.
type TLSReferenceBaseline struct {
	Browser string
	Version string

	// JA3/JA4 from captured training data
	JA3Hash string
	JA4     string

	// Structural properties
	CipherSuiteCount int      // non-GREASE cipher count
	ExtensionCount   int      // non-GREASE extension count
	HasGREASE        bool     // GREASE values present
	HasALPS          bool     // ALPS extension (Chrome-specific, ext 0x44cd / 17613)
	HasCertCompress  bool     // compress_certificate extension
	CipherSuiteOrder []uint16 // non-GREASE cipher suites in order
	ExtensionOrder   []uint16 // non-GREASE extensions in order
	SupportedGroups  []uint16 // non-GREASE supported groups
	ALPN             []string // ALPN protocols
}

// Chrome146Baseline returns the reference TLS baseline for Chrome 146 on macOS,
// captured from training-data/session-001 via the lab MITM proxy.
func Chrome146Baseline() *TLSReferenceBaseline {
	return &TLSReferenceBaseline{
		Browser: "chrome",
		Version: "146",
		// From training-data/session-001/capture_01_afterpay_com.json
		JA3Hash: "5bac942cde3e35b287292d9a1367681e",
		JA4:     "t12d1516h2_3fcf15715704_0a79012240d9",

		CipherSuiteCount: 15, // 16 total - 1 GREASE
		ExtensionCount:   16, // 18 total - 2 GREASE
		HasGREASE:        true,
		HasALPS:          true, // ext 17613 (0x44cd)
		HasCertCompress:  true, // ext 27 (0x001b)

		// Non-GREASE cipher suites in order (from captured data)
		CipherSuiteOrder: []uint16{
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
			0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
			0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		},

		// Non-GREASE extensions in order (from captured data)
		ExtensionOrder: []uint16{
			0x002d, // psk_key_exchange_modes
			0x0012, // signed_certificate_timestamp (position 3)
			0xff01, // renegotiation_info
			0x44cd, // ALPS (17613)
			0x0033, // key_share
			0xfe0d, // encrypted_client_hello (65037)
			0x0005, // status_request
			0x002b, // supported_versions
			0x000a, // supported_groups
			0x000b, // ec_point_formats
			0x0023, // session_ticket (35)
			0x000d, // signature_algorithms
			0x001b, // compress_certificate
			0x0000, // server_name
			0x0017, // extended_master_secret
			0x0010, // ALPN
		},

		SupportedGroups: []uint16{
			0x11ec, // X25519MLKEM768 (post-quantum)
			0x001d, // x25519
			0x0017, // secp256r1
			0x0018, // secp384r1
		},

		ALPN: []string{"h2", "http/1.1"},
	}
}

// Firefox128Baseline returns the reference TLS baseline for Firefox 128.
// Firefox differs from Chrome in cipher order, no ALPS, different extension set.
func Firefox128Baseline() *TLSReferenceBaseline {
	return &TLSReferenceBaseline{
		Browser: "firefox",
		Version: "128",

		CipherSuiteCount: 17,
		ExtensionCount:   15,
		HasGREASE:        true,  // Firefox 128+ uses GREASE
		HasALPS:          false, // ALPS is Chrome-only
		HasCertCompress:  false, // Firefox doesn't use compress_certificate

		CipherSuiteOrder: []uint16{
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
			0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
			0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		},

		ExtensionOrder: []uint16{
			0x0000, // server_name
			0x0017, // extended_master_secret
			0xff01, // renegotiation_info
			0x000a, // supported_groups
			0x000b, // ec_point_formats
			0x0023, // session_ticket
			0x0010, // ALPN
			0x0005, // status_request
			0x0022, // delegated_credentials
			0x0033, // key_share
			0x002b, // supported_versions
			0x000d, // signature_algorithms
			0x002d, // psk_key_exchange_modes
			0x001c, // record_size_limit
			0x0015, // padding
		},

		SupportedGroups: []uint16{
			0x001d, // x25519
			0x0017, // secp256r1
			0x0018, // secp384r1
			0x0100, // ffdhe2048
			0x0101, // ffdhe3072
		},

		ALPN: []string{"h2", "http/1.1"},
	}
}

// GoDefaultBaseline returns what Go 1.26's crypto/tls sends by default.
// This is the fingerprint the shield should detect.
func GoDefaultBaseline() *TLSReferenceBaseline {
	return &TLSReferenceBaseline{
		Browser: "go",
		Version: "1.26",

		CipherSuiteCount: 13,
		ExtensionCount:   10,
		HasGREASE:        false,
		HasALPS:          false,
		HasCertCompress:  false,

		// Go 1.26 actual cipher suite order (captured via CapturingListener)
		CipherSuiteOrder: []uint16{
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		},

		// Go 1.26 actual extension order
		ExtensionOrder: []uint16{
			0x0000, // server_name
			0x0005, // status_request
			0x000a, // supported_groups
			0x000b, // ec_point_formats
			0x000d, // signature_algorithms
			0x0012, // signed_certificate_timestamp
			0x002b, // supported_versions
			0x002d, // psk_key_exchange_modes
			0x0033, // key_share
			0xff01, // renegotiation_info
		},

		SupportedGroups: []uint16{
			0x0019, // secp521r1 (Go 1.26 includes this)
			0x001d, // x25519
			0x0017, // secp256r1
			0x0018, // secp384r1
		},

		ALPN: []string{"h2", "http/1.1"},
	}
}

// knownBrowserBaselines returns all reference baselines for comparison.
func knownBrowserBaselines() []*TLSReferenceBaseline {
	return []*TLSReferenceBaseline{
		Chrome146Baseline(),
		Firefox128Baseline(),
	}
}

// TLSDeepAnalysis holds the results of deep TLS fingerprint analysis.
type TLSDeepAnalysis struct {
	// Matched baseline (nil if no match)
	MatchedBaseline *TLSReferenceBaseline
	MatchScore      float64 // 0.0 = no match, 1.0 = perfect match

	// Individual signal scores
	GREASEScore       float64 // 0.0 = has GREASE, 1.0 = missing GREASE
	ALPSScore         float64 // 0.0 = expected, 1.0 = missing when expected
	CertCompressScore float64
	CipherCountScore  float64 // deviation from expected
	ExtCountScore     float64
	CipherOrderScore  float64 // Jaccard/order similarity
	ExtOrderScore     float64
	JA3MatchScore     float64 // 0.0 = matches known, 1.0 = unknown
	JA4MatchScore     float64

	// Composite
	BotScore   float64
	Anomalies  []string
	IsGoTLS    bool
	IsUTLS     bool
	Indicators []string
}

// AnalyzeTLSDeep performs deep TLS fingerprint analysis against known baselines.
func AnalyzeTLSDeep(fp *types.TLSFingerprint, claimedBrowser string) *TLSDeepAnalysis {
	if fp == nil {
		return nil
	}

	analysis := &TLSDeepAnalysis{
		Anomalies:  make([]string, 0),
		Indicators: make([]string, 0),
	}

	// Extract non-GREASE values
	ciphers := nonGREASECiphers(fp)
	extensions := nonGREASEExtensions(fp)
	groups := nonGREASEGroups(fp)

	// 1. GREASE check — all modern browsers use GREASE, Go does not
	hasGREASE := len(fp.GREASE) > 0
	if !hasGREASE {
		analysis.GREASEScore = 1.0
		analysis.Anomalies = append(analysis.Anomalies, "no_grease: Go/curl TLS fingerprint (browsers always use GREASE)")
		analysis.Indicators = append(analysis.Indicators, "tls_no_grease")
	}

	// 2. ALPS check — Chrome sends ALPS (ext 0x44cd), Firefox/Go do not
	hasALPS := hasExtension(fp, 0x44cd)
	if claimedBrowser == "chrome" && !hasALPS {
		analysis.ALPSScore = 0.8
		analysis.Anomalies = append(analysis.Anomalies, "no_alps: claims Chrome but missing ALPS extension")
		analysis.Indicators = append(analysis.Indicators, "tls_chrome_missing_alps")
	}

	// 3. compress_certificate — Chrome sends it, Firefox/Go do not
	hasCertCompress := hasExtension(fp, 0x001b)
	if claimedBrowser == "chrome" && !hasCertCompress {
		analysis.CertCompressScore = 0.5
		analysis.Anomalies = append(analysis.Anomalies, "no_cert_compress: claims Chrome but missing compress_certificate")
		analysis.Indicators = append(analysis.Indicators, "tls_chrome_missing_cert_compress")
	}

	// 4. Cipher suite count deviation
	goBaseline := GoDefaultBaseline()
	if len(ciphers) <= goBaseline.CipherSuiteCount+1 {
		analysis.CipherCountScore = 0.7
		analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("low_cipher_count: %d ciphers (browsers have 15-17)", len(ciphers)))
		analysis.Indicators = append(analysis.Indicators, "tls_low_cipher_count")
	}

	// 5. Extension count deviation
	if len(extensions) <= goBaseline.ExtensionCount+1 {
		analysis.ExtCountScore = 0.7
		analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("low_extension_count: %d extensions (browsers have 15-18)", len(extensions)))
		analysis.Indicators = append(analysis.Indicators, "tls_low_extension_count")
	}

	// 6. Cipher suite order similarity to known baselines
	// NOTE: Chrome 110+ randomizes extension order per session, so we use
	// set-only (Jaccard) comparison for extensions, but ordered comparison for ciphers.
	bestCipherSim := 0.0
	bestExtSim := 0.0
	var bestBaseline *TLSReferenceBaseline

	for _, baseline := range knownBrowserBaselines() {
		cipherSim := orderSimilarity(ciphers, baseline.CipherSuiteOrder)
		// Extensions: set-only comparison (ignore order due to Chrome extension shuffling)
		extSim := setJaccard(extensions, baseline.ExtensionOrder)
		combined := (cipherSim + extSim) / 2.0

		if combined > (bestCipherSim+bestExtSim)/2.0 {
			bestCipherSim = cipherSim
			bestExtSim = extSim
			bestBaseline = baseline
		}
	}

	analysis.CipherOrderScore = 1.0 - bestCipherSim
	analysis.ExtOrderScore = 1.0 - bestExtSim
	analysis.MatchedBaseline = bestBaseline
	analysis.MatchScore = (bestCipherSim + bestExtSim) / 2.0

	if bestCipherSim < 0.5 {
		analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("cipher_order_mismatch: %.0f%% similarity to %s %s", bestCipherSim*100, bestBaseline.Browser, bestBaseline.Version))
		analysis.Indicators = append(analysis.Indicators, "tls_cipher_order_mismatch")
	}

	if bestExtSim < 0.5 {
		analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("extension_set_mismatch: %.0f%% overlap with %s %s", bestExtSim*100, bestBaseline.Browser, bestBaseline.Version))
		analysis.Indicators = append(analysis.Indicators, "tls_extension_set_mismatch")
	}

	// 7. JA3/JA4 matching against known baselines
	// Only penalize if the set-level match is also low — JA3/JA4 hashes change with
	// extension order randomization (Chrome 110+), so a perfect set match with
	// mismatched hash is normal.
	if fp.JA3Hash != "" && bestExtSim < 0.95 {
		ja3Known := false
		for _, baseline := range knownBrowserBaselines() {
			if fp.JA3Hash == baseline.JA3Hash {
				ja3Known = true
				break
			}
		}
		if !ja3Known {
			analysis.JA3MatchScore = 0.3
		}
	}

	if fp.JA4 != "" && bestExtSim < 0.95 {
		ja4Known := false
		for _, baseline := range knownBrowserBaselines() {
			if fp.JA4 == baseline.JA4 {
				ja4Known = true
				break
			}
		}
		if !ja4Known {
			analysis.JA4MatchScore = 0.3
		}
	}

	// 8. Go TLS detection — very specific pattern
	goSim := orderSimilarity(ciphers, goBaseline.CipherSuiteOrder)
	goExtSim := setJaccard(extensions, goBaseline.ExtensionOrder)
	if goSim > 0.8 && goExtSim > 0.8 && !hasGREASE {
		analysis.IsGoTLS = true
		analysis.Anomalies = append(analysis.Anomalies, "go_tls_detected: cipher+extension order matches Go default")
		analysis.Indicators = append(analysis.Indicators, "tls_go_default_detected")
	}

	// 9. uTLS detection — has GREASE but may have mismatched extension set
	if hasGREASE && claimedBrowser == "chrome" {
		// Check for missing Chrome-specific extensions that uTLS might not include
		chromeExtensions := []uint16{0x44cd, 0xfe0d, 0x001b} // ALPS, ECH, cert_compress
		missingCount := 0
		for _, ext := range chromeExtensions {
			if !hasExtension(fp, ext) {
				missingCount++
			}
		}
		if missingCount >= 2 {
			analysis.IsUTLS = true
			analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("utls_detected: missing %d Chrome-specific extensions", missingCount))
			analysis.Indicators = append(analysis.Indicators, "tls_utls_detected")
		}
	}

	// 10. Supported groups check — post-quantum indicator
	hasPostQuantum := false
	for _, g := range groups {
		if g == 0x11ec { // X25519MLKEM768
			hasPostQuantum = true
			break
		}
	}
	if claimedBrowser == "chrome" && !hasPostQuantum {
		// Chrome 146+ uses post-quantum key exchange
		analysis.Anomalies = append(analysis.Anomalies, "no_post_quantum: Chrome 146+ uses X25519MLKEM768")
		analysis.Indicators = append(analysis.Indicators, "tls_no_post_quantum")
	}

	// Composite bot score
	analysis.BotScore = computeTLSBotScore(analysis)

	return analysis
}

// computeTLSBotScore computes a composite TLS bot score from individual signals.
func computeTLSBotScore(a *TLSDeepAnalysis) float64 {
	// Weighted combination of signals
	score := 0.0
	score += a.GREASEScore * 0.30       // No GREASE is the strongest Go signal
	score += a.ALPSScore * 0.10         // Missing ALPS for Chrome
	score += a.CertCompressScore * 0.05 // Missing cert compress
	score += a.CipherCountScore * 0.15  // Low cipher count
	score += a.ExtCountScore * 0.10     // Low extension count
	score += a.CipherOrderScore * 0.15  // Cipher order mismatch
	score += a.ExtOrderScore * 0.10     // Extension order mismatch
	score += a.JA3MatchScore * 0.025    // JA3 unknown
	score += a.JA4MatchScore * 0.025    // JA4 unknown

	// Binary boost for definitive Go detection
	if a.IsGoTLS && score < 0.95 {
		score = 0.95
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// nonGREASECiphers extracts non-GREASE cipher suites in order.
func nonGREASECiphers(fp *types.TLSFingerprint) []uint16 {
	out := make([]uint16, 0, len(fp.CipherSuites))
	for _, c := range fp.CipherSuites {
		if !c.IsGREASE {
			out = append(out, c.Value)
		}
	}
	return out
}

// nonGREASEExtensions extracts non-GREASE extensions in order.
func nonGREASEExtensions(fp *types.TLSFingerprint) []uint16 {
	out := make([]uint16, 0, len(fp.Extensions))
	for _, e := range fp.Extensions {
		if !e.IsGREASE {
			out = append(out, e.Type)
		}
	}
	return out
}

// nonGREASEGroups extracts non-GREASE supported groups.
func nonGREASEGroups(fp *types.TLSFingerprint) []uint16 {
	out := make([]uint16, 0, len(fp.SupportedGroups))
	for _, g := range fp.SupportedGroups {
		if !isGREASEValue(g) {
			out = append(out, g)
		}
	}
	return out
}

// hasExtension checks if an extension type is present.
func hasExtension(fp *types.TLSFingerprint, extType uint16) bool {
	for _, e := range fp.Extensions {
		if e.Type == extType {
			return true
		}
	}
	return false
}

// isGREASEValue checks if a value is a GREASE value.
func isGREASEValue(val uint16) bool {
	return (val&0x0F0F) == 0x0A0A && ((val>>4)&0x0F) == ((val>>12)&0x0F)
}

// setJaccard computes set-only Jaccard similarity (ignoring order).
// Used for extensions since Chrome 110+ randomizes extension order per session.
// Also tolerates missing server_name (0x0000) when connecting to IP addresses.
func setJaccard(a, b []uint16) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	setA := make(map[uint16]bool, len(a))
	for _, v := range a {
		setA[v] = true
	}
	setB := make(map[uint16]bool, len(b))
	for _, v := range b {
		setB[v] = true
	}

	// Tolerate missing server_name (0x0000) — it's omitted when connecting to IP addresses
	if !setA[0x0000] && setB[0x0000] {
		delete(setB, 0x0000)
	}
	if !setB[0x0000] && setA[0x0000] {
		delete(setA, 0x0000)
	}

	intersection := 0
	for v := range setA {
		if setB[v] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// orderSimilarity computes the ordered Jaccard similarity between two uint16 sequences.
// Returns 1.0 for identical sequences, 0.0 for completely different.
// This considers both set overlap AND positional ordering.
func orderSimilarity(a, b []uint16) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Set intersection (Jaccard)
	setA := make(map[uint16]bool, len(a))
	for _, v := range a {
		setA[v] = true
	}
	setB := make(map[uint16]bool, len(b))
	for _, v := range b {
		setB[v] = true
	}

	intersection := 0
	for v := range setA {
		if setB[v] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}
	jaccard := float64(intersection) / float64(union)

	// Longest common subsequence for order similarity
	common := make([]uint16, 0, intersection)
	for _, v := range a {
		if setB[v] {
			common = append(common, v)
		}
	}

	commonB := make([]uint16, 0, intersection)
	for _, v := range b {
		if setA[v] {
			commonB = append(commonB, v)
		}
	}

	lcsLen := lcs(common, commonB)
	orderScore := 0.0
	if len(common) > 0 {
		maxLen := len(common)
		if len(commonB) > maxLen {
			maxLen = len(commonB)
		}
		orderScore = float64(lcsLen) / float64(maxLen)
	}

	// Combined: 50% set overlap, 50% order preservation
	return 0.5*jaccard + 0.5*orderScore
}

// lcs computes the length of the longest common subsequence.
func lcs(a, b []uint16) int {
	m, n := len(a), len(b)
	if m == 0 || n == 0 {
		return 0
	}

	// Use O(n) space
	prev := make([]int, n+1)
	curr := make([]int, n+1)

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				curr[j] = prev[j-1] + 1
			} else {
				if prev[j] > curr[j-1] {
					curr[j] = prev[j]
				} else {
					curr[j] = curr[j-1]
				}
			}
		}
		prev, curr = curr, prev
		for j := range curr {
			curr[j] = 0
		}
	}

	return prev[n]
}

// FormatTLSAnalysis returns a human-readable summary of TLS analysis.
func FormatTLSAnalysis(a *TLSDeepAnalysis) string {
	if a == nil {
		return "no TLS data"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "TLS Bot Score: %.3f\n", a.BotScore)
	if a.MatchedBaseline != nil {
		fmt.Fprintf(&sb, "Best Match: %s %s (%.0f%% similarity)\n", a.MatchedBaseline.Browser, a.MatchedBaseline.Version, a.MatchScore*100)
	}
	if a.IsGoTLS {
		fmt.Fprintf(&sb, "DETECTED: Go default TLS fingerprint\n")
	}
	if a.IsUTLS {
		fmt.Fprintf(&sb, "DETECTED: uTLS fingerprint (missing browser-specific extensions)\n")
	}

	if len(a.Anomalies) > 0 {
		fmt.Fprintf(&sb, "Anomalies:\n")
		for _, anom := range a.Anomalies {
			fmt.Fprintf(&sb, "  - %s\n", anom)
		}
	}

	return sb.String()
}

// TLSReferenceBaselineReport holds comparison results for reporting.
type TLSReferenceBaselineReport struct {
	Baseline         string
	CipherSimilarity float64
	ExtSimilarity    float64
	SetOverlap       float64
	Missing          []string
	Extra            []string
}

// CompareTLSToBaselines compares a captured TLS fingerprint against all baselines.
func CompareTLSToBaselines(fp *types.TLSFingerprint) []TLSReferenceBaselineReport {
	if fp == nil {
		return nil
	}

	ciphers := nonGREASECiphers(fp)
	extensions := nonGREASEExtensions(fp)
	baselines := append(knownBrowserBaselines(), GoDefaultBaseline())

	reports := make([]TLSReferenceBaselineReport, 0, len(baselines))
	for _, bl := range baselines {
		report := TLSReferenceBaselineReport{
			Baseline:         fmt.Sprintf("%s_%s", bl.Browser, bl.Version),
			CipherSimilarity: orderSimilarity(ciphers, bl.CipherSuiteOrder),
			ExtSimilarity:    setJaccard(extensions, bl.ExtensionOrder),
		}

		// Find missing and extra ciphers
		blSet := make(map[uint16]bool, len(bl.CipherSuiteOrder))
		for _, c := range bl.CipherSuiteOrder {
			blSet[c] = true
		}
		fpSet := make(map[uint16]bool, len(ciphers))
		for _, c := range ciphers {
			fpSet[c] = true
		}

		for c := range blSet {
			if !fpSet[c] {
				report.Missing = append(report.Missing, fmt.Sprintf("cipher:0x%04x", c))
			}
		}
		for c := range fpSet {
			if !blSet[c] {
				report.Extra = append(report.Extra, fmt.Sprintf("cipher:0x%04x", c))
			}
		}

		sort.Strings(report.Missing)
		sort.Strings(report.Extra)

		reports = append(reports, report)
	}

	return reports
}
