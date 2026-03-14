package session

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/skunkworq/stealth/brws/types"
)

// browserProfile is a static browser identity used for fingerprint generation.
type browserProfile struct {
	Name           string
	Version        string
	Platform       string
	UserAgent      string
	SecCHUA        string
	SecCHUAPlatform string
	AcceptLang     string
	ViewportWidth  int
	ViewportHeight int
	TLSFingerprint string
}

// profileTable contains 8 realistic browser profiles spanning Chrome, Firefox, and Edge
// across Windows, macOS, and Linux. Enough entropy for session diversity without
// requiring external data files.
var profileTable = []browserProfile{
	{
		Name: "chrome", Version: "120", Platform: "windows",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		SecCHUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		SecCHUAPlatform: `"Windows"`,
		AcceptLang:      "en-US,en;q=0.9",
		ViewportWidth:   1920, ViewportHeight: 1080,
		TLSFingerprint: "chrome_120",
	},
	{
		Name: "chrome", Version: "121", Platform: "macos",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		SecCHUA:         `"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"`,
		SecCHUAPlatform: `"macOS"`,
		AcceptLang:      "en-US,en;q=0.9",
		ViewportWidth:   1440, ViewportHeight: 900,
		TLSFingerprint: "chrome_121",
	},
	{
		Name: "chrome", Version: "119", Platform: "linux",
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		SecCHUA:         `"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"`,
		SecCHUAPlatform: `"Linux"`,
		AcceptLang:      "en-US,en;q=0.9",
		ViewportWidth:   1920, ViewportHeight: 1080,
		TLSFingerprint: "chrome_119",
	},
	{
		Name: "chrome", Version: "122", Platform: "windows",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		SecCHUA:         `"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`,
		SecCHUAPlatform: `"Windows"`,
		AcceptLang:      "en-US,en;q=0.9,de;q=0.8",
		ViewportWidth:   1366, ViewportHeight: 768,
		TLSFingerprint: "chrome_122",
	},
	{
		Name: "firefox", Version: "121", Platform: "windows",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		SecCHUA:         "", // Firefox doesn't send client hints
		SecCHUAPlatform: "",
		AcceptLang:      "en-US,en;q=0.5",
		ViewportWidth:   1920, ViewportHeight: 1080,
		TLSFingerprint: "firefox_121",
	},
	{
		Name: "firefox", Version: "120", Platform: "macos",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		SecCHUA:         "",
		SecCHUAPlatform: "",
		AcceptLang:      "en-US,en;q=0.5",
		ViewportWidth:   1440, ViewportHeight: 900,
		TLSFingerprint: "firefox_120",
	},
	{
		Name: "edge", Version: "120", Platform: "windows",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		SecCHUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
		SecCHUAPlatform: `"Windows"`,
		AcceptLang:      "en-US,en;q=0.9",
		ViewportWidth:   1920, ViewportHeight: 1080,
		TLSFingerprint: "edge_120",
	},
	{
		Name: "chrome", Version: "120", Platform: "macos",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		SecCHUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		SecCHUAPlatform: `"macOS"`,
		AcceptLang:      "en-US,en;q=0.9",
		ViewportWidth:   2560, ViewportHeight: 1440,
		TLSFingerprint: "chrome_120",
	},
	{
		Name: "chrome", Version: "146", Platform: "macos",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecCHUA:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecCHUAPlatform: `"macOS"`,
		AcceptLang:      "en-GB,en-US;q=0.9,en;q=0.8",
		ViewportWidth:   1440, ViewportHeight: 900,
		TLSFingerprint: "chrome_146",
	},
}

// GenerateFingerprint derives a stable CompleteFingerprint from a session ID.
// The same session ID always produces the same fingerprint (deterministic).
// Diversity across sessions comes from the SHA-256 hash of the UUID.
func GenerateFingerprint(sessionID string) *types.CompleteFingerprint {
	hash := sha256.Sum256([]byte(sessionID))
	seed := binary.BigEndian.Uint64(hash[:8])

	idx := int(seed % uint64(len(profileTable)))
	return fingerprintFromProfile(idx, sessionID)
}

func fingerprintFromProfile(idx int, id string) *types.CompleteFingerprint {
	p := profileTable[idx]

	fp := &types.CompleteFingerprint{
		ID:        fmt.Sprintf("fp-%s-%s-%s-%s", p.Name, p.Version, p.Platform, id[:8]),
		Timestamp: time.Now(),
		TLS: &types.TLSFingerprint{
			JA3Hash: fmt.Sprintf("gen-%s-%d", p.TLSFingerprint, idx),
		},
		HTTP: &types.HTTPFingerprint{
			UserAgent:  p.UserAgent,
			AcceptLang: p.AcceptLang,
			AcceptEnc:  "gzip, deflate, br",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		},
		Behavior: &types.BehaviorFingerprint{},
		Metadata: map[string]string{
			"browser":  p.Name,
			"version":  p.Version,
			"platform": p.Platform,
		},
	}

	if p.SecCHUA != "" {
		fp.HTTP.ClientHints = &types.ClientHints{
			SecCHUA:         p.SecCHUA,
			SecCHUAMobile:   "?0",
			SecCHUAPlatform: p.SecCHUAPlatform,
		}
	}

	return fp
}
