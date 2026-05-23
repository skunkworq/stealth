package detection

import (
	"crypto/tls"
	"fmt"

	"github.com/skunkworq/stealth/brws/core/constants"
)

func (sd *StealthDetector) analyzeTLSFingerprint(tlsConn *tls.ConnectionState) *TLSFingerprintInfo {
	info := &TLSFingerprintInfo{
		TLSVersion:  fmt.Sprintf("0x%04x", tlsConn.Version),
		CipherSuite: fmt.Sprintf("0x%04x", tlsConn.CipherSuite),
		Anomalies:   make([]string, 0),
	}

	// Check for known JA4 (simplified - real implementation would parse ClientHello)
	info.JA4 = "unknown"

	// Detect anomalies
	if info.TLSVersion != "0x0304" && info.TLSVersion != "0x0303" {
		info.Anomalies = append(info.Anomalies, fmt.Sprintf("Unusual TLS version: %s", info.TLSVersion))
	}

	// Check for GREASE - standard Go crypto/tls DOES NOT use GREASE
	// Modern browsers (Chrome, Firefox, Safari) ALL use GREASE.

	// Check cipher suite for GREASE (0x0a0a, 0x1a1a, etc.)
	if (tlsConn.CipherSuite & 0x0f0f) == 0x0a0a {
		info.HasGREASE = true
	}

	// We can't strictly flag here because we don't have the UA.
	// We will perform the cross-check in AnalyzeRequest.

	return info
}

func (sd *StealthDetector) tlsInfoToVector(info *TLSFingerprintInfo) DetectionVector {
	vec := DetectionVector{
		Name:        "TLS Fingerprint",
		Category:    "tls",
		Weight:      constants.WeightTLS,
		Description: "Analyzes TLS handshake for browser identification",
		Indicators:  info.Anomalies,
	}

	if len(info.Anomalies) > 0 {
		vec.Score = 0.3
		vec.Detected = true
	}

	return vec
}
