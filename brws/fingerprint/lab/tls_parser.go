// Package lab provides TLS ClientHello parsing for complete fingerprint capture
package lab

import (
	"github.com/skunkworq/stealth/brws/fingerprint/tls/parser"
)

// Re-export types from tlsparser for backwards compatibility
type (
	ClientHello = tlsparser.ClientHello
	Extension   = tlsparser.Extension
	GREASEValue = tlsparser.GREASEValue
	TLSRecord   = tlsparser.TLSRecord
)

// ParseClientHello parses raw ClientHello bytes
func ParseClientHello(data []byte) (*ClientHello, error) {
	return tlsparser.ParseClientHello(data)
}

// ToFingerprint converts parsed ClientHello to fingerprint format
func ToFingerprint(ch *ClientHello) *TLSFingerprint {
	return ch.ToFingerprint()
}
