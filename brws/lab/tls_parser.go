// Package lab provides TLS ClientHello parsing for complete fingerprint capture
package lab

import (
	"github.com/stealth/brwslab/brws/tlsparser"
)

// Re-export types from tlsparser for backwards compatibility
type ClientHello = tlsparser.ClientHello
type Extension = tlsparser.Extension
type GREASEValue = tlsparser.GREASEValue
type TLSRecord = tlsparser.TLSRecord

// ParseClientHello parses raw ClientHello bytes
func ParseClientHello(data []byte) (*ClientHello, error) {
	return tlsparser.ParseClientHello(data)
}

// ToFingerprint converts parsed ClientHello to fingerprint format
func ToFingerprint(ch *ClientHello) *TLSFingerprint {
	return ch.ToFingerprint()
}
