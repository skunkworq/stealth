package tlsprobe

import "fmt"

// TLSVersion is a TLS protocol version number (wire format).
type TLSVersion uint16

const (
	VersionTLS10 TLSVersion = 0x0301
	VersionTLS11 TLSVersion = 0x0302
	VersionTLS12 TLSVersion = 0x0303
	VersionTLS13 TLSVersion = 0x0304
)

// String returns a human-readable TLS version string ("TLS 1.0".."TLS 1.3").
// Unknown versions return "unknown (0x<hex>)".
func (v TLSVersion) String() string {
	switch v {
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", uint16(v))
	}
}
