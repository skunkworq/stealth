// Package tlsfprint provides TLS fingerprinting capabilities.
//nolint:gosec // G501: crypto/md5 used intentionally for JA3/JA4 fingerprinting
package tlsfprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type JA4Fingerprint struct {
	Version         string
	TLSVersion      uint16
	ALPN            string
	CipherSuite     uint16
	GREASE          bool
	Extensions      []uint16
	KeyShares       []uint16
	SignatureAlgs   []uint16
	SupportedGroups []uint16
	SupportedVers   []uint16
	ECPointFormats  []byte
	SessionTicket   bool
	EarlyData       bool
	QUICParams      []byte
}

func ParseJA4(ja4 string) (*JA4Fingerprint, error) {
	fp := &JA4Fingerprint{}

	parts := strings.Split(ja4, "_")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JA4 format")
	}

	fp.Version = parts[0]

	if strings.HasPrefix(parts[0], "t13") {
		fp.TLSVersion = 0x0304
	} else if strings.HasPrefix(parts[0], "t12") {
		fp.TLSVersion = 0x0303
	}

	protoPart := strings.TrimPrefix(parts[0], "t13")
	protoPart = strings.TrimPrefix(protoPart, "t12")
	if protoPart == "d" {
		protoPart = ""
	}
	fp.ALPN = protoPart

	if len(parts) >= 2 {
		cs := strings.TrimSuffix(parts[1], "d")
		_, _ = fmt.Sscanf(cs, "%04x", &fp.CipherSuite)
	}

	if len(parts) >= 3 {
		third := parts[2]
		if strings.HasSuffix(third, "d") {
			fp.GREASE = true
			third = strings.TrimSuffix(third, "d")
		}

		if third == "h" || third == "q" || third == "h2" || third == "hq" {
			fp.ALPN = third
		}
	}

	return fp, nil
}

func (j *JA4Fingerprint) ToString() string {
	ver := "t12"
	if j.TLSVersion >= 0x0304 {
		ver = "t13"
	}

	proto := "_"
	if j.ALPN != "" {
		proto = j.ALPN
	}

	cs := fmt.Sprintf("%04x", j.CipherSuite)

	suffix := ""
	if j.GREASE {
		suffix = "d"
	}

	return fmt.Sprintf("%s%s_%s%s", ver, proto, cs, suffix)
}

func (j *JA4Fingerprint) Hash() string {
	return sha256Hash(j.ToString())
}

type JA4Plus struct {
	JA4Fingerprint

	ServerName string

	ExtensionOrder []uint16
	CipherOrder    []uint16

	ExtensionCount    int
	CipherCount       int
	KeyShareCount     int
	SignatureAlgCount int

	HasGREASE        bool
	HasKeyShare      bool
	HasSessionTicket bool
	HasEarlyData     bool

	ECHConfig []byte
	Cookie    []byte

	RawClientHello []byte
}

func (j *JA4Plus) ToExtendedString() string {
	var parts []string

	parts = append(parts, j.ToString())

	parts = append(parts, fmt.Sprintf("e%d", j.ExtensionCount))
	parts = append(parts, fmt.Sprintf("c%d", j.CipherCount))

	if j.HasGREASE {
		parts = append(parts, "g")
	}
	if j.HasKeyShare {
		parts = append(parts, "k")
	}
	if j.HasSessionTicket {
		parts = append(parts, "s")
	}
	if j.HasEarlyData {
		parts = append(parts, "0rtt")
	}

	if len(j.ServerName) > 0 {
		parts = append(parts, fmt.Sprintf("sn%d", len(j.ServerName)))
	}

	return strings.Join(parts, "_")
}

func (j *JA4Plus) Hash() string {
	return sha256Hash(j.ToExtendedString())
}

type JA3Plus struct {
	Version      uint16
	CipherSuites []uint16
	Extensions   []uint16

	CipherOrder    []uint16
	ExtensionOrder []uint16

	SupportedGroups []uint16
	SignatureAlgs   []uint16
	ALPN            []string

	ECPointFormats []byte

	HasGREASE      bool
	SessionTickets bool
	EarlyData      bool

	RawClientHello []byte
}

func (j *JA3Plus) ToString() string {
	var cipherStrs []string
	for _, c := range j.CipherSuites {
		cipherStrs = append(cipherStrs, fmt.Sprintf("%04x", c))
	}

	var extStrs []string
	for _, e := range j.Extensions {
		extStrs = append(extStrs, fmt.Sprintf("%d", e))
	}

	alpn := ""
	if len(j.ALPN) > 0 {
		alpn = "," + strings.Join(j.ALPN, ",")
	}

	return fmt.Sprintf("%04x,%s,%s%s", j.Version, strings.Join(cipherStrs, "-"), strings.Join(extStrs, "-"), alpn)
}

func (j *JA3Plus) Hash() string {
	h := md5.Sum([]byte(j.ToString()))
	return hex.EncodeToString(h[:])
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
