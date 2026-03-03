// Package tlsparser provides TLS ClientHello parsing for complete fingerprint capture
//nolint:gosec // G401/G501: MD5 required for JA3 fingerprinting per JA3 spec
package tlsparser

import (
	"bytes"
	//nolint:gosec // MD5 required for JA3 fingerprinting per JA3 spec
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/skunkworq/stealth/brws/types"
)

// TLSRecord represents a TLS record layer
type TLSRecord struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Data        []byte
}

// ClientHello represents a parsed ClientHello message
type ClientHello struct {
	Version            uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension

	// Parsed fields
	ServerName           string
	SupportedGroups      []uint16
	SignatureAlgorithms  []uint16
	ALPNProtocols        []string
	ALPS                 string
	CertCompressionAlgos []uint16
	KeyShareGroups       []uint16
	GREASEValues         []GREASEValue
}

// GREASEValue represents a GREASE value and its position
type GREASEValue struct {
	Value    uint16
	Position int
	Context  string // "cipher", "extension", "group"
}

// Extension represents a TLS extension
type Extension struct {
	Type   uint16
	Length uint16
	Data   []byte
}

// ParseClientHello parses raw ClientHello bytes
func ParseClientHello(data []byte) (*ClientHello, error) {
	// Parse TLS record layer
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record")
	}

	record := TLSRecord{
		ContentType: data[0],
		Version:     binary.BigEndian.Uint16(data[1:3]),
		Length:      binary.BigEndian.Uint16(data[3:5]),
	}

	if record.ContentType != 0x16 { // Handshake
		return nil, fmt.Errorf("not a handshake record: 0x%02x", record.ContentType)
	}

	if len(data) < int(5+record.Length) {
		return nil, fmt.Errorf("incomplete TLS record")
	}

	record.Data = data[5 : 5+record.Length]

	// Parse handshake layer
	if len(record.Data) < 4 {
		return nil, fmt.Errorf("handshake data too short")
	}

	handshakeType := record.Data[0]
	if handshakeType != 0x01 { // ClientHello
		return nil, fmt.Errorf("not a ClientHello: 0x%02x", handshakeType)
	}

	handshakeLength := uint32(record.Data[1])<<16 | uint32(record.Data[2])<<8 | uint32(record.Data[3])
	if len(record.Data) < int(4+handshakeLength) {
		return nil, fmt.Errorf("incomplete handshake")
	}

	helloData := record.Data[4 : 4+handshakeLength]
	return parseClientHelloBody(helloData)
}

// parseClientHelloBody parses the ClientHello body (after handshake header)
func parseClientHelloBody(data []byte) (*ClientHello, error) {
	ch := &ClientHello{}
	reader := bytes.NewReader(data)

	// Version (2 bytes)
	if err := binary.Read(reader, binary.BigEndian, &ch.Version); err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}

	// Random (32 bytes)
	ch.Random = make([]byte, 32)
	if _, err := reader.Read(ch.Random); err != nil {
		return nil, fmt.Errorf("reading random: %w", err)
	}

	// Session ID length
	var sessionIDLen uint8
	if err := binary.Read(reader, binary.BigEndian, &sessionIDLen); err != nil {
		return nil, fmt.Errorf("reading session ID length: %w", err)
	}

	// Session ID
	ch.SessionID = make([]byte, sessionIDLen)
	if _, err := reader.Read(ch.SessionID); err != nil {
		return nil, fmt.Errorf("reading session ID: %w", err)
	}

	// Cipher suites length
	var cipherSuitesLen uint16
	if err := binary.Read(reader, binary.BigEndian, &cipherSuitesLen); err != nil {
		return nil, fmt.Errorf("reading cipher suites length: %w", err)
	}

	// Cipher suites
	cipherData := make([]byte, cipherSuitesLen)
	if _, err := reader.Read(cipherData); err != nil {
		return nil, fmt.Errorf("reading cipher suites: %w", err)
	}

	for i := 0; i < len(cipherData); i += 2 {
		suite := binary.BigEndian.Uint16(cipherData[i : i+2])
		ch.CipherSuites = append(ch.CipherSuites, suite)

		if IsGREASE(suite) {
			ch.GREASEValues = append(ch.GREASEValues, GREASEValue{
				Value:    suite,
				Position: i / 2,
				Context:  "cipher",
			})
		}
	}

	// Compression methods length
	var compressionLen uint8
	if err := binary.Read(reader, binary.BigEndian, &compressionLen); err != nil {
		return nil, fmt.Errorf("reading compression length: %w", err)
	}

	// Compression methods
	ch.CompressionMethods = make([]uint8, compressionLen)
	if _, err := reader.Read(ch.CompressionMethods); err != nil {
		return nil, fmt.Errorf("reading compression methods: %w", err)
	}

	// Extensions length (if remaining data exists)
	if reader.Len() == 0 {
		return ch, nil
	}

	var extensionsLen uint16
	if err := binary.Read(reader, binary.BigEndian, &extensionsLen); err != nil {
		return nil, fmt.Errorf("reading extensions length: %w", err)
	}

	// Parse extensions
	extData := make([]byte, extensionsLen)
	if _, err := reader.Read(extData); err != nil {
		return nil, fmt.Errorf("reading extensions: %w", err)
	}

	ch.Extensions, _ = parseExtensions(extData)

	// Extract specific extension data
	for i, ext := range ch.Extensions {
		if IsGREASE(ext.Type) {
			ch.GREASEValues = append(ch.GREASEValues, GREASEValue{
				Value:    ext.Type,
				Position: i,
				Context:  "extension",
			})
		}

		switch ext.Type {
		case 0x0000: // server_name
			ch.ServerName = parseServerNameExtension(ext.Data)
		case 0x000a: // supported_groups
			ch.SupportedGroups = parseSupportedGroups(ext.Data)
		case 0x000d: // signature_algorithms
			ch.SignatureAlgorithms = parseSignatureAlgorithms(ext.Data)
		case 0x0010: // ALPN
			ch.ALPNProtocols = parseALPNExtension(ext.Data)
		case 0x0011: // ALPS (Application-Layer Protocol Settings)
			ch.ALPS = parseALPSExtension(ext.Data)
		case 0x001b: // compress_certificate
			ch.CertCompressionAlgos = parseCertCompression(ext.Data)
		case 0x0033: // key_share
			ch.KeyShareGroups = parseKeyShareGroups(ext.Data)
		}
	}

	return ch, nil
}

// parseExtensions parses the extension list
func parseExtensions(data []byte) ([]Extension, error) {
	var extensions []Extension
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		var ext Extension

		if err := binary.Read(reader, binary.BigEndian, &ext.Type); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.BigEndian, &ext.Length); err != nil {
			return nil, err
		}

		ext.Data = make([]byte, ext.Length)
		if _, err := reader.Read(ext.Data); err != nil {
			return nil, err
		}

		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// parseServerNameExtension extracts SNI
func parseServerNameExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Skip SNI extension length and list length
	nameListLen := binary.BigEndian.Uint16(data[0:2])
	if int(nameListLen) != len(data)-2 {
		return "" // Malformed
	}

	// Host name type (should be 0 for host_name)
	if data[2] != 0 {
		return ""
	}

	// Host name length
	hostLen := binary.BigEndian.Uint16(data[3:5])
	if int(5+hostLen) > len(data) {
		return ""
	}

	return string(data[5 : 5+hostLen])
}

// parseSupportedGroups extracts elliptic curve groups
func parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	listLen := binary.BigEndian.Uint16(data[0:2])
	groups := make([]uint16, 0, listLen/2)

	for i := 2; i < 2+int(listLen); i += 2 {
		if i+2 <= len(data) {
			group := binary.BigEndian.Uint16(data[i : i+2])
			groups = append(groups, group)
		}
	}

	return groups
}

// parseSignatureAlgorithms extracts signature algorithms
func parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	listLen := binary.BigEndian.Uint16(data[0:2])
	algs := make([]uint16, 0, listLen/2)

	for i := 2; i < 2+int(listLen); i += 2 {
		if i+2 <= len(data) {
			alg := binary.BigEndian.Uint16(data[i : i+2])
			algs = append(algs, alg)
		}
	}

	return algs
}

// parseALPNExtension extracts ALPN protocols
func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	listLen := binary.BigEndian.Uint16(data[0:2])

	var protocols []string

	for i := 2; i < 2+int(listLen); {
		if i >= len(data) {
			break
		}
		protoLen := int(data[i])
		if i+1+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[i+1:i+1+protoLen]))
		i += 1 + protoLen
	}

	return protocols
}

// parseALPSExtension extracts ALPS (Chrome-specific)
func parseALPSExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// ALPS extension is similar to ALPN - return first protocol
	protocols := parseALPNExtension(data)
	if len(protocols) > 0 {
		return protocols[0]
	}
	return ""
}

// parseCertCompression extracts certificate compression algorithms
func parseCertCompression(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}

	count := int(data[0])
	algos := make([]uint16, 0, count)

	for i := 1; i < 1+count*2; i += 2 {
		if i+2 <= len(data) {
			algo := binary.BigEndian.Uint16(data[i : i+2])
			algos = append(algos, algo)
		}
	}

	return algos
}

// parseKeyShareGroups extracts key share groups
func parseKeyShareGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	// Skip total length
	offset := 2

	var groups []uint16

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		group := binary.BigEndian.Uint16(data[offset : offset+2])
		groups = append(groups, group)

		if offset+4 > len(data) {
			break
		}
		keyLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4 + int(keyLen)
	}

	return groups
}

// IsGREASE checks if a value is a GREASE value
// IsGREASE checks if a value is a GREASE value
func IsGREASE(val uint16) bool {
	// GREASE values: 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
	return (val&0x0F0F) == 0x0A0A && ((val>>4)&0x0F) == ((val>>12)&0x0F)
}

// ToFingerprint converts parsed ClientHello to types.TLSFingerprint format
func (ch *ClientHello) ToFingerprint() *types.TLSFingerprint {
	fp := &types.TLSFingerprint{
		Version:         ch.Version,
		VersionName:     tlsVersionName(ch.Version),
		SupportedGroups: ch.SupportedGroups,
		ALPN:            ch.ALPNProtocols,
		ALPS:            ch.ALPS,
		KeyShareGroups:  ch.KeyShareGroups,
	}

	// Convert cipher suites
	for i, suite := range ch.CipherSuites {
		fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{
			Value:    suite,
			Name:     cipherSuiteName(suite),
			Position: i + 1,
			IsGREASE: IsGREASE(suite),
		})
	}

	// Convert extensions
	for i, ext := range ch.Extensions {
		fp.Extensions = append(fp.Extensions, types.ExtensionInfo{
			Type:     ext.Type,
			Name:     extensionName(ext.Type),
			Position: i + 1,
			IsGREASE: IsGREASE(ext.Type),
			Data:     ext.Data,
		})
	}

	// Convert GREASE values
	for _, g := range ch.GREASEValues {
		fp.GREASE = append(fp.GREASE, types.GREASEInfo{
			Value:    g.Value,
			Position: g.Position,
			Context:  g.Context,
		})
	}

	// Group names
	for _, g := range ch.SupportedGroups {
		fp.GroupNames = append(fp.GroupNames, namedGroupName(g))
	}

	// Certificate compression algorithms
	for _, algo := range ch.CertCompressionAlgos {
		switch algo {
		case 0x0001:
			fp.CertCompression = append(fp.CertCompression, "zlib")
		case 0x0002:
			fp.CertCompression = append(fp.CertCompression, "brotli")
		case 0x0003:
			fp.CertCompression = append(fp.CertCompression, "zstd")
		}
	}

	// Calculate JA3
	fp.JA3String = calculateJA3FromCH(ch)
	fp.JA3Hash = hashString(fp.JA3String)

	// Calculate JA4
	fp.JA4 = calculateJA4FromCH(ch)

	return fp
}

// cipherSuiteName returns the name of a cipher suite
func cipherSuiteName(suite uint16) string {
	names := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	if name, ok := names[suite]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", suite)
}

// extensionName returns the name of a TLS extension
func extensionName(ext uint16) string {
	names := map[uint16]string{
		0x0000: "server_name",
		0x0001: "max_fragment_length",
		0x0005: "status_request",
		0x0007: "client_authz",
		0x0008: "server_authz",
		0x0009: "cert_type",
		0x000a: "supported_groups",
		0x000b: "ec_point_formats",
		0x000d: "signature_algorithms",
		0x000e: "use_srtp",
		0x000f: "heartbeat",
		0x0010: "application_layer_protocol_negotiation",
		0x0011: "application_settings", // ALPS
		0x0012: "signed_certificate_timestamp",
		0x0013: "client_certificate_type",
		0x0014: "server_certificate_type",
		0x0015: "padding",
		0x0016: "encrypt_then_mac",
		0x0017: "extended_master_secret",
		0x0018: "token_binding",
		0x0019: "cached_info",
		0x001b: "compress_certificate",
		0x0023: "signed_certificate_timestamp",
		0x0029: "pre_shared_key",
		0x002a: "early_data",
		0x002b: "supported_versions",
		0x002c: "cookie",
		0x002d: "psk_key_exchange_modes",
		0x002f: "certificate_authorities",
		0x0031: "post_handshake_auth",
		0x0032: "signature_algorithms_cert",
		0x0033: "key_share",
		0x0034: "transparency_info",
		0x3374: "next_protocol_negotiation",
		0xff01: "renegotiation_info",
	}

	if name, ok := names[ext]; ok {
		return name
	}
	return fmt.Sprintf("extension_%d", ext)
}

// namedGroupName returns the name of a named group
func namedGroupName(group uint16) string {
	names := map[uint16]string{
		0x0017: "secp256r1",
		0x0018: "secp384r1",
		0x0019: "secp521r1",
		0x001d: "x25519",
		0x001e: "x448",
		0x0100: "ffdhe2048",
		0x0101: "ffdhe3072",
		0x0102: "ffdhe4096",
		0x0103: "ffdhe6144",
		0x0104: "ffdhe8192",
	}

	if name, ok := names[group]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", group)
}

// calculateJA3FromCH calculates JA3 from parsed ClientHello
func calculateJA3FromCH(ch *ClientHello) string {
	var parts []string

	// SSLVersion
	parts = append(parts, fmt.Sprintf("%d", ch.Version))

	// Cipher suites (excluding GREASE)
	var ciphers []string
	for _, c := range ch.CipherSuites {
		if !IsGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%d", c))
		}
	}
	parts = append(parts, joinInts(ciphers, "-"))

	// Extensions (excluding GREASE)
	var exts []string
	for _, e := range ch.Extensions {
		if !IsGREASE(e.Type) {
			exts = append(exts, fmt.Sprintf("%d", e.Type))
		}
	}
	parts = append(parts, joinInts(exts, "-"))

	// Elliptic curves
	var groups []string
	for _, g := range ch.SupportedGroups {
		if !IsGREASE(g) {
			groups = append(groups, fmt.Sprintf("%d", g))
		}
	}
	parts = append(parts, joinInts(groups, "-"))

	// EC point formats (default to uncompressed)
	parts = append(parts, "0")

	return joinStrings(parts, ",")
}

// calculateJA4FromCH calculates JA4 from parsed ClientHello
func calculateJA4FromCH(ch *ClientHello) string {
	// JA4: t[protocol][version][SNI][cipher_count][ext_count][ALPN]_[cipher_hash]_[ext_hash]
	proto := "t"
	version := "12"
	if ch.Version == 0x0304 {
		version = "13"
	}

	sni := "i"
	if ch.ServerName != "" {
		sni = "d"
	}

	// Cipher count (excluding GREASE)
	cipherCount := 0
	for _, c := range ch.CipherSuites {
		if !IsGREASE(c) {
			cipherCount++
		}
	}

	// Extension count (excluding GREASE)
	extCount := 0
	for _, e := range ch.Extensions {
		if !IsGREASE(e.Type) {
			extCount++
		}
	}

	// ALPN first value (2 chars)
	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		alpn = ch.ALPNProtocols[0]
		if len(alpn) >= 2 {
			alpn = alpn[:2]
		} else {
			alpn = alpn + "00"[:2-len(alpn)]
		}
	}

	ja4 := fmt.Sprintf("%s%s%s%02d%02d%s", proto, version, sni, cipherCount, extCount, alpn)

	// Cipher hash
	var cipherList []string
	for _, c := range ch.CipherSuites {
		if !IsGREASE(c) {
			cipherList = append(cipherList, fmt.Sprintf("%04x", c))
		}
	}
	// Sort cipher list for JA4
	sortStrings(cipherList)
	cipherHash := hashStringTruncated(joinStrings(cipherList, ","), 12)

	// Extension hash (sorted)
	var extList []string
	for _, e := range ch.Extensions {
		if !IsGREASE(e.Type) {
			extList = append(extList, fmt.Sprintf("%04x", e.Type))
		}
	}

	sortStrings(extList)
	extHash := hashStringTruncated(joinStrings(extList, ","), 12)

	return fmt.Sprintf("%s_%s_%s", ja4, cipherHash, extHash)
}

// Helper functions
func joinInts(ints []string, sep string) string {
	return joinStrings(ints, sep)
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

func sortStrings(strs []string) {
	// Simple bubble sort for small lists
	for i := 0; i < len(strs); i++ {
		for j := i + 1; j < len(strs); j++ {
			if strs[i] > strs[j] {
				strs[i], strs[j] = strs[j], strs[i]
			}
		}
	}
}

// tlsVersionName returns the name of a TLS version
func tlsVersionName(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// hashString returns MD5 hash of a string
func hashString(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// hashStringTruncated returns MD5 hash of a string, truncated to n chars
func hashStringTruncated(s string, n int) string {
	h := hashString(s)
	if len(h) > n {
		return h[:n]
	}
	return h
}
