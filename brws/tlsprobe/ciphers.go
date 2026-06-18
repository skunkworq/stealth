package tlsprobe

import "crypto/tls"

// Strength describes the cryptographic strength of a TLS cipher suite.
type Strength string

const (
	StrengthUnknown     Strength = ""
	StrengthInsecure    Strength = "insecure"
	StrengthWeak        Strength = "weak"
	StrengthSecure      Strength = "secure"
	StrengthRecommended Strength = "recommended"
)

// CipherInfo holds static metadata about a TLS cipher suite.
type CipherInfo struct {
	ID             uint16
	Name           string
	KeyExchange    string
	Authentication string
	Encryption     string
	MAC            string
	KeyBits        int
	ForwardSecrecy bool
	Strength       Strength
}

// cipherTable maps IANA cipher suite IDs to their metadata.
// The table is verbatim from the uptime security extension (33 entries).
var cipherTable = map[uint16]CipherInfo{
	// ── TLS 1.3 suites (implicit ECDHE, AEAD, always FS) ────────────────────
	0x1301: {
		ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", KeyExchange: "any", Authentication: "any",
		Encryption: "AES-128-GCM", MAC: "AEAD", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},
	0x1302: {
		ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", KeyExchange: "any", Authentication: "any",
		Encryption: "AES-256-GCM", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},
	0x1303: {
		ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", KeyExchange: "any", Authentication: "any",
		Encryption: "CHACHA20-POLY1305", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},

	// ── ECDHE + ECDSA, AEAD ─────────────────────────────────────────────────
	0xc02b: {
		ID: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "AES-128-GCM", MAC: "AEAD", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},
	0xc02c: {
		ID: 0xc02c, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "AES-256-GCM", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},
	0xcca9: {
		ID: 0xcca9, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "CHACHA20-POLY1305", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},

	// ── ECDHE + RSA, AEAD ───────────────────────────────────────────────────
	0xc02f: {
		ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "AES-128-GCM", MAC: "AEAD", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},
	0xc030: {
		ID: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "AES-256-GCM", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},
	0xcca8: {
		ID: 0xcca8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "CHACHA20-POLY1305", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthRecommended,
	},

	// ── ECDHE + ECDSA, CBC ──────────────────────────────────────────────────
	0xc009: {
		ID: 0xc009, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "AES-128-CBC", MAC: "SHA", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},
	0xc00a: {
		ID: 0xc00a, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "AES-256-CBC", MAC: "SHA", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},
	0xc023: {
		ID: 0xc023, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "AES-128-CBC", MAC: "SHA256", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},
	0xc024: {
		ID: 0xc024, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "AES-256-CBC", MAC: "SHA384", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},

	// ── ECDHE + RSA, CBC ────────────────────────────────────────────────────
	0xc013: {
		ID: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "AES-128-CBC", MAC: "SHA", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},
	0xc014: {
		ID: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "AES-256-CBC", MAC: "SHA", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},
	0xc027: {
		ID: 0xc027, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "AES-128-CBC", MAC: "SHA256", KeyBits: 128,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},
	0xc028: {
		ID: 0xc028, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "AES-256-CBC", MAC: "SHA384", KeyBits: 256,
		ForwardSecrecy: true, Strength: StrengthSecure,
	},

	// ── RSA key-exchange, AEAD (no FS) ──────────────────────────────────────
	0x009c: {
		ID: 0x009c, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "AES-128-GCM", MAC: "AEAD", KeyBits: 128,
		ForwardSecrecy: false, Strength: StrengthWeak,
	},
	0x009d: {
		ID: 0x009d, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "AES-256-GCM", MAC: "AEAD", KeyBits: 256,
		ForwardSecrecy: false, Strength: StrengthWeak,
	},

	// ── RSA key-exchange, CBC (no FS) ────────────────────────────────────────
	0x002f: {
		ID: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "AES-128-CBC", MAC: "SHA", KeyBits: 128,
		ForwardSecrecy: false, Strength: StrengthWeak,
	},
	0x0035: {
		ID: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "AES-256-CBC", MAC: "SHA", KeyBits: 256,
		ForwardSecrecy: false, Strength: StrengthWeak,
	},
	0x003c: {
		ID: 0x003c, Name: "TLS_RSA_WITH_AES_128_CBC_SHA256", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "AES-128-CBC", MAC: "SHA256", KeyBits: 128,
		ForwardSecrecy: false, Strength: StrengthWeak,
	},
	0x003d: {
		ID: 0x003d, Name: "TLS_RSA_WITH_AES_256_CBC_SHA256", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "AES-256-CBC", MAC: "SHA256", KeyBits: 256,
		ForwardSecrecy: false, Strength: StrengthWeak,
	},

	// ── Legacy / insecure ────────────────────────────────────────────────────
	0x0005: {
		ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "RC4-128", MAC: "SHA", KeyBits: 128,
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
	0x0004: {
		ID: 0x0004, Name: "TLS_RSA_WITH_RC4_128_MD5", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "RC4-128", MAC: "MD5", KeyBits: 128,
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
	0x000a: {
		ID: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: "RSA", Authentication: "RSA",
		Encryption: "3DES-EDE-CBC", MAC: "SHA", KeyBits: 112,
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
	0xc011: {
		ID: 0xc011, Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "RC4-128", MAC: "SHA", KeyBits: 128,
		// RC4 is broken regardless of key exchange
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
	0xc012: {
		ID: 0xc012, Name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: "ECDHE", Authentication: "RSA",
		Encryption: "3DES-EDE-CBC", MAC: "SHA", KeyBits: 112,
		// 3DES is insecure (SWEET32) regardless of key exchange
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
	0xc007: {
		ID: 0xc007, Name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "RC4-128", MAC: "SHA", KeyBits: 128,
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
	0xc008: {
		ID: 0xc008, Name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: "ECDHE", Authentication: "ECDSA",
		Encryption: "3DES-EDE-CBC", MAC: "SHA", KeyBits: 112,
		ForwardSecrecy: false, Strength: StrengthInsecure,
	},
}

// ClassifyCipher returns metadata for a cipher suite ID.
// For unknown IDs it returns a conservative default using crypto/tls for the name.
func ClassifyCipher(id uint16) CipherInfo {
	if info, ok := cipherTable[id]; ok {
		return info
	}
	// Unknown cipher: fall back to the crypto/tls name and assume weak/no-FS.
	return CipherInfo{
		ID:             id,
		Name:           tls.CipherSuiteName(id),
		Strength:       StrengthWeak,
		ForwardSecrecy: false,
	}
}
