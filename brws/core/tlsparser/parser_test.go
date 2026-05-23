package tlsparser_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/core/tlsparser"
)

func TestParseClientHello_tooShort(t *testing.T) {
	_, err := tlsparser.ParseClientHello([]byte{0x16, 0x03})
	if err == nil {
		t.Error("expected error for data too short")
	}
}

func TestParseClientHello_wrongContentType(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x17 // application data, not handshake
	data[1] = 0x03
	data[2] = 0x03
	_, err := tlsparser.ParseClientHello(data)
	if err == nil {
		t.Error("expected error for wrong content type")
	}
}

func TestParseClientHello_incompleteRecord(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x16 // handshake
	data[1] = 0x03
	data[2] = 0x03
	data[3] = 0x01 // length = 256, but we only have 5 bytes total
	data[4] = 0x00
	_, err := tlsparser.ParseClientHello(data)
	if err == nil {
		t.Error("expected error for incomplete record")
	}
}

func TestIsGREASE(t *testing.T) {
	// GREASE values follow the pattern 0x?A?A
	greaseValues := []uint16{
		0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
		0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
		0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
	}
	for _, v := range greaseValues {
		if !tlsparser.IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04X) = false, want true", v)
		}
	}
}

func TestIsGREASE_nonGrease(t *testing.T) {
	nonGrease := []uint16{
		0x0035, 0x002F, 0x009C, 0x1301, 0x1302,
	}
	for _, v := range nonGrease {
		if tlsparser.IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04X) = true, want false", v)
		}
	}
}

func TestClientHello_ToFingerprint_empty(t *testing.T) {
	ch := &tlsparser.ClientHello{}
	fp := ch.ToFingerprint()
	if fp == nil {
		t.Fatal("ToFingerprint returned nil for empty ClientHello")
	}
}

func TestClientHello_ToFingerprint_withCiphers(t *testing.T) {
	ch := &tlsparser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0x0035},
		Extensions: []tlsparser.Extension{
			{Type: 0x0000, Length: 0}, // server_name
			{Type: 0x000A, Length: 0}, // supported_groups
		},
		SupportedGroups:     []uint16{0x001D, 0x0017},
		SignatureAlgorithms:  []uint16{0x0403, 0x0804},
		ALPNProtocols:        []string{"h2", "http/1.1"},
	}
	fp := ch.ToFingerprint()
	if fp == nil {
		t.Fatal("ToFingerprint returned nil")
	}
	if len(fp.CipherSuites) == 0 {
		t.Error("CipherSuites should not be empty")
	}
}

func TestClientHello_ToFingerprint_hasJA3(t *testing.T) {
	ch := &tlsparser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions: []tlsparser.Extension{
			{Type: 0x000A, Length: 0},
		},
		SupportedGroups:    []uint16{0x001D},
		SignatureAlgorithms: []uint16{0x0403},
	}
	fp := ch.ToFingerprint()
	if fp == nil {
		t.Fatal("ToFingerprint returned nil")
	}
	if fp.JA3Hash == "" {
		t.Error("JA3Hash should not be empty")
	}
}

func TestTLSRecord_structure(t *testing.T) {
	record := tlsparser.TLSRecord{
		ContentType: 0x16,
		Version:     0x0303,
		Length:      100,
		Data:        make([]byte, 100),
	}
	if record.ContentType != 0x16 {
		t.Errorf("ContentType = 0x%02X, want 0x16", record.ContentType)
	}
	if record.Version != 0x0303 {
		t.Errorf("Version = 0x%04X, want 0x0303", record.Version)
	}
}

func TestExtension_structure(t *testing.T) {
	ext := tlsparser.Extension{
		Type:   0x0000,
		Length: 10,
		Data:   make([]byte, 10),
	}
	if ext.Type != 0x0000 {
		t.Errorf("Type = 0x%04X, want 0x0000", ext.Type)
	}
}

func TestGREASEValue_structure(t *testing.T) {
	gv := tlsparser.GREASEValue{
		Value:    0x0A0A,
		Position: 3,
		Context:  "cipher",
	}
	if gv.Value != 0x0A0A {
		t.Errorf("Value = 0x%04X, want 0x0A0A", gv.Value)
	}
	if gv.Context != "cipher" {
		t.Errorf("Context = %q, want cipher", gv.Context)
	}
}

func TestClientHello_ToFingerprint_greaseFiltered(t *testing.T) {
	ch := &tlsparser.ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x0A0A, 0x1301}, // first is GREASE
		GREASEValues: []tlsparser.GREASEValue{
			{Value: 0x0A0A, Position: 0, Context: "cipher"},
		},
	}
	fp := ch.ToFingerprint()
	if fp == nil {
		t.Fatal("ToFingerprint returned nil")
	}
	if len(fp.GREASE) == 0 {
		t.Error("GREASE slice should be populated when GREASE values are present")
	}
}
