package tlsfprint

import (
	"crypto/x509"
	"testing"
)

func TestCertificateFingerprintBasic(t *testing.T) {
	t.Run("creates empty fingerprint", func(t *testing.T) {
		fp := &CertificateFingerprint{
			SPKIHash: "abc123",
			Subject:  "test.example.com",
			Issuer:   "DigiCert",
		}
		if fp.SPKIHash != "abc123" {
			t.Errorf("expected SPKIHash abc123, got %s", fp.SPKIHash)
		}
	})
}

func TestCertificateFingerprintToJA3C(t *testing.T) {
	t.Run("converts to JA3C format", func(t *testing.T) {
		fp := &CertificateFingerprint{
			SPKIHash:     "abc123def456ghi789",
			Subject:      "test.example.com",
			Issuer:       "DigiCert",
			SerialNumber: "1234567890",
		}
		ja3c := fp.ToJA3C()
		if ja3c == "" {
			t.Error("expected non-empty JA3C")
		}
	})
}

func TestCertificateFingerprintValid(t *testing.T) {
	t.Run("valid certificate", func(t *testing.T) {
		fp := &CertificateFingerprint{
			NotBefore: 0,
			NotAfter:  253402300799,
		}
		if !fp.Valid() {
			t.Error("expected certificate to be valid")
		}
	})
}

func TestCertificateFingerprintExpired(t *testing.T) {
	t.Run("expired certificate", func(t *testing.T) {
		fp := &CertificateFingerprint{
			NotAfter: -1,
		}
		if !fp.IsExpired() {
			t.Error("expected certificate to be expired")
		}
	})
}

func TestCertificateChain(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		chain := &CertificateChain{
			Chain: make([]CertificateFingerprint, 0),
		}
		if chain.GetLeaf() != nil {
			t.Error("expected nil leaf for empty chain")
		}
		if chain.GetRoot() != nil {
			t.Error("expected nil root for empty chain")
		}
		if chain.IsValid() {
			t.Error("expected empty chain to be invalid")
		}
	})

	t.Run("chain depth", func(t *testing.T) {
		chain := &CertificateChain{
			Chain: []CertificateFingerprint{
				{Subject: "leaf", NotBefore: 0, NotAfter: 253402300799},
				{Subject: "intermediate", NotBefore: 0, NotAfter: 253402300799},
				{Subject: "root", IsCA: true, NotBefore: 0, NotAfter: 253402300799},
			},
		}
		chain.Depth = len(chain.Chain)
		if chain.Depth != 3 {
			t.Errorf("expected depth 3, got %d", chain.Depth)
		}
		if chain.GetLeaf() == nil || chain.GetLeaf().Subject != "leaf" {
			t.Error("expected leaf certificate")
		}
		if chain.GetRoot() == nil || chain.GetRoot().Subject != "root" {
			t.Error("expected root certificate")
		}
	})
}

func TestCertificateChainToSPKIList(t *testing.T) {
	t.Run("converts chain to SPKI list", func(t *testing.T) {
		chain := &CertificateChain{
			Chain: []CertificateFingerprint{
				{SPKIHash: "abc123def456ghi789"},
				{SPKIHash: "xyz789uvw012abc345"},
			},
		}
		list := chain.ToSPKIList()
		if len(list) != 2 {
			t.Errorf("expected 2 items, got %d", len(list))
		}
	})
}

func TestCertificateComparator(t *testing.T) {
	t.Run("matching certificates", func(t *testing.T) {
		cert := &CertificateFingerprint{SPKIHash: "abc123"}
		comp := NewCertificateComparator(cert, cert)
		if !comp.Compare() {
			t.Error("expected certificates to match")
		}
	})

	t.Run("non-matching certificates", func(t *testing.T) {
		obs := &CertificateFingerprint{SPKIHash: "abc123"}
		exp := &CertificateFingerprint{SPKIHash: "xyz789"}
		comp := NewCertificateComparator(obs, exp)
		if comp.Compare() {
			t.Error("expected certificates to not match")
		}
	})

	t.Run("nil comparison", func(t *testing.T) {
		comp := NewCertificateComparator(nil, nil)
		if comp.Compare() {
			t.Error("expected false for nil comparison")
		}
	})
}

func TestCertificateMatcher(t *testing.T) {
	t.Run("registers and matches", func(t *testing.T) {
		matcher := NewCertificateMatcher()
		matcher.Register("abc123def456ghi789", "DigiCert")

		cert := &CertificateFingerprint{SPKIHash: "abc123def456ghi789012"}
		name, ok := matcher.Match(cert)
		if !ok {
			t.Error("expected match")
		}
		if name != "DigiCert" {
			t.Errorf("expected DigiCert, got %s", name)
		}
	})

	t.Run("no match", func(t *testing.T) {
		matcher := NewCertificateMatcher()
		cert := &CertificateFingerprint{SPKIHash: "unknown1234567890123456"}
		_, ok := matcher.Match(cert)
		if ok {
			t.Error("expected no match")
		}
	})
}

func TestKeyUsageToStrings(t *testing.T) {
	t.Run("digital signature", func(t *testing.T) {
		usages := keyUsageToStrings(x509.KeyUsageDigitalSignature)
		if len(usages) == 0 {
			t.Error("expected non-empty usages")
		}
	})
}

func TestExtKeyUsageToStrings(t *testing.T) {
	t.Run("empty ext key usage", func(t *testing.T) {
		usages := extKeyUsageToStrings(nil)
		if usages != nil {
			t.Error("expected nil usages for nil input")
		}
	})
}
