package tlsfprint

import (
	"testing"
)

func TestPSKFingerprint(t *testing.T) {
	t.Run("analyzes client hello with PSK", func(t *testing.T) {
		ch := &ClientHelloInfo{
			CipherSuites:   []uint16{0x002f},
			ExtensionsList: []uint16{41, 35},
		}
		fp := AnalyzePSK(ch)
		if !fp.HasPSK {
			t.Error("expected PSK to be detected")
		}
		if !fp.EarlyDataAllowed {
			t.Error("expected early data to be allowed")
		}
	})

	t.Run("analyzes client hello without PSK", func(t *testing.T) {
		ch := &ClientHelloInfo{
			CipherSuites:   []uint16{0x002f},
			ExtensionsList: []uint16{0, 1},
		}
		fp := AnalyzePSK(ch)
		if fp.HasPSK {
			t.Error("expected no PSK to be detected")
		}
	})
}

func TestPSKFingerprintToString(t *testing.T) {
	t.Run("converts to string", func(t *testing.T) {
		fp := &PSKFingerprint{
			HasPSK:           true,
			PSKMode:          "psk_dhe_ke",
			PSKCount:         1,
			EarlyDataAllowed: true,
		}
		str := fp.ToString()
		if str == "" {
			t.Error("expected non-empty string")
		}
	})
}

func TestPSKSession(t *testing.T) {
	t.Run("creates session", func(t *testing.T) {
		session := NewPSKSession("external")
		if session.Identity != "external" {
			t.Errorf("expected identity external, got %s", session.Identity)
		}
		if !session.IsUsable() {
			t.Error("expected session to be usable")
		}
	})

	t.Run("marks used", func(t *testing.T) {
		session := NewPSKSession("external")
		session.MarkUsed()
		if session.UsesRemaining != 0 {
			t.Errorf("expected 0 uses remaining, got %d", session.UsesRemaining)
		}
	})
}

func TestPSKStore(t *testing.T) {
	t.Run("creates store", func(t *testing.T) {
		store := NewPSKStore()
		if store == nil {
			t.Error("expected non-nil store")
		}
	})

	t.Run("adds and gets session", func(t *testing.T) {
		store := NewPSKStore()
		session := NewPSKSession("external")
		store.AddSession("external", session)

		retrieved := store.GetSession("external")
		if retrieved == nil {
			t.Error("expected to retrieve session")
		}
	})

	t.Run("removes session", func(t *testing.T) {
		store := NewPSKStore()
		session := NewPSKSession("external")
		store.AddSession("external", session)

		store.RemoveSession("external")
		if store.GetSession("external") != nil {
			t.Error("expected session to be removed")
		}
	})

	t.Run("gets usable sessions", func(t *testing.T) {
		store := NewPSKStore()
		session := NewPSKSession("external")
		store.AddSession("external", session)

		usable := store.GetUsableSessions()
		if len(usable) != 1 {
			t.Errorf("expected 1 usable session, got %d", len(usable))
		}
	})
}

func TestPSKAnalyzer(t *testing.T) {
	t.Run("creates analyzer", func(t *testing.T) {
		analyzer := NewPSKAnalyzer()
		if analyzer == nil {
			t.Error("expected non-nil analyzer")
		}
	})

	t.Run("records client hello", func(t *testing.T) {
		analyzer := NewPSKAnalyzer()
		ch := &ClientHelloInfo{
			CipherSuites:   []uint16{0x002f},
			ExtensionsList: []uint16{41},
		}
		analyzer.Record(ch)

		stats := analyzer.GetStats()
		if stats.TotalConnections != 1 {
			t.Errorf("expected 1 connection, got %d", stats.TotalConnections)
		}
	})
}

func TestPSKCompatibilityChecker(t *testing.T) {
	t.Run("has compatible PSK", func(t *testing.T) {
		checker := NewPSKCompatibilityChecker()
		checker.SetClientIdentities([]string{"external", "resumption"})
		checker.SetServerIdentities([]string{"external"})

		if !checker.HasCompatiblePSK() {
			t.Error("expected compatible PSK")
		}
	})

	t.Run("no compatible PSK", func(t *testing.T) {
		checker := NewPSKCompatibilityChecker()
		checker.SetClientIdentities([]string{"external"})
		checker.SetServerIdentities([]string{"resumption"})

		if checker.HasCompatiblePSK() {
			t.Error("expected no compatible PSK")
		}
	})

	t.Run("gets matching identities", func(t *testing.T) {
		checker := NewPSKCompatibilityChecker()
		checker.SetClientIdentities([]string{"external", "resumption"})
		checker.SetServerIdentities([]string{"external"})

		matches := checker.GetMatchingIdentities()
		if len(matches) != 1 || matches[0] != "external" {
			t.Errorf("expected [external], got %v", matches)
		}
	})
}

func TestZeroRTTAnalyzer(t *testing.T) {
	t.Run("creates analyzer", func(t *testing.T) {
		analyzer := NewZeroRTTAnalyzer()
		if analyzer == nil {
			t.Error("expected non-nil analyzer")
		}
	})

	t.Run("records early data", func(t *testing.T) {
		analyzer := NewZeroRTTAnalyzer()
		analyzer.Record(true, 1024)

		stats := analyzer.GetStats()
		if stats.SuccessfulCount != 1 {
			t.Errorf("expected 1 successful, got %d", stats.SuccessfulCount)
		}
		if stats.TotalBytes != 1024 {
			t.Errorf("expected 1024 bytes, got %d", stats.TotalBytes)
		}
	})

	t.Run("records retry", func(t *testing.T) {
		analyzer := NewZeroRTTAnalyzer()
		analyzer.Record(true, 1024)
		analyzer.RecordRetry()

		stats := analyzer.GetStats()
		if stats.RetryCount != 1 {
			t.Errorf("expected 1 retry, got %d", stats.RetryCount)
		}
	})

	t.Run("calculates success rate", func(t *testing.T) {
		analyzer := NewZeroRTTAnalyzer()
		analyzer.Record(true, 100)
		analyzer.Record(true, 200)
		analyzer.Record(false, 0)

		stats := analyzer.GetStats()
		if stats.SuccessRate != 0.6666666666666666 {
			t.Errorf("expected ~0.67 success rate, got %f", stats.SuccessRate)
		}
	})
}

func TestZeroRTTStatsToString(t *testing.T) {
	t.Run("converts to string", func(t *testing.T) {
		stats := &ZeroRTTStats{
			TotalAttempts:   10,
			SuccessfulCount: 8,
			RetryCount:      1,
			SuccessRate:     0.8,
		}
		str := stats.ToString()
		if str == "" {
			t.Error("expected non-empty string")
		}
	})
}
