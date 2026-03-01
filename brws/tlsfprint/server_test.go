package tlsfprint

import (
	"testing"
)

//nolint:staticcheck // SA5011: Test validation
func TestServerFingerprintAnalyzer(t *testing.T) {
	t.Run("creates analyzer", func(t *testing.T) {
		analyzer := NewServerFingerprintAnalyzer()
		if analyzer == nil {
			t.Error("expected non-nil analyzer")
		}
		//nolint:staticcheck // SA5011: Test validation
		if len(analyzer.observations) != 0 {
			t.Error("expected empty observations")
		}
	})

	t.Run("records server hello", func(t *testing.T) {
		analyzer := NewServerFingerprintAnalyzer()
		sh := &ServerHelloInfo{
			Version:     0x0303,
			CipherSuite: 0xc02f,
		}
		analyzer.RecordServerHello("example.com", sh)

		stats := analyzer.GetStats()
		if stats.TotalConnections != 1 {
			t.Errorf("expected 1 connection, got %d", stats.TotalConnections)
		}
	})

	t.Run("gets observations", func(t *testing.T) {
		analyzer := NewServerFingerprintAnalyzer()
		sh := &ServerHelloInfo{
			Version:     0x0303,
			CipherSuite: 0xc02f,
		}
		analyzer.RecordServerHello("example.com", sh)

		obs := analyzer.GetObservations()
		if len(obs) != 1 {
			t.Errorf("expected 1 observation, got %d", len(obs))
		}
	})
}

func TestServerSignatureDatabase(t *testing.T) {
	t.Run("creates database with defaults", func(t *testing.T) {
		db := NewServerSignatureDatabase()
		//nolint:staticcheck // SA5011: Test validation
		if db == nil {
			t.Error("expected non-nil database")
		}
		//nolint:staticcheck // SA5011: Test validation
		if len(db.signatures) == 0 {
			t.Error("expected default signatures")
		}
	})

	t.Run("registers signature", func(t *testing.T) {
		db := NewServerSignatureDatabase()
		sig := ServerSignature{
			Name:         "custom-server",
			TLSVersions:  []uint16{0x0303},
			CipherSuites: []uint16{0x002f},
		}
		db.Register(sig)

		if db.signatures["custom-server"].Name != "custom-server" {
			t.Error("expected signature to be registered")
		}
	})

	t.Run("identifies server", func(t *testing.T) {
		db := NewServerSignatureDatabase()
		fp := &ServerTLSFingerprint{
			TLSVersion:  0x0304,
			CipherSuite: 0xc02f,
			ALPN:        []string{"h2"},
		}

		name, score := db.Identify(fp)
		if name == "" {
			t.Error("expected server to be identified")
		}
		if score < 0 || score > 1 {
			t.Errorf("expected score between 0 and 1, got %f", score)
		}
	})
}

func TestServerPreferenceAnalyzer(t *testing.T) {
	t.Run("creates analyzer", func(t *testing.T) {
		analyzer := NewServerPreferenceAnalyzer()
		if analyzer == nil {
			t.Error("expected non-nil analyzer")
		}
	})

	t.Run("gets server preference", func(t *testing.T) {
		analyzer := NewServerPreferenceAnalyzer()
		ch := &ClientHelloInfo{
			CipherSuites: []uint16{0x002f, 0x0035},
		}
		analyzer.RecordClientHello(ch)

		sh := &ServerHelloInfo{
			CipherSuite: 0x002f,
		}
		analyzer.RecordServerHello(sh)

		pref := analyzer.GetServerPreference()
		if pref != "client" {
			t.Errorf("expected client preference, got %s", pref)
		}
	})

	t.Run("gets preference order", func(t *testing.T) {
		analyzer := NewServerPreferenceAnalyzer()
		ch := &ClientHelloInfo{
			CipherSuites: []uint16{0x002f, 0x0035, 0xc02f},
		}
		analyzer.RecordClientHello(ch)

		sh := &ServerHelloInfo{
			CipherSuite: 0xc02f,
		}
		analyzer.RecordServerHello(sh)

		order := analyzer.GetPreferenceOrder()
		if order != 2 {
			t.Errorf("expected order 2, got %d", order)
		}
	})

	t.Run("detects resumption", func(t *testing.T) {
		analyzer := NewServerPreferenceAnalyzer()
		ch := &ClientHelloInfo{
			SessionID: []byte("session123"),
		}
		analyzer.RecordClientHello(ch)

		sh := &ServerHelloInfo{
			SessionID: []byte("session123"),
		}
		analyzer.RecordServerHello(sh)

		if !analyzer.IsResumed() {
			t.Error("expected session resumption detected")
		}
	})
}

func TestServerHelloCollector(t *testing.T) {
	t.Run("creates collector", func(t *testing.T) {
		collector := NewServerHelloCollector(100)
		if collector == nil {
			t.Error("expected non-nil collector")
		}
	})

	t.Run("records server hello", func(t *testing.T) {
		collector := NewServerHelloCollector(100)
		sh := &ServerHelloInfo{
			Version:     0x0303,
			CipherSuite: 0xc02f,
		}
		collector.Record("trace-1", sh)

		retrieved := collector.Get("trace-1")
		if retrieved == nil {
			t.Error("expected to retrieve server hello")
		}
	})

	t.Run("gets all server hellos", func(t *testing.T) {
		collector := NewServerHelloCollector(100)
		sh := &ServerHelloInfo{Version: 0x0303}
		collector.Record("trace-1", sh)
		collector.Record("trace-2", sh)

		all := collector.GetAll()
		if len(all) != 2 {
			t.Errorf("expected 2 server hellos, got %d", len(all))
		}
	})
}

func TestServerFingerprintExporter(t *testing.T) {
	t.Run("exports summary", func(t *testing.T) {
		analyzer := NewServerFingerprintAnalyzer()
		sh := &ServerHelloInfo{
			Version:     0x0303,
			CipherSuite: 0xc02f,
		}
		analyzer.RecordServerHello("example.com", sh)

		exporter := NewServerFingerprintExporter(analyzer)
		summary := exporter.ExportSummary()

		if summary.TotalConnections != 1 {
			t.Errorf("expected 1 connection, got %d", summary.TotalConnections)
		}
	})
}

func TestContainsFunctions(t *testing.T) {
	t.Run("contains uint16", func(t *testing.T) {
		if !containsUint16(0x002f, []uint16{0x002f, 0x0035}) {
			t.Error("expected to find element")
		}
		if containsUint16(0xc02f, []uint16{0x002f, 0x0035}) {
			t.Error("expected not to find element")
		}
	})

	t.Run("contains string", func(t *testing.T) {
		if !containsString([]string{"h2"}, []string{"h2", "http/1.1"}) {
			t.Error("expected to find string")
		}
	})
}
