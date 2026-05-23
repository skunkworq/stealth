package tlsfprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func makeObservation(tlsVer uint16, cipher uint16, alpn string, grease bool) *TLSObservation {
	return &TLSObservation{
		Timestamp:      time.Now(),
		ConnectionID:   "test-conn-1",
		RemoteAddr:     "127.0.0.1:443",
		TLSVersion:     tlsVer,
		CipherSuite:    cipher,
		ServerName:     "example.com",
		ALPN:           alpn,
		CipherOrder:    []uint16{0x1301, 0xc02b, 0xc02f},
		ExtensionOrder: []uint16{0x0000, 0x000a, 0x0010},
		GREASEFound:    grease,
		GREASECount:    0,
		KeyShareGroups: []uint16{0x001d},
		SignatureAlgs:  []uint16{0x0403},
		SupportedVers:  []uint16{0x0304},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NewTLSObserver
// ─────────────────────────────────────────────────────────────────────────────

func TestNewTLSObserver_NilConfig(t *testing.T) {
	obs := NewTLSObserver(nil)
	if obs == nil {
		t.Fatal("NewTLSObserver(nil) returned nil")
	}
}

func TestNewTLSObserver_CustomConfig(t *testing.T) {
	cfg := &ObserverConfig{
		Enabled:         true,
		MaxObservations: 5,
	}
	obs := NewTLSObserver(cfg)
	if obs == nil {
		t.Fatal("NewTLSObserver(config) returned nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Record / GetObservations
// ─────────────────────────────────────────────────────────────────────────────

func TestTLSObserver_Record_Single(t *testing.T) {
	obs := NewTLSObserver(nil)
	obs.Record(makeObservation(0x0303, 0x1301, "h2", false))
	got := obs.GetObservations()
	if len(got) != 1 {
		t.Errorf("expected 1 observation, got %d", len(got))
	}
}

func TestTLSObserver_Record_Disabled(t *testing.T) {
	cfg := &ObserverConfig{Enabled: false, MaxObservations: 100}
	obs := NewTLSObserver(cfg)
	obs.Record(makeObservation(0x0303, 0x1301, "h2", false))
	if len(obs.GetObservations()) != 0 {
		t.Error("disabled observer should not record observations")
	}
}

func TestTLSObserver_Record_MaxBound(t *testing.T) {
	cfg := &ObserverConfig{Enabled: true, MaxObservations: 3}
	obs := NewTLSObserver(cfg)
	for i := 0; i < 5; i++ {
		obs.Record(makeObservation(0x0303, 0x1301, "h2", false))
	}
	got := obs.GetObservations()
	if len(got) > 3 {
		t.Errorf("observer should cap at MaxObservations=3, got %d", len(got))
	}
}

func TestTLSObserver_GetObservations_Empty(t *testing.T) {
	obs := NewTLSObserver(nil)
	got := obs.GetObservations()
	if got == nil {
		t.Error("GetObservations() on empty observer should return non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("empty observer should have 0 observations, got %d", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetStats
// ─────────────────────────────────────────────────────────────────────────────

func TestTLSObserver_GetStats_Initial(t *testing.T) {
	obs := NewTLSObserver(nil)
	stats := obs.GetStats()
	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}
	if stats.TotalObservations != 0 {
		t.Errorf("initial TotalObservations = %d, want 0", stats.TotalObservations)
	}
}

func TestTLSObserver_GetStats_UniqueJA4Tracking(t *testing.T) {
	obs := NewTLSObserver(nil)
	// Record two observations with same cipher/version → same JA4 → UniqueJA4 = 1
	obs.Record(makeObservation(0x0304, 0x1301, "h2", false))
	obs.Record(makeObservation(0x0304, 0x1301, "h2", false))
	stats := obs.GetStats()
	if stats.UniqueJA4 != 1 {
		t.Errorf("UniqueJA4 = %d, want 1 for identical observations", stats.UniqueJA4)
	}
	if stats.TotalObservations != 2 {
		t.Errorf("TotalObservations = %d, want 2", stats.TotalObservations)
	}
}

func TestTLSObserver_GetStats_GREASEFrequency(t *testing.T) {
	obs := NewTLSObserver(nil)
	obs.Record(makeObservation(0x0303, 0x1301, "h2", true))  // grease
	obs.Record(makeObservation(0x0303, 0x1301, "h2", false)) // no grease
	stats := obs.GetStats()
	// 1 grease out of 2 = 0.5
	if stats.GREASEFrequency != 0.5 {
		t.Errorf("GREASEFrequency = %f, want 0.5", stats.GREASEFrequency)
	}
}

func TestTLSObserver_GetStats_MapsNotNil(t *testing.T) {
	obs := NewTLSObserver(nil)
	stats := obs.GetStats()
	if stats.ByTLSVersion == nil {
		t.Error("ByTLSVersion map should not be nil")
	}
	if stats.ByCipherSuite == nil {
		t.Error("ByCipherSuite map should not be nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TLSObservation.ToJA3 / ToJA4
// ─────────────────────────────────────────────────────────────────────────────

func TestTLSObservation_ToJA3_Format(t *testing.T) {
	o := makeObservation(0x0303, 0x1301, "h2", false)
	ja3 := o.ToJA3()
	if ja3 == "" {
		t.Fatal("ToJA3() returned empty string")
	}
	// JA3 format: version,ciphers,extensions
	parts := strings.Split(ja3, ",")
	if len(parts) != 3 {
		t.Errorf("JA3 should have 3 comma-separated parts, got %d: %q", len(parts), ja3)
	}
}

func TestTLSObservation_ToJA4_TLS13(t *testing.T) {
	o := makeObservation(0x0304, 0xc02b, "h2", false)
	ja4 := o.ToJA4()
	if !strings.HasPrefix(ja4, "t13") {
		t.Errorf("TLS 1.3 JA4 should start with 't13', got %q", ja4)
	}
}

func TestTLSObservation_ToJA4_TLS12(t *testing.T) {
	o := makeObservation(0x0303, 0xc02b, "http/1.1", false)
	ja4 := o.ToJA4()
	if !strings.HasPrefix(ja4, "t12") {
		t.Errorf("TLS 1.2 JA4 should start with 't12', got %q", ja4)
	}
}

func TestTLSObservation_ToJA4_GREASE_Suffix(t *testing.T) {
	o := makeObservation(0x0304, 0x1301, "h2", true)
	ja4 := o.ToJA4()
	if !strings.HasSuffix(ja4, "d") {
		t.Errorf("GREASE JA4 should end with 'd', got %q", ja4)
	}
}

func TestTLSObservation_ToJA4_H2_Included(t *testing.T) {
	o := makeObservation(0x0304, 0x1301, "h2", false)
	ja4 := o.ToJA4()
	if !strings.Contains(ja4, "h2") {
		t.Errorf("h2 ALPN JA4 should contain 'h2', got %q", ja4)
	}
}

func TestTLSObservation_ToJA4_NoALPN(t *testing.T) {
	o := makeObservation(0x0304, 0x1301, "http/1.1", false)
	ja4 := o.ToJA4()
	if strings.Contains(ja4, "h2") {
		t.Errorf("non-h2 ALPN JA4 should not contain 'h2', got %q", ja4)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TLSObservation.ToVector
// ─────────────────────────────────────────────────────────────────────────────

func TestTLSObservation_ToVector_NonNil(t *testing.T) {
	o := makeObservation(0x0304, 0x1301, "h2", true)
	v := o.ToVector()
	if v == nil {
		t.Fatal("ToVector() returned nil")
	}
}

func TestTLSObservation_ToVector_Fields(t *testing.T) {
	o := makeObservation(0x0304, 0x1301, "h2", true)
	v := o.ToVector()
	if v.CipherCount != len(o.CipherOrder) {
		t.Errorf("CipherCount = %d, want %d", v.CipherCount, len(o.CipherOrder))
	}
	if !v.ALPNHTTP2 {
		t.Error("ALPNHTTP2 should be true for h2")
	}
	if !v.HasGREASE {
		t.Error("HasGREASE should be true")
	}
	if v.GREASECount != 1 {
		t.Errorf("GREASECount = %d, want 1", v.GREASECount)
	}
}

func TestTLSObservation_ToVector_NoGREASE(t *testing.T) {
	o := makeObservation(0x0303, 0x1301, "http/1.1", false)
	v := o.ToVector()
	if v.HasGREASE {
		t.Error("HasGREASE should be false")
	}
	if v.GREASECount != 0 {
		t.Errorf("GREASECount = %d, want 0", v.GREASECount)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// calculateEntropy
// ─────────────────────────────────────────────────────────────────────────────

func TestCalculateEntropy_Empty(t *testing.T) {
	e := calculateEntropy(nil, nil)
	if e != 0 {
		t.Errorf("entropy of empty = %f, want 0", e)
	}
}

func TestCalculateEntropy_Uniform(t *testing.T) {
	// All identical values → minimum entropy
	ciphers := []uint16{0x1301, 0x1301, 0x1301}
	e := calculateEntropy(ciphers, nil)
	if e != 0 {
		t.Errorf("uniform values should have entropy=0, got %f", e)
	}
}

func TestCalculateEntropy_AllUnique(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	e := calculateEntropy(ciphers, nil)
	// 3 unique values, p=1/3 each → entropy = log2(3) ≈ 1.585
	if e <= 1.0 {
		t.Errorf("all-unique entropy should be > 1.0, got %f", e)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FingerprintComparator
// ─────────────────────────────────────────────────────────────────────────────

func TestNewFingerprintComparator_NonNil(t *testing.T) {
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	exp := makeObservation(0x0303, 0x1301, "h2", false)
	cmp := NewFingerprintComparator(obs, exp)
	if cmp == nil {
		t.Fatal("NewFingerprintComparator returned nil")
	}
}

func TestFingerprintComparator_Compare_Identical(t *testing.T) {
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	exp := makeObservation(0x0303, 0x1301, "h2", false)
	// Make both have same cipher/extension order
	exp.CipherOrder = []uint16{0x1301, 0xc02b, 0xc02f}
	exp.ExtensionOrder = []uint16{0x0000, 0x000a, 0x0010}
	cmp := NewFingerprintComparator(obs, exp)
	diffs := cmp.Compare()
	if len(diffs) != 0 {
		t.Errorf("identical observations should have 0 diffs, got %d: %v", len(diffs), diffs)
	}
}

func TestFingerprintComparator_Compare_VersionMismatch(t *testing.T) {
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	exp := makeObservation(0x0304, 0x1301, "h2", false)
	cmp := NewFingerprintComparator(obs, exp)
	diffs := cmp.Compare()
	hasTLSVersionDiff := false
	for _, d := range diffs {
		if d.Field == "TLS Version" {
			hasTLSVersionDiff = true
		}
	}
	if !hasTLSVersionDiff {
		t.Error("version mismatch should produce a TLS Version diff")
	}
}

func TestFingerprintComparator_TotalScore_ZeroForIdentical(t *testing.T) {
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	exp := makeObservation(0x0303, 0x1301, "h2", false)
	exp.CipherOrder = []uint16{0x1301, 0xc02b, 0xc02f}
	exp.ExtensionOrder = []uint16{0x0000, 0x000a, 0x0010}
	cmp := NewFingerprintComparator(obs, exp)
	cmp.Compare()
	if cmp.TotalScore() != 0 {
		t.Errorf("TotalScore for identical = %f, want 0", cmp.TotalScore())
	}
}

func TestFingerprintComparator_TotalScore_NonZeroForDiff(t *testing.T) {
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	exp := makeObservation(0x0304, 0xc02b, "http/1.1", true)
	cmp := NewFingerprintComparator(obs, exp)
	cmp.Compare()
	if cmp.TotalScore() == 0 {
		t.Error("mismatched observations should have TotalScore > 0")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtensionPermutator
// ─────────────────────────────────────────────────────────────────────────────

func TestNewExtensionPermutator_NonNil(t *testing.T) {
	p := NewExtensionPermutator(42)
	if p == nil {
		t.Fatal("NewExtensionPermutator returned nil")
	}
}

func TestExtensionPermutator_PermuteChrome_SameLength(t *testing.T) {
	p := NewExtensionPermutator(1)
	exts := []uint16{0x0000, 0x000a, 0x0010, 0x5a5a, 0x0023}
	result := p.PermuteChrome(exts)
	if len(result) != len(exts) {
		t.Errorf("PermuteChrome result length = %d, want %d", len(result), len(exts))
	}
}

func TestExtensionPermutator_PermuteChrome_GREASEFirst(t *testing.T) {
	p := NewExtensionPermutator(1)
	// 0x5a5a is a GREASE value
	exts := []uint16{0x0000, 0x000a, 0x5a5a, 0x0010}
	result := p.PermuteChrome(exts)
	// GREASE should appear before non-GREASE extensions
	greaseIdx := -1
	for i, e := range result {
		if e == 0x5a5a {
			greaseIdx = i
			break
		}
	}
	if greaseIdx == -1 {
		t.Error("GREASE extension 0x5a5a not found in permuted result")
	}
	// All non-GREASE should appear after GREASE
	for _, e := range result[:greaseIdx] {
		if e != 0x5a5a {
			t.Errorf("non-GREASE extension %04x found before GREASE", e)
		}
	}
}

func TestExtensionPermutator_PermuteFirefox_SameLength(t *testing.T) {
	p := NewExtensionPermutator(99)
	exts := []uint16{0x0000, 0x000a, 0x0010, 0x0023, 0x0033}
	result := p.PermuteFirefox(append([]uint16{}, exts...))
	if len(result) != len(exts) {
		t.Errorf("PermuteFirefox result length = %d, want %d", len(result), len(exts))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

func TestNewTimingAnalyzer_NonNil(t *testing.T) {
	a := NewTimingAnalyzer()
	if a == nil {
		t.Fatal("NewTimingAnalyzer() returned nil")
	}
}

func TestTimingAnalyzer_GetStats_Empty(t *testing.T) {
	a := NewTimingAnalyzer()
	stats := a.GetStats()
	if stats == nil {
		t.Fatal("GetStats() on empty analyzer returned nil")
	}
	if stats.Count != 0 {
		t.Errorf("Count = %d, want 0", stats.Count)
	}
}

func TestTimingAnalyzer_GetStats_SingleObservation(t *testing.T) {
	a := NewTimingAnalyzer()
	a.Record(100 * time.Millisecond)
	stats := a.GetStats()
	if stats.Count != 1 {
		t.Errorf("Count = %d, want 1", stats.Count)
	}
	if stats.Min != 100*time.Millisecond {
		t.Errorf("Min = %v, want 100ms", stats.Min)
	}
	if stats.Max != 100*time.Millisecond {
		t.Errorf("Max = %v, want 100ms", stats.Max)
	}
}

func TestTimingAnalyzer_GetStats_MultipleObservations(t *testing.T) {
	a := NewTimingAnalyzer()
	a.Record(10 * time.Millisecond)
	a.Record(20 * time.Millisecond)
	a.Record(30 * time.Millisecond)
	stats := a.GetStats()
	if stats.Count != 3 {
		t.Errorf("Count = %d, want 3", stats.Count)
	}
	if stats.Min != 10*time.Millisecond {
		t.Errorf("Min = %v, want 10ms", stats.Min)
	}
	if stats.Max != 30*time.Millisecond {
		t.Errorf("Max = %v, want 30ms", stats.Max)
	}
	// Mean of 10, 20, 30 = 20ms
	if stats.Mean != 20*time.Millisecond {
		t.Errorf("Mean = %v, want 20ms", stats.Mean)
	}
	// Median of 3 = middle = 20ms
	if stats.Median != 20*time.Millisecond {
		t.Errorf("Median = %v, want 20ms", stats.Median)
	}
}

func TestTimingAnalyzer_GetStats_EvenCount_Median(t *testing.T) {
	a := NewTimingAnalyzer()
	a.Record(10 * time.Millisecond)
	a.Record(20 * time.Millisecond)
	stats := a.GetStats()
	// Median of 2 = (10+20)/2 = 15ms
	if stats.Median != 15*time.Millisecond {
		t.Errorf("Median (even count) = %v, want 15ms", stats.Median)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CaptureStore
// ─────────────────────────────────────────────────────────────────────────────

func TestNewCaptureStore_NonNil(t *testing.T) {
	s := NewCaptureStore(10)
	if s == nil {
		t.Fatal("NewCaptureStore returned nil")
	}
}

func TestNewCaptureStore_DefaultMaxSize(t *testing.T) {
	// maxSize=0 should use default 1000
	s := NewCaptureStore(0)
	if s == nil {
		t.Fatal("NewCaptureStore(0) returned nil")
	}
}

func TestCaptureStore_StoreAndGet(t *testing.T) {
	s := NewCaptureStore(10)
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	capture := &HandshakeCapture{Observation: obs}
	s.Store("conn-1", capture)
	got := s.Get("conn-1")
	if got == nil {
		t.Fatal("Get() returned nil for stored capture")
	}
}

func TestCaptureStore_Get_Missing(t *testing.T) {
	s := NewCaptureStore(10)
	got := s.Get("nonexistent")
	if got != nil {
		t.Error("Get() should return nil for missing key")
	}
}

func TestCaptureStore_GetAll_Empty(t *testing.T) {
	s := NewCaptureStore(10)
	all := s.GetAll()
	if len(all) != 0 {
		t.Errorf("GetAll() on empty store = %d, want 0", len(all))
	}
}

func TestCaptureStore_GetAll_WithItems(t *testing.T) {
	s := NewCaptureStore(10)
	for i := 0; i < 3; i++ {
		obs := makeObservation(0x0303, 0x1301, "h2", false)
		s.Store(string(rune('a'+i)), &HandshakeCapture{Observation: obs})
	}
	all := s.GetAll()
	if len(all) != 3 {
		t.Errorf("GetAll() = %d, want 3", len(all))
	}
}

func TestCaptureStore_MaxSize_Eviction(t *testing.T) {
	s := NewCaptureStore(2)
	for i := 0; i < 4; i++ {
		obs := &TLSObservation{
			Timestamp:   time.Now().Add(time.Duration(i) * time.Second),
			ConnectionID: string(rune('a' + i)),
		}
		s.Store(string(rune('a'+i)), &HandshakeCapture{Observation: obs})
	}
	all := s.GetAll()
	if len(all) > 2 {
		t.Errorf("store should evict old entries, got %d (max 2)", len(all))
	}
}

func TestCaptureStore_Clear(t *testing.T) {
	s := NewCaptureStore(10)
	obs := makeObservation(0x0303, 0x1301, "h2", false)
	s.Store("x", &HandshakeCapture{Observation: obs})
	s.Clear()
	if s.Get("x") != nil {
		t.Error("Get() should return nil after Clear()")
	}
	if len(s.GetAll()) != 0 {
		t.Error("GetAll() should return empty slice after Clear()")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportJSON (writes to temp file)
// ─────────────────────────────────────────────────────────────────────────────

func TestTLSObserver_ExportJSON_NoPanic(t *testing.T) {
	obs := NewTLSObserver(nil)
	obs.Record(makeObservation(0x0303, 0x1301, "h2", false))

	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := obs.ExportJSON(path); err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading exported JSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported JSON file is empty")
	}
}

func TestTLSObserver_ExportCSV_NoPanic(t *testing.T) {
	obs := NewTLSObserver(nil)
	obs.Record(makeObservation(0x0303, 0x1301, "h2", false))

	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	if err := obs.ExportCSV(path); err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading exported CSV: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported CSV file is empty")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// joinStrings helper
// ─────────────────────────────────────────────────────────────────────────────

func TestJoinStrings_Empty(t *testing.T) {
	if joinStrings(nil, "-") != "" {
		t.Error("joinStrings(nil) should return empty string")
	}
}

func TestJoinStrings_Single(t *testing.T) {
	if joinStrings([]string{"a"}, "-") != "a" {
		t.Errorf("joinStrings(single) = %q, want 'a'", joinStrings([]string{"a"}, "-"))
	}
}

func TestJoinStrings_Multiple(t *testing.T) {
	result := joinStrings([]string{"a", "b", "c"}, "-")
	if result != "a-b-c" {
		t.Errorf("joinStrings = %q, want 'a-b-c'", result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// uniqueStrings helper
// ─────────────────────────────────────────────────────────────────────────────

func TestUniqueStrings_Empty(t *testing.T) {
	if len(uniqueStrings(nil)) != 0 {
		t.Error("uniqueStrings(nil) should return empty slice")
	}
}

func TestUniqueStrings_Deduplication(t *testing.T) {
	result := uniqueStrings([]string{"a", "b", "a", "c", "b"})
	if len(result) != 3 {
		t.Errorf("uniqueStrings dedup = %d items, want 3", len(result))
	}
}
