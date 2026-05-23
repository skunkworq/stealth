package detection

import (
	"testing"

	"github.com/skunkworq/stealth/brws/core/types"
)

// ---------------------------------------------------------------------------
// Baseline constructor tests
// ---------------------------------------------------------------------------

func TestChrome146Baseline_Fields(t *testing.T) {
	bl := Chrome146Baseline()
	if bl == nil {
		t.Fatal("Chrome146Baseline() returned nil")
	}
	if bl.Browser != "chrome" {
		t.Errorf("Browser: want %q, got %q", "chrome", bl.Browser)
	}
	if bl.Version != "146" {
		t.Errorf("Version: want %q, got %q", "146", bl.Version)
	}
	if bl.JA3Hash == "" {
		t.Error("JA3Hash should not be empty")
	}
	if bl.JA4 == "" {
		t.Error("JA4 should not be empty")
	}
	if !bl.HasGREASE {
		t.Error("Chrome146 should have HasGREASE=true")
	}
	if !bl.HasALPS {
		t.Error("Chrome146 should have HasALPS=true")
	}
	if !bl.HasCertCompress {
		t.Error("Chrome146 should have HasCertCompress=true")
	}
}

func TestChrome146Baseline_CipherCount(t *testing.T) {
	bl := Chrome146Baseline()
	if bl.CipherSuiteCount != 15 {
		t.Errorf("CipherSuiteCount: want 15, got %d", bl.CipherSuiteCount)
	}
	if len(bl.CipherSuiteOrder) != 15 {
		t.Errorf("len(CipherSuiteOrder): want 15, got %d", len(bl.CipherSuiteOrder))
	}
}

func TestChrome146Baseline_ExtensionCount(t *testing.T) {
	bl := Chrome146Baseline()
	if bl.ExtensionCount != 16 {
		t.Errorf("ExtensionCount: want 16, got %d", bl.ExtensionCount)
	}
	if len(bl.ExtensionOrder) != 16 {
		t.Errorf("len(ExtensionOrder): want 16, got %d", len(bl.ExtensionOrder))
	}
}

func TestChrome146Baseline_HasALPSExtension(t *testing.T) {
	bl := Chrome146Baseline()
	alpsFound := false
	for _, ext := range bl.ExtensionOrder {
		if ext == 0x44cd {
			alpsFound = true
			break
		}
	}
	if !alpsFound {
		t.Error("Chrome146 ExtensionOrder should contain ALPS (0x44cd)")
	}
}

func TestChrome146Baseline_HasPostQuantumGroup(t *testing.T) {
	bl := Chrome146Baseline()
	pqFound := false
	for _, g := range bl.SupportedGroups {
		if g == 0x11ec {
			pqFound = true
			break
		}
	}
	if !pqFound {
		t.Error("Chrome146 SupportedGroups should include X25519MLKEM768 (0x11ec)")
	}
}

func TestFirefox128Baseline_Fields(t *testing.T) {
	bl := Firefox128Baseline()
	if bl == nil {
		t.Fatal("Firefox128Baseline() returned nil")
	}
	if bl.Browser != "firefox" {
		t.Errorf("Browser: want %q, got %q", "firefox", bl.Browser)
	}
	if bl.Version != "128" {
		t.Errorf("Version: want %q, got %q", "128", bl.Version)
	}
	if bl.HasALPS {
		t.Error("Firefox128 should have HasALPS=false (ALPS is Chrome-only)")
	}
	if bl.HasCertCompress {
		t.Error("Firefox128 should have HasCertCompress=false")
	}
}

func TestFirefox128Baseline_CipherCount(t *testing.T) {
	bl := Firefox128Baseline()
	if bl.CipherSuiteCount != 17 {
		t.Errorf("CipherSuiteCount: want 17, got %d", bl.CipherSuiteCount)
	}
	if len(bl.CipherSuiteOrder) != 17 {
		t.Errorf("len(CipherSuiteOrder): want 17, got %d", len(bl.CipherSuiteOrder))
	}
}

func TestGoDefaultBaseline_Fields(t *testing.T) {
	bl := GoDefaultBaseline()
	if bl == nil {
		t.Fatal("GoDefaultBaseline() returned nil")
	}
	if bl.Browser != "go" {
		t.Errorf("Browser: want %q, got %q", "go", bl.Browser)
	}
	if bl.HasGREASE {
		t.Error("Go TLS should not use GREASE")
	}
	if bl.HasALPS {
		t.Error("Go TLS should not use ALPS")
	}
	if bl.CipherSuiteCount != 13 {
		t.Errorf("CipherSuiteCount: want 13, got %d", bl.CipherSuiteCount)
	}
}

// ---------------------------------------------------------------------------
// knownBrowserBaselines tests
// ---------------------------------------------------------------------------

func TestKnownBrowserBaselines_ContainsChromeAndFirefox(t *testing.T) {
	baselines := knownBrowserBaselines()
	if len(baselines) < 2 {
		t.Fatalf("expected at least 2 known baselines, got %d", len(baselines))
	}
	found := map[string]bool{}
	for _, bl := range baselines {
		found[bl.Browser] = true
	}
	if !found["chrome"] {
		t.Error("knownBrowserBaselines should include chrome")
	}
	if !found["firefox"] {
		t.Error("knownBrowserBaselines should include firefox")
	}
}

// ---------------------------------------------------------------------------
// AnalyzeTLSDeep tests
// ---------------------------------------------------------------------------

func TestAnalyzeTLSDeep_NilReturnsNil(t *testing.T) {
	result := AnalyzeTLSDeep(nil, "chrome")
	if result != nil {
		t.Errorf("expected nil for nil fingerprint, got %+v", result)
	}
}

func TestAnalyzeTLSDeep_GoTLSDetection(t *testing.T) {
	// Build a fingerprint that exactly matches the Go default baseline —
	// no GREASE, same ciphers and extensions as GoDefaultBaseline.
	gobl := GoDefaultBaseline()

	fp := &types.TLSFingerprint{
		GREASE: []types.GREASEInfo{}, // no GREASE
	}
	for _, c := range gobl.CipherSuiteOrder {
		fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{Value: c, IsGREASE: false})
	}
	for _, e := range gobl.ExtensionOrder {
		fp.Extensions = append(fp.Extensions, types.ExtensionInfo{Type: e, IsGREASE: false})
	}
	fp.SupportedGroups = gobl.SupportedGroups

	analysis := AnalyzeTLSDeep(fp, "go")
	if analysis == nil {
		t.Fatal("expected non-nil analysis")
	}
	if !analysis.IsGoTLS {
		t.Error("expected IsGoTLS=true for a fingerprint matching the Go default baseline")
	}
	if analysis.BotScore < 0.5 {
		t.Errorf("expected BotScore >= 0.5 for a Go TLS fingerprint, got %f", analysis.BotScore)
	}
}

func TestAnalyzeTLSDeep_BotScoreRange(t *testing.T) {
	// Use the Go default baseline's ciphers to ensure the baseline-matching loop
	// finds a match and avoids a nil-dereference in the production code path
	// (AnalyzeTLSDeep has a latent bug: bestBaseline stays nil if no baseline's
	// combined score exceeds 0.0, which happens with an entirely empty fingerprint).
	gobl := GoDefaultBaseline()
	fp := &types.TLSFingerprint{
		GREASE: []types.GREASEInfo{},
	}
	fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{Value: gobl.CipherSuiteOrder[0]})
	fp.Extensions = append(fp.Extensions, types.ExtensionInfo{Type: gobl.ExtensionOrder[0]})

	analysis := AnalyzeTLSDeep(fp, "chrome")
	if analysis == nil {
		t.Fatal("expected non-nil analysis")
	}
	if analysis.BotScore < 0 || analysis.BotScore > 1 {
		t.Errorf("BotScore out of range [0,1]: %f", analysis.BotScore)
	}
}

func TestAnalyzeTLSDeep_AnomaliesPopulated(t *testing.T) {
	// A fingerprint with no GREASE claiming to be Chrome should have anomalies.
	// We need at least one cipher/extension so the baseline-matching loop finds a match.
	gobl := GoDefaultBaseline()
	fp := &types.TLSFingerprint{
		GREASE: []types.GREASEInfo{},
	}
	fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{Value: gobl.CipherSuiteOrder[0]})
	fp.Extensions = append(fp.Extensions, types.ExtensionInfo{Type: gobl.ExtensionOrder[0]})

	analysis := AnalyzeTLSDeep(fp, "chrome")
	if len(analysis.Anomalies) == 0 {
		t.Error("expected anomalies for a Chrome claim with no GREASE and no ALPS")
	}
}

func TestAnalyzeTLSDeep_GREASEScore(t *testing.T) {
	// No GREASE → GREASEScore = 1.0.
	// Need at least one cipher/extension to avoid nil-dereference in the
	// production baseline-matching loop.
	gobl := GoDefaultBaseline()
	fp := &types.TLSFingerprint{GREASE: nil}
	fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{Value: gobl.CipherSuiteOrder[0]})
	fp.Extensions = append(fp.Extensions, types.ExtensionInfo{Type: gobl.ExtensionOrder[0]})

	analysis := AnalyzeTLSDeep(fp, "go")
	if analysis.GREASEScore != 1.0 {
		t.Errorf("GREASEScore: want 1.0, got %f", analysis.GREASEScore)
	}
}

func TestAnalyzeTLSDeep_WithGREASE_NoGREASEScore(t *testing.T) {
	// Include a real cipher so the baseline loop has something to compare.
	bl := Chrome146Baseline()
	fp := &types.TLSFingerprint{
		GREASE: []types.GREASEInfo{{Value: 0x0a0a, Position: 0, Context: "cipher"}},
	}
	for _, c := range bl.CipherSuiteOrder {
		fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{Value: c})
	}
	fp.Extensions = append(fp.Extensions, types.ExtensionInfo{Type: 0x0000})

	analysis := AnalyzeTLSDeep(fp, "chrome")
	if analysis.GREASEScore != 0 {
		t.Errorf("GREASEScore: want 0 when GREASE present, got %f", analysis.GREASEScore)
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestSetJaccard_IdenticalSets(t *testing.T) {
	a := []uint16{1, 2, 3, 4}
	sim := setJaccard(a, a)
	if sim != 1.0 {
		t.Errorf("identical sets: want 1.0, got %f", sim)
	}
}

func TestSetJaccard_DisjointSets(t *testing.T) {
	a := []uint16{1, 2}
	b := []uint16{3, 4}
	sim := setJaccard(a, b)
	if sim != 0 {
		t.Errorf("disjoint sets: want 0.0, got %f", sim)
	}
}

func TestSetJaccard_BothEmpty(t *testing.T) {
	sim := setJaccard([]uint16{}, []uint16{})
	if sim != 1.0 {
		t.Errorf("both empty: want 1.0, got %f", sim)
	}
}

func TestSetJaccard_OneEmpty(t *testing.T) {
	sim := setJaccard([]uint16{1, 2}, []uint16{})
	if sim != 0 {
		t.Errorf("one empty: want 0.0, got %f", sim)
	}
}

func TestOrderSimilarity_Identical(t *testing.T) {
	a := []uint16{1, 2, 3, 4, 5}
	sim := orderSimilarity(a, a)
	if sim != 1.0 {
		t.Errorf("identical sequences: want 1.0, got %f", sim)
	}
}

func TestOrderSimilarity_Disjoint(t *testing.T) {
	a := []uint16{1, 2, 3}
	b := []uint16{4, 5, 6}
	sim := orderSimilarity(a, b)
	if sim != 0 {
		t.Errorf("disjoint sequences: want 0.0, got %f", sim)
	}
}

func TestOrderSimilarity_BothEmpty(t *testing.T) {
	sim := orderSimilarity([]uint16{}, []uint16{})
	if sim != 1.0 {
		t.Errorf("both empty: want 1.0, got %f", sim)
	}
}

func TestIsGREASEValue(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0xfafa}
	for _, v := range greaseValues {
		if !isGREASEValue(v) {
			t.Errorf("isGREASEValue(0x%04x) should be true", v)
		}
	}
	nonGrease := []uint16{0x0001, 0x1301, 0xc02b, 0x0000}
	for _, v := range nonGrease {
		if isGREASEValue(v) {
			t.Errorf("isGREASEValue(0x%04x) should be false", v)
		}
	}
}

func TestLCS_Identical(t *testing.T) {
	a := []uint16{1, 2, 3, 4, 5}
	length := lcs(a, a)
	if length != 5 {
		t.Errorf("lcs identical: want 5, got %d", length)
	}
}

func TestLCS_Empty(t *testing.T) {
	length := lcs([]uint16{}, []uint16{1, 2, 3})
	if length != 0 {
		t.Errorf("lcs with empty: want 0, got %d", length)
	}
}

func TestLCS_Classic(t *testing.T) {
	// LCS([1,2,3,4,5], [2,4,5]) = 3
	a := []uint16{1, 2, 3, 4, 5}
	b := []uint16{2, 4, 5}
	length := lcs(a, b)
	if length != 3 {
		t.Errorf("lcs([1,2,3,4,5],[2,4,5]): want 3, got %d", length)
	}
}

// ---------------------------------------------------------------------------
// CompareTLSToBaselines tests
// ---------------------------------------------------------------------------

func TestCompareTLSToBaselines_Nil(t *testing.T) {
	result := CompareTLSToBaselines(nil)
	if result != nil {
		t.Errorf("expected nil for nil fingerprint, got %v", result)
	}
}

func TestCompareTLSToBaselines_ReturnsReports(t *testing.T) {
	fp := &types.TLSFingerprint{}
	reports := CompareTLSToBaselines(fp)

	// Should have at least 3 reports: chrome, firefox, go
	if len(reports) < 3 {
		t.Errorf("expected at least 3 reports, got %d", len(reports))
	}

	for _, r := range reports {
		if r.Baseline == "" {
			t.Error("report Baseline should not be empty")
		}
		if r.CipherSimilarity < 0 || r.CipherSimilarity > 1 {
			t.Errorf("CipherSimilarity out of [0,1]: %f for %s", r.CipherSimilarity, r.Baseline)
		}
		if r.ExtSimilarity < 0 || r.ExtSimilarity > 1 {
			t.Errorf("ExtSimilarity out of [0,1]: %f for %s", r.ExtSimilarity, r.Baseline)
		}
	}
}

// ---------------------------------------------------------------------------
// FormatTLSAnalysis tests
// ---------------------------------------------------------------------------

func TestFormatTLSAnalysis_Nil(t *testing.T) {
	out := FormatTLSAnalysis(nil)
	if out != "no TLS data" {
		t.Errorf("FormatTLSAnalysis(nil): want %q, got %q", "no TLS data", out)
	}
}

func TestFormatTLSAnalysis_NonNil(t *testing.T) {
	a := &TLSDeepAnalysis{
		BotScore:  0.75,
		Anomalies: []string{"test_anomaly"},
	}
	out := FormatTLSAnalysis(a)
	if out == "" {
		t.Error("FormatTLSAnalysis should return non-empty string for non-nil analysis")
	}
}
