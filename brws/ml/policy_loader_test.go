package ml

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestMatVecMul(t *testing.T) {
	// 2x3 matrix * 3-vector
	mat := [][]float64{
		{1.0, 2.0, 3.0},
		{4.0, 5.0, 6.0},
	}
	vec := []float64{1.0, 1.0, 1.0}

	result := matVecMul(mat, vec)

	if len(result) != 2 {
		t.Fatalf("expected length 2, got %d", len(result))
	}
	// Row 0: 1+2+3 = 6
	if math.Abs(result[0]-6.0) > 1e-9 {
		t.Errorf("result[0] = %f, want 6.0", result[0])
	}
	// Row 1: 4+5+6 = 15
	if math.Abs(result[1]-15.0) > 1e-9 {
		t.Errorf("result[1] = %f, want 15.0", result[1])
	}

	// Identity matrix test
	identity := [][]float64{
		{1, 0, 0},
		{0, 1, 0},
		{0, 0, 1},
	}
	vec2 := []float64{7.0, 8.0, 9.0}
	result2 := matVecMul(identity, vec2)
	for i, want := range vec2 {
		if math.Abs(result2[i]-want) > 1e-9 {
			t.Errorf("identity result[%d] = %f, want %f", i, result2[i], want)
		}
	}
}

func TestReLU(t *testing.T) {
	input := []float64{-5.0, -1.0, 0.0, 1.0, 5.0, -0.001, 100.0}
	result := relu(input)

	expected := []float64{0.0, 0.0, 0.0, 1.0, 5.0, 0.0, 100.0}
	if len(result) != len(expected) {
		t.Fatalf("length mismatch: got %d, want %d", len(result), len(expected))
	}
	for i, want := range expected {
		if math.Abs(result[i]-want) > 1e-9 {
			t.Errorf("relu[%d] = %f, want %f", i, result[i], want)
		}
	}

	// Empty input
	empty := relu([]float64{})
	if len(empty) != 0 {
		t.Errorf("relu of empty should be empty, got length %d", len(empty))
	}

	// All negative
	allNeg := relu([]float64{-1, -2, -3})
	for i, v := range allNeg {
		if v != 0 {
			t.Errorf("relu all negative [%d] = %f, want 0", i, v)
		}
	}
}

func TestVecAdd(t *testing.T) {
	a := []float64{1.0, 2.0, 3.0}
	b := []float64{4.0, 5.0, 6.0}
	result := vecAdd(a, b)

	expected := []float64{5.0, 7.0, 9.0}
	for i, want := range expected {
		if math.Abs(result[i]-want) > 1e-9 {
			t.Errorf("vecAdd[%d] = %f, want %f", i, result[i], want)
		}
	}
}

func TestPolicyLoaderForwardPass(t *testing.T) {
	// Create a minimal but valid DQN weights structure matching the 18->64->64->32->18 architecture.
	// Use small known weights to verify deterministic output.
	w := &DQNWeights{
		W1: makeMatrix(64, 18, 0.1),
		B1: makeVec(64, 0.01),
		W2: makeMatrix(64, 64, 0.05),
		B2: makeVec(64, 0.01),
		W3: makeMatrix(32, 64, 0.05),
		B3: makeVec(32, 0.01),
		W4: makeMatrix(18, 32, 0.1),
		B4: makeVec(18, 0.0),
	}

	pl := &PolicyLoader{
		weights:  w,
		modelID:  "test-model",
		inputDim: 18,
	}

	state := make([]float64, 18)
	for i := range state {
		state[i] = 1.0
	}

	action1, qval1 := pl.SelectAction(state)

	// Action should be in valid range
	if action1 < 0 || action1 >= 18 {
		t.Errorf("action %d out of range [0, 18)", action1)
	}

	// Q-value should be finite
	if math.IsNaN(qval1) || math.IsInf(qval1, 0) {
		t.Errorf("Q-value is not finite: %f", qval1)
	}

	// Deterministic: running again with same input should give same output
	action2, qval2 := pl.SelectAction(state)
	if action1 != action2 {
		t.Errorf("non-deterministic action: %d vs %d", action1, action2)
	}
	if math.Abs(qval1-qval2) > 1e-12 {
		t.Errorf("non-deterministic Q-value: %f vs %f", qval1, qval2)
	}

	// Different input should (likely) give different Q-values
	state2 := make([]float64, 18)
	state2[0] = 1.0 // Only one feature active
	_, qval3 := pl.SelectAction(state2)
	if math.Abs(qval1-qval3) < 1e-12 {
		t.Log("Warning: different inputs produced same Q-value (possible but unlikely with non-zero weights)")
	}
}

func TestPolicyLoaderLoadFromFile(t *testing.T) {
	// Create a temporary JSON weights file with proper dimensions
	w := DQNWeights{
		W1: makeMatrix(64, 18, 0.01),
		B1: makeVec(64, 0.0),
		W2: makeMatrix(64, 64, 0.01),
		B2: makeVec(64, 0.0),
		W3: makeMatrix(32, 64, 0.01),
		B3: makeVec(32, 0.0),
		W4: makeMatrix(18, 32, 0.01),
		B4: makeVec(18, 0.0),
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test_weights.json")

	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal weights: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	pl, err := NewPolicyLoader(path)
	if err != nil {
		t.Fatalf("NewPolicyLoader: %v", err)
	}

	if pl.ModelID() != path {
		t.Errorf("ModelID() = %q, want %q", pl.ModelID(), path)
	}
	if pl.InputDim() != 18 {
		t.Errorf("InputDim() = %d, want 18", pl.InputDim())
	}

	// Run a forward pass to verify it works end-to-end
	state := make([]float64, 18)
	for i := range state {
		state[i] = float64(i) * 0.1
	}
	action, qval := pl.SelectAction(state)
	if action < 0 || action >= 18 {
		t.Errorf("action %d out of valid range", action)
	}
	if math.IsNaN(qval) || math.IsInf(qval, 0) {
		t.Errorf("Q-value not finite: %f", qval)
	}
}

func TestPolicyLoaderLoadFromFile_BadDimensions(t *testing.T) {
	// Wrong W1 dimensions: [32][18] instead of [64][18]
	w := DQNWeights{
		W1: makeMatrix(32, 18, 0.01), // Wrong: should be 64 rows
		B1: makeVec(32, 0.0),
		W2: makeMatrix(64, 64, 0.01),
		B2: makeVec(64, 0.0),
		W3: makeMatrix(32, 64, 0.01),
		B3: makeVec(32, 0.0),
		W4: makeMatrix(18, 32, 0.01),
		B4: makeVec(18, 0.0),
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad_weights.json")

	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = NewPolicyLoader(path)
	if err == nil {
		t.Fatal("expected error for bad dimensions, got nil")
	}
}

func TestPolicyLoaderLoadFromFile_MissingFile(t *testing.T) {
	_, err := NewPolicyLoader("/nonexistent/path/weights.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestPolicyLoaderLoadFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := NewPolicyLoader(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestPolicyLoaderNilSafety(t *testing.T) {
	w := &DQNWeights{
		W1: makeMatrix(64, 18, 0.1),
		B1: makeVec(64, 0.01),
		W2: makeMatrix(64, 64, 0.05),
		B2: makeVec(64, 0.01),
		W3: makeMatrix(32, 64, 0.05),
		B3: makeVec(32, 0.01),
		W4: makeMatrix(18, 32, 0.1),
		B4: makeVec(18, 0.0),
	}

	pl := &PolicyLoader{
		weights:  w,
		modelID:  "test",
		inputDim: 18,
	}

	// Empty state vector
	action, qval := pl.SelectAction([]float64{})
	if action < 0 || action >= 18 {
		t.Errorf("empty state: action %d out of range", action)
	}
	if math.IsNaN(qval) || math.IsInf(qval, 0) {
		t.Errorf("empty state: Q-value not finite: %f", qval)
	}

	// Nil state vector
	action2, qval2 := pl.SelectAction(nil)
	if action2 < 0 || action2 >= 18 {
		t.Errorf("nil state: action %d out of range", action2)
	}
	if math.IsNaN(qval2) || math.IsInf(qval2, 0) {
		t.Errorf("nil state: Q-value not finite: %f", qval2)
	}

	// Short state vector (should be zero-padded)
	action3, qval3 := pl.SelectAction([]float64{1.0, 0.5})
	if action3 < 0 || action3 >= 18 {
		t.Errorf("short state: action %d out of range", action3)
	}
	if math.IsNaN(qval3) || math.IsInf(qval3, 0) {
		t.Errorf("short state: Q-value not finite: %f", qval3)
	}

	// Long state vector (extra elements ignored via copy)
	longState := make([]float64, 25)
	for i := range longState {
		longState[i] = 1.0
	}
	action4, qval4 := pl.SelectAction(longState)
	if action4 < 0 || action4 >= 18 {
		t.Errorf("long state: action %d out of range", action4)
	}
	if math.IsNaN(qval4) || math.IsInf(qval4, 0) {
		t.Errorf("long state: Q-value not finite: %f", qval4)
	}
}

func TestActionMap(t *testing.T) {
	if len(ActionMap) != 18 {
		t.Errorf("ActionMap has %d entries, want 18", len(ActionMap))
	}

	// Verify all indices 0-17 are present
	for i := 0; i < 18; i++ {
		if _, ok := ActionMap[i]; !ok {
			t.Errorf("ActionMap missing index %d", i)
		}
	}

	// Spot-check some known mappings
	checks := map[int]string{
		0:  "RemoveWebDriver",
		1:  "CanvasNoise",
		12: "CaptchaSolver",
		17: "HeadlessPatches",
	}
	for idx, want := range checks {
		if got := ActionMap[idx]; got != want {
			t.Errorf("ActionMap[%d] = %q, want %q", idx, got, want)
		}
	}
}

// makeMatrix creates a [rows][cols] matrix filled with the given value.
func makeMatrix(rows, cols int, val float64) [][]float64 {
	mat := make([][]float64, rows)
	for i := range mat {
		mat[i] = make([]float64, cols)
		for j := range mat[i] {
			mat[i][j] = val
		}
	}
	return mat
}

// makeVec creates a vector of the given length filled with the given value.
func makeVec(n int, val float64) []float64 {
	v := make([]float64, n)
	for i := range v {
		v[i] = val
	}
	return v
}
