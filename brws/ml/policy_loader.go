package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// DQNWeights holds exported neural network weights (from PyTorch JSON export)
type DQNWeights struct {
	W1 [][]float64 `json:"w1"` // input (18) -> hidden1 (64)
	B1 []float64   `json:"b1"`
	W2 [][]float64 `json:"w2"` // hidden1 (64) -> hidden2 (64)
	B2 []float64   `json:"b2"`
	W3 [][]float64 `json:"w3"` // hidden2 (64) -> hidden3 (32)
	B3 []float64   `json:"b3"`
	W4 [][]float64 `json:"w4"` // hidden3 (32) -> output (18)
	B4 []float64   `json:"b4"`
}

// PolicyLoader loads and runs DQN inference in pure Go
type PolicyLoader struct {
	weights  *DQNWeights
	modelID  string
	inputDim int
}

// ActionMap maps action indices to stealth config fields
var ActionMap = map[int]string{
	0:  "RemoveWebDriver",
	1:  "CanvasNoise",
	2:  "ClientHints",
	3:  "RandomUserAgent",
	4:  "WebGLSpoof",
	5:  "HardwareSync",
	6:  "NetworkSync",
	7:  "PluginsSync",
	8:  "GeometrySync",
	9:  "VideoSync",
	10: "PermissionsSync",
	11: "TimezoneSync",
	12: "CaptchaSolver",
	13: "HumanizeInteraction",
	14: "DelayedNavigation",
	15: "WebRTCDisable",
	16: "CanvasNoiseStrength",
	17: "HeadlessPatches",
}

// NewPolicyLoader loads DQN weights from a JSON file and validates dimensions.
// The expected architecture is:
//   - fc1: 18 -> 64 (W1: [64][18], B1: [64])
//   - fc2: 64 -> 64 (W2: [64][64], B2: [64])
//   - fc3: 64 -> 32 (W3: [32][64], B3: [32])
//   - fc4: 32 -> 18 (W4: [18][32], B4: [18])
func NewPolicyLoader(modelPath string) (*PolicyLoader, error) {
	data, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("read model file: %w", err)
	}

	var w DQNWeights
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("unmarshal weights: %w", err)
	}

	// Validate layer dimensions.
	// PyTorch stores weights as [out_features][in_features], so W1 is [64][18].
	if err := validateLayer("fc1", w.W1, w.B1, 64, 18); err != nil {
		return nil, err
	}
	if err := validateLayer("fc2", w.W2, w.B2, 64, 64); err != nil {
		return nil, err
	}
	if err := validateLayer("fc3", w.W3, w.B3, 32, 64); err != nil {
		return nil, err
	}
	if err := validateLayer("fc4", w.W4, w.B4, 18, 32); err != nil {
		return nil, err
	}

	return &PolicyLoader{
		weights:  &w,
		modelID:  modelPath,
		inputDim: 18,
	}, nil
}

// validateLayer checks that a weight matrix has shape [rows][cols] and bias has length [rows].
func validateLayer(name string, w [][]float64, b []float64, expectedRows, expectedCols int) error {
	if len(w) != expectedRows {
		return fmt.Errorf("%s: weight matrix has %d rows, expected %d", name, len(w), expectedRows)
	}
	for i, row := range w {
		if len(row) != expectedCols {
			return fmt.Errorf("%s: weight row %d has %d cols, expected %d", name, i, len(row), expectedCols)
		}
	}
	if len(b) != expectedRows {
		return fmt.Errorf("%s: bias has %d elements, expected %d", name, len(b), expectedRows)
	}
	return nil
}

// SelectAction performs a forward pass through the DQN and returns the argmax
// action index and the corresponding maximum Q-value.
//
// The forward pass applies ReLU after each hidden layer; the final output
// layer is linear (no activation).
func (pl *PolicyLoader) SelectAction(stateVector []float64) (int, float64) {
	if len(stateVector) == 0 {
		return 0, 0.0
	}

	// Pad or truncate to expected input dimension
	input := make([]float64, pl.inputDim)
	copy(input, stateVector)

	// Layer 1: ReLU(W1 * x + B1)
	h1 := relu(vecAdd(matVecMul(pl.weights.W1, input), pl.weights.B1))

	// Layer 2: ReLU(W2 * h1 + B2)
	h2 := relu(vecAdd(matVecMul(pl.weights.W2, h1), pl.weights.B2))

	// Layer 3: ReLU(W3 * h2 + B3)
	h3 := relu(vecAdd(matVecMul(pl.weights.W3, h2), pl.weights.B3))

	// Layer 4: W4 * h3 + B4 (linear output)
	output := vecAdd(matVecMul(pl.weights.W4, h3), pl.weights.B4)

	// Argmax over Q-values
	bestAction := 0
	bestValue := math.Inf(-1)
	for i, v := range output {
		if v > bestValue {
			bestValue = v
			bestAction = i
		}
	}

	return bestAction, bestValue
}

// ModelID returns the model identifier (typically the file path).
func (pl *PolicyLoader) ModelID() string {
	return pl.modelID
}

// InputDim returns the expected input dimension for the state vector.
func (pl *PolicyLoader) InputDim() int {
	return pl.inputDim
}

// matVecMul computes the matrix-vector product mat * vec.
// mat has shape [M][N] and vec has length N, returning a vector of length M.
func matVecMul(mat [][]float64, vec []float64) []float64 {
	rows := len(mat)
	result := make([]float64, rows)
	for i := 0; i < rows; i++ {
		sum := 0.0
		for j := 0; j < len(mat[i]); j++ {
			sum += mat[i][j] * vec[j]
		}
		result[i] = sum
	}
	return result
}

// vecAdd computes element-wise addition of two vectors.
func vecAdd(a, b []float64) []float64 {
	n := len(a)
	result := make([]float64, n)
	for i := 0; i < n; i++ {
		result[i] = a[i] + b[i]
	}
	return result
}

// relu applies the ReLU activation function element-wise: max(0, x).
func relu(v []float64) []float64 {
	result := make([]float64, len(v))
	for i, x := range v {
		if x > 0 {
			result[i] = x
		}
	}
	return result
}
