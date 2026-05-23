package captcha_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/captcha"
)

func TestDefaultModelConfig(t *testing.T) {
	cfg := captcha.DefaultModelConfig
	if cfg.InputDim <= 0 {
		t.Error("InputDim should be positive")
	}
	if len(cfg.HiddenDims) == 0 {
		t.Error("HiddenDims should not be empty")
	}
	if cfg.NumClasses <= 0 {
		t.Error("NumClasses should be positive")
	}
}

func TestNewModel_defaultConfig(t *testing.T) {
	m := captcha.NewModel(nil)
	if m == nil {
		t.Fatal("NewModel(nil) returned nil")
	}
}

func TestNewModel_customConfig(t *testing.T) {
	cfg := &captcha.ModelConfig{
		InputDim:   64,
		HiddenDims: []int{128, 64},
		OutputDim:  32,
		NumClasses: 10,
		Activation: "relu",
	}
	m := captcha.NewModel(cfg)
	if m == nil {
		t.Fatal("NewModel returned nil")
	}
}

func TestModel_Forward_returnsOutput(t *testing.T) {
	cfg := &captcha.ModelConfig{
		InputDim:   16,
		HiddenDims: []int{32},
		OutputDim:  16,
		NumClasses: 5,
		Activation: "relu",
	}
	m := captcha.NewModel(cfg)
	input := make([]float64, 16)
	output := m.Forward(input)
	if len(output) != 5 {
		t.Errorf("Forward output len = %d, want %d (NumClasses)", len(output), 5)
	}
}

func TestModel_Forward_softmaxNormalized(t *testing.T) {
	cfg := &captcha.ModelConfig{
		InputDim:   8,
		HiddenDims: []int{16},
		OutputDim:  8,
		NumClasses: 3,
		Activation: "relu",
	}
	m := captcha.NewModel(cfg)
	input := make([]float64, 8)
	output := m.Forward(input)

	// Softmax output should sum to ~1.0
	var sum float64
	for _, v := range output {
		sum += v
	}
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("softmax output sum = %f, expected ~1.0", sum)
	}
}

func TestModel_Predict(t *testing.T) {
	cfg := &captcha.ModelConfig{
		InputDim:   8,
		HiddenDims: []int{16},
		OutputDim:  8,
		NumClasses: 4,
		Activation: "relu",
	}
	m := captcha.NewModel(cfg)
	input := make([]float64, 8)
	class, confidence := m.Predict(input)
	if class < 0 || class >= 4 {
		t.Errorf("Predict class = %d, expected in [0, 4)", class)
	}
	if confidence <= 0 || confidence > 1 {
		t.Errorf("Predict confidence = %f, expected in (0, 1]", confidence)
	}
}

func TestModel_Forward_defaultConfig_doesNotPanic(t *testing.T) {
	m := captcha.NewModel(nil)
	input := make([]float64, captcha.DefaultModelConfig.InputDim)
	output := m.Forward(input)
	if len(output) != captcha.DefaultModelConfig.NumClasses {
		t.Errorf("output len = %d, want %d", len(output), captcha.DefaultModelConfig.NumClasses)
	}
}

func TestNewResNetBlock(t *testing.T) {
	block := captcha.NewResNetBlock(16, 32)
	if block == nil {
		t.Fatal("NewResNetBlock returned nil")
	}
}

func TestResNetBlock_Forward(t *testing.T) {
	block := captcha.NewResNetBlock(4, 4)
	input := make([][][]float64, 4)
	for i := range input {
		input[i] = make([][]float64, 4)
		for j := range input[i] {
			input[i][j] = make([]float64, 4)
		}
	}
	output := block.Forward(input)
	if output == nil {
		t.Fatal("ResNetBlock.Forward returned nil")
	}
	if len(output) == 0 {
		t.Error("ResNetBlock.Forward returned empty output")
	}
}

func TestNewCNNModel(t *testing.T) {
	cfg := &captcha.ModelConfig{
		InputDim:   16,
		HiddenDims: []int{32},
		OutputDim:  16,
		NumClasses: 5,
	}
	m := captcha.NewCNNModel(cfg)
	if m == nil {
		t.Fatal("NewCNNModel returned nil")
	}
}

func TestNewCNNModel_nil(t *testing.T) {
	m := captcha.NewCNNModel(nil)
	if m == nil {
		t.Fatal("NewCNNModel(nil) returned nil")
	}
}

func TestCNNModel_Forward_doesNotPanic(t *testing.T) {
	m := captcha.NewCNNModel(nil)

	channels := 1
	height := 8
	width := 8
	input := make([][][]float64, channels)
	for c := range input {
		input[c] = make([][]float64, height)
		for h := range input[c] {
			input[c][h] = make([]float64, width)
		}
	}
	// Forward should not panic
	_ = m.Forward(input)
}
