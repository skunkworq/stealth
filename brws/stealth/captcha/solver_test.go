package captcha_test

import (
	"image"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/captcha"
)

func TestDefaultCaptchaEncoderConfig(t *testing.T) {
	cfg := captcha.DefaultCaptchaEncoderConfig
	if cfg.EmbeddingDim <= 0 {
		t.Error("EmbeddingDim should be positive")
	}
	if cfg.HiddenDim <= 0 {
		t.Error("HiddenDim should be positive")
	}
	if cfg.NumClasses <= 0 {
		t.Error("NumClasses should be positive")
	}
	if cfg.Temperature <= 0 {
		t.Error("Temperature should be positive")
	}
	if cfg.Augmentation == nil {
		t.Error("Augmentation should not be nil")
	}
}

func TestNewContrastiveEncoder_defaultConfig(t *testing.T) {
	enc := captcha.NewContrastiveEncoder(nil)
	if enc == nil {
		t.Fatal("NewContrastiveEncoder(nil) returned nil")
	}
}

func TestNewContrastiveEncoder_customConfig(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		EmbeddingDim:  64,
		HiddenDim:     128,
		ProjectionDim: 32,
		NumClasses:    26,
		Temperature:   0.07,
		LearningRate:  0.01,
		BatchSize:     16,
	}
	enc := captcha.NewContrastiveEncoder(cfg)
	if enc == nil {
		t.Fatal("NewContrastiveEncoder returned nil")
	}
}

func TestNewProjectionHead(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		HiddenDim:     128,
		ProjectionDim: 64,
	}
	ph := captcha.NewProjectionHead(cfg)
	if ph == nil {
		t.Fatal("NewProjectionHead returned nil")
	}
}

func TestNewProjectionHead_nil(t *testing.T) {
	ph := captcha.NewProjectionHead(nil)
	if ph == nil {
		t.Fatal("NewProjectionHead(nil) returned nil")
	}
}

func TestNewCharacterClassifier(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		HiddenDim:  128,
		NumClasses: 36,
	}
	cc := captcha.NewCharacterClassifier(cfg)
	if cc == nil {
		t.Fatal("NewCharacterClassifier returned nil")
	}
}

func TestNewSolver_defaultConfig(t *testing.T) {
	s := captcha.NewSolver(nil)
	if s == nil {
		t.Fatal("NewSolver(nil) returned nil")
	}
}

func TestNewSolver_customConfig(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		EmbeddingDim:  32,
		HiddenDim:     64,
		ProjectionDim: 16,
		NumClasses:    10,
		Temperature:   0.1,
		LearningRate:  0.001,
		BatchSize:     8,
	}
	s := captcha.NewSolver(cfg)
	if s == nil {
		t.Fatal("NewSolver returned nil")
	}
}

func TestSolver_Solve_withImage(t *testing.T) {
	s := captcha.NewSolver(nil)
	img := image.NewRGBA(image.Rect(0, 0, 64, 32))
	c := &captcha.Captcha{
		Image:    img,
		Metadata: captcha.CaptchaMetadata{CharCount: 4},
	}
	text, confidence := s.Solve(c)
	if len(text) == 0 {
		t.Error("Solve should return non-empty text")
	}
	if confidence < 0 || confidence > 1 {
		t.Errorf("confidence = %f, expected [0,1]", confidence)
	}
}

func TestSolver_Save_Load(t *testing.T) {
	s := captcha.NewSolver(nil)
	// Save and Load are no-ops (stub implementations)
	if err := s.Save("/tmp/test-solver.bin"); err != nil {
		t.Errorf("Save() error: %v", err)
	}
	if err := s.Load("/tmp/test-solver.bin"); err != nil {
		t.Errorf("Load() error: %v", err)
	}
}

func TestNewContrastiveDataset(t *testing.T) {
	ds := captcha.NewContrastiveDataset("abcdefghijklmnopqrstuvwxyz")
	if ds == nil {
		t.Fatal("NewContrastiveDataset returned nil")
	}
	if ds.Size() != 0 {
		t.Errorf("new dataset Size = %d, want 0", ds.Size())
	}
}

func TestContrastiveDataset_Add(t *testing.T) {
	ds := captcha.NewContrastiveDataset("abc")
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	ds.Add(img, 0)
	ds.Add(img, 1)
	if ds.Size() != 2 {
		t.Errorf("Size after 2 adds = %d, want 2", ds.Size())
	}
}

func TestContrastiveDataset_GetBatches_empty(t *testing.T) {
	ds := captcha.NewContrastiveDataset("abc")
	batches := ds.GetBatches(32)
	if batches == nil {
		t.Error("GetBatches on empty dataset should return empty slice, not nil")
	}
}

func TestContrastiveDataset_GetBatches(t *testing.T) {
	ds := captcha.NewContrastiveDataset("abcdef")
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for i := 0; i < 10; i++ {
		ds.Add(img, i%6)
	}
	batches := ds.GetBatches(4)
	totalSamples := 0
	for _, b := range batches {
		totalSamples += len(b.Images)
	}
	if totalSamples != 10 {
		t.Errorf("total samples across batches = %d, want 10", totalSamples)
	}
}

func TestContrastiveEncoder_Forward(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		EmbeddingDim: 32,
		HiddenDim:    64,
	}
	enc := captcha.NewContrastiveEncoder(cfg)
	// Forward on zero input — 32 elements (EmbeddingDim)
	input := make([]float64, 32)
	output := enc.Forward(input)
	if len(output) == 0 {
		t.Error("Forward returned empty output")
	}
}

func TestProjectionHead_Forward(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		HiddenDim:     64,
		ProjectionDim: 32,
	}
	ph := captcha.NewProjectionHead(cfg)
	input := make([]float64, 64)
	output := ph.Forward(input)
	if len(output) == 0 {
		t.Error("ProjectionHead.Forward returned empty output")
	}
}

func TestCharacterClassifier_Predict(t *testing.T) {
	cfg := &captcha.CaptchaEncoderConfig{
		HiddenDim:  64,
		NumClasses: 10,
	}
	cc := captcha.NewCharacterClassifier(cfg)
	embedding := make([]float64, 64)
	pred := cc.Predict(embedding)
	if pred == nil {
		t.Fatal("Predict returned nil")
	}
	if pred.Class < 0 || pred.Class >= 10 {
		t.Errorf("Class = %d, expected in [0, 10)", pred.Class)
	}
	if pred.Confidence < 0 || pred.Confidence > 1 {
		t.Errorf("Confidence = %f, expected in [0, 1]", pred.Confidence)
	}
}

func TestNewContrastiveLearner(t *testing.T) {
	l := captcha.NewContrastiveLearner(nil)
	if l == nil {
		t.Fatal("NewContrastiveLearner returned nil")
	}
}

func TestContrastiveLearner_Solve(t *testing.T) {
	l := captcha.NewContrastiveLearner(nil)
	img := image.NewRGBA(image.Rect(0, 0, 64, 32))
	c := &captcha.Captcha{
		Image:    img,
		Metadata: captcha.CaptchaMetadata{CharCount: 4},
	}
	text, confidence := l.Solve(c)
	_ = text
	if confidence < 0 || confidence > 1 {
		t.Errorf("confidence = %f, expected [0,1]", confidence)
	}
}
