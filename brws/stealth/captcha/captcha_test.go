package captcha

import (
	"testing"
)

func TestGeneratorText(t *testing.T) {
	gen := NewGenerator(nil)

	captcha, err := gen.Generate(CaptchaTypeText)
	if err != nil {
		t.Fatalf("failed to generate text captcha: %v", err)
	}

	if captcha.Type != CaptchaTypeText {
		t.Errorf("expected type %s, got %s", CaptchaTypeText, captcha.Type)
	}

	if captcha.Image == nil {
		t.Error("expected non-nil image")
	}
}

func TestGeneratorMath(t *testing.T) {
	gen := NewGenerator(nil)

	captcha, err := gen.Generate(CaptchaTypeMath)
	if err != nil {
		t.Fatalf("failed to generate math captcha: %v", err)
	}

	if captcha.Type != CaptchaTypeMath {
		t.Errorf("expected type %s, got %s", CaptchaTypeMath, captcha.Type)
	}

	solution, ok := captcha.Solution.(MathSolution)
	if !ok {
		t.Error("expected MathSolution")
	}

	if solution.Answer == 0 {
		t.Error("expected non-zero answer")
	}
}

func TestGeneratorImage(t *testing.T) {
	gen := NewGenerator(nil)

	captcha, err := gen.Generate(CaptchaTypeImage)
	if err != nil {
		t.Fatalf("failed to generate image captcha: %v", err)
	}

	if captcha.Type != CaptchaTypeImage {
		t.Errorf("expected type %s, got %s", CaptchaTypeImage, captcha.Type)
	}
}

func TestGeneratorSlider(t *testing.T) {
	gen := NewGenerator(nil)

	captcha, err := gen.Generate(CaptchaTypeSlider)
	if err != nil {
		t.Fatalf("failed to generate slider captcha: %v", err)
	}

	if captcha.Type != CaptchaTypeSlider {
		t.Errorf("expected type %s, got %s", CaptchaTypeSlider, captcha.Type)
	}
}

func TestGeneratorBatch(t *testing.T) {
	gen := NewGenerator(nil)

	captchas, err := gen.GenerateBatch(5, CaptchaTypeText)
	if err != nil {
		t.Fatalf("failed to generate batch: %v", err)
	}

	if len(captchas) != 5 {
		t.Errorf("expected 5 captchas, got %d", len(captchas))
	}
}

func TestGeneratorValidation(t *testing.T) {
	gen := NewGenerator(nil)

	captcha, err := gen.Generate(CaptchaTypeText)
	if err != nil {
		t.Fatalf("failed to generate captcha: %v", err)
	}

	solution, ok := captcha.Solution.(TextSolution)
	if !ok {
		t.Fatal("expected TextSolution")
	}

	if !gen.Validate(captcha, solution.Text) {
		t.Error("expected validation to pass for correct answer")
	}

	if gen.Validate(captcha, "WRONG") {
		t.Error("expected validation to fail for wrong answer")
	}
}

func TestCaptchaStore(t *testing.T) {
	store := NewCaptchaStore()

	captcha, _ := NewGenerator(nil).Generate(CaptchaTypeText)

	store.Add(captcha)

	if store.Count() != 1 {
		t.Errorf("expected count 1, got %d", store.Count())
	}

	retrieved, ok := store.Get(captcha.ID)
	if !ok {
		t.Error("expected to retrieve captcha")
	}

	if retrieved.ID != captcha.ID {
		t.Errorf("expected ID %s, got %s", captcha.ID, retrieved.ID)
	}

	store.Remove(captcha.ID)
	if store.Count() != 0 {
		t.Error("expected count 0 after removal")
	}
}

func TestCaptchaStoreCleanup(t *testing.T) {
	store := NewCaptchaStore()

	for i := 0; i < 5; i++ {
		captcha, _ := NewGenerator(nil).Generate(CaptchaTypeText)
		store.Add(captcha)
	}

	removed := store.Cleanup(0)
	if removed != 5 {
		t.Errorf("expected 5 removed, got %d", removed)
	}
}

func TestDifficultyLevels(t *testing.T) {
	tests := []Difficulty{DifficultyEasy, DifficultyMedium, DifficultyHard, DifficultyExtreme}

	for _, diff := range tests {
		cfg := &CaptchaConfig{
			Length:     4,
			CharSet:    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
			Difficulty: diff,
		}
		gen := NewGenerator(cfg)

		captcha, err := gen.Generate(CaptchaTypeText)
		if err != nil {
			t.Fatalf("failed to generate captcha with difficulty %d: %v", diff, err)
		}

		if captcha.Metadata.Difficulty != diff {
			t.Errorf("expected difficulty %d, got %d", diff, captcha.Metadata.Difficulty)
		}
	}
}

func TestSolver(t *testing.T) {
	solver := NewSolver(nil)

	//nolint:staticcheck // SA5011: Test validation
	if solver == nil {
		t.Error("expected non-nil solver")
	}

	//nolint:staticcheck // SA5011: Test validation
	if solver.encoder == nil {
		t.Error("expected non-nil encoder")
	}

	//nolint:staticcheck // SA5011: Test validation
	if solver.classifier == nil {
		t.Error("expected non-nil classifier")
	}
}

func TestSolverConfig(t *testing.T) {
	config := &CaptchaEncoderConfig{
		EmbeddingDim:  128,
		HiddenDim:     256,
		ProjectionDim: 64,
		NumClasses:    36,
		Temperature:   0.1,
	}

	solver := NewSolver(config)

	if solver.config.EmbeddingDim != 128 {
		t.Errorf("expected embedding dim 128, got %d", solver.config.EmbeddingDim)
	}

	if solver.config.Temperature != 0.1 {
		t.Errorf("expected temperature 0.1, got %f", solver.config.Temperature)
	}
}

func TestModel(t *testing.T) {
	config := &ModelConfig{
		InputDim:   100,
		HiddenDims: []int{50, 25},
		OutputDim:  10,
		NumClasses: 10,
	}

	model := NewModel(config)

	//nolint:staticcheck // SA5011: Test validation
	if model == nil {
		t.Error("expected non-nil model")
	}

	//nolint:staticcheck // SA5011: Test validation
	if len(model.layers) != 2 {
		t.Errorf("expected 2 layers, got %d", len(model.layers))
	}
}

func TestTrainer(t *testing.T) {
	config := &TrainerConfig{
		Epochs:       10,
		BatchSize:    8,
		LearningRate: 0.01,
	}

	model := NewModel(nil)
	trainer := NewTrainer(model, config)

	//nolint:staticcheck // SA5011: Test validation
	if trainer == nil {
		t.Error("expected non-nil trainer")
	}

	//nolint:staticcheck // SA5011: Test validation
	if trainer.config.Epochs != 10 {
		t.Errorf("expected epochs 10, got %d", trainer.config.Epochs)
	}
}

func TestDataAugmenter(t *testing.T) {
	augmenter := NewDataAugmenter(nil)

	if augmenter == nil {
		t.Error("expected non-nil augmenter")
	}

	data := NewTrainingData()
	data.Add(make([]float64, 100), 0)
	data.Add(make([]float64, 100), 1)

	origLen := len(data.Images)
	augData := augmenter.CreateAugmentedDataset(data)

	if len(augData.Images) <= origLen {
		t.Error("expected augmented data to be larger than original")
	}
}

func TestContrastiveDataset(t *testing.T) {
	dataset := NewContrastiveDataset("ABC")

	if dataset.Size() != 0 {
		t.Error("expected empty dataset")
	}
}

func TestOptimizer(t *testing.T) {
	opt := NewOptimizer(0.01, 0.9, 0.0001)

	if opt.learningRate != 0.01 {
		t.Errorf("expected learning rate 0.01, got %f", opt.learningRate)
	}
}

func TestLearningRateScheduler(t *testing.T) {
	sched := NewLearningRateScheduler(0.1, "step", 0.5, 10)

	lr1 := sched.Step(0)
	if lr1 != 0.1 {
		t.Errorf("expected initial lr 0.1, got %f", lr1)
	}

	lr2 := sched.Step(10)
	if lr2 >= lr1 {
		t.Errorf("expected lr to decay, got %f", lr2)
	}
}

func TestRNG(t *testing.T) {
	rng := NewRNG()

	n := rng.Intn(100)
	if n < 0 || n >= 100 {
		t.Errorf("expected int in [0,100), got %d", n)
	}

	minVal, maxVal := 10, 20
	between := rng.IntBetween(minVal, maxVal)
	if between < minVal || between >= maxVal {
		t.Errorf("expected int in [%d,%d), got %d", minVal, maxVal, between)
	}
}
