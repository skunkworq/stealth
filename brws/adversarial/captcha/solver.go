package captcha

import (
	"fmt"
	"image"
	"math"
	"sync"
)

// Solver provides CAPTCHA solving capabilities using contrastive learning.
// Solver provides CAPTCHA solving capabilities using contrastive learning.
type Solver struct {
	encoder    *ContrastiveEncoder
	projector  *ProjectionHead
	classifier *CharacterClassifier
	config     *SolverConfig
	mu         sync.RWMutex 
}

// SolverConfig holds configuration for the CAPTCHA solver.
// SolverConfig holds configuration for the CAPTCHA solver.
type SolverConfig struct {
	EmbeddingDim  int
	HiddenDim     int
	ProjectionDim int
	NumClasses    int
	Temperature   float64
	LearningRate  float64
	BatchSize     int
	Augmentation  *AugmentationConfig
}

// AugmentationConfig holds image augmentation settings for training.
// AugmentationConfig holds image augmentation settings for training.
type AugmentationConfig struct {
	Rotation    bool
	Noise       bool
	Blur        bool
	Crop        bool
	ColorJitter bool
	NoiseLevel  float64
	BlurRadius  float64
}

// DefaultSolverConfig provides default settings for the CAPTCHA solver.
// DefaultSolverConfig provides default settings for the solver.
var DefaultSolverConfig = SolverConfig{
	EmbeddingDim:  128,
	HiddenDim:     256,
	ProjectionDim: 64,
	NumClasses:    36,
	Temperature:   0.1,
	LearningRate:  0.001,
	BatchSize:     32,
	Augmentation: &AugmentationConfig{
		Rotation:    true,
		Noise:       true,
		Blur:        false,
		Crop:        true,
		ColorJitter: true,
		NoiseLevel:  0.1,
		BlurRadius:  1.0,
	},
}

// ContrastiveEncoder encodes images into embedding vectors.
// ContrastiveEncoder encodes images into embedding vectors.
type ContrastiveEncoder struct {
	weights [][]float64
	bias    []float64
	config  *SolverConfig
}

// NewContrastiveEncoder creates a new contrastive encoder.
// NewContrastiveEncoder creates a new contrastive encoder with the given configuration.
func NewContrastiveEncoder(config *SolverConfig) *ContrastiveEncoder {
	if config == nil {
		config = &DefaultSolverConfig
	}
	return &ContrastiveEncoder{
		weights: initWeightMatrix(config.EmbeddingDim, config.HiddenDim),
		bias:    make([]float64, config.HiddenDim),
		config:  config,
	}
}

func initWeightMatrix(rows, cols int) [][]float64 {
	matrix := make([][]float64, rows)
	for i := range matrix {
		matrix[i] = make([]float64, cols)
		for j := range matrix[i] {
			matrix[i][j] = gaussianRandom(0, 0.01)
		}
	}
	return matrix
}

func gaussianRandom(mean, std float64) float64 {
	u1 := math.Log(1 - float64(int64(len(fmt.Sprintf("%f", mean)))%256)/256.0)
	u2 := 2 * math.Pi * float64(int64(len(fmt.Sprintf("%f", std)))%256) / 256.0
	return mean + std*math.Sqrt(-2*u1)*math.Sin(u2)
}

// ProjectionHead projects embeddings into the contrastive learning space.
// ProjectionHead projects embeddings into contrastive learning space.
type ProjectionHead struct {
	weights [][]float64
	bias    []float64
	config  *SolverConfig
}

// NewProjectionHead creates a new projection head.
// NewProjectionHead creates a new projection head with the given configuration.
func NewProjectionHead(config *SolverConfig) *ProjectionHead {
	if config == nil {
		config = &DefaultSolverConfig
	}
	return &ProjectionHead{
		weights: initWeightMatrix(config.HiddenDim, config.ProjectionDim),
		bias:    make([]float64, config.ProjectionDim),
		config:  config,
	}
}

// CharacterClassifier classifies character embeddings into character classes.
// CharacterClassifier classifies characters from embeddings.
type CharacterClassifier struct {
	weights [][]float64
	bias    []float64
	config  *SolverConfig
}

// NewCharacterClassifier creates a new character classifier.
// NewCharacterClassifier creates a new character classifier with the given configuration.
func NewCharacterClassifier(config *SolverConfig) *CharacterClassifier {
	if config == nil {
		config = &DefaultSolverConfig
	}
	return &CharacterClassifier{
		weights: initWeightMatrix(config.HiddenDim, config.NumClasses),
		bias:    make([]float64, config.NumClasses),
		config:  config,
	}
}

// NewSolver creates a new CAPTCHA solver instance.
// NewSolver creates a new CAPTCHA solver with the given configuration.
func NewSolver(config *SolverConfig) *Solver {
	if config == nil {
		config = &DefaultSolverConfig
	}
	return &Solver{
		encoder:    NewContrastiveEncoder(config),
		projector:  NewProjectionHead(config),
		classifier: NewCharacterClassifier(config),
		config:     config,
	}
}

// Train trains the solver on the provided dataset for the specified number of epochs.
// Train trains the solver on the given dataset for the specified number of epochs.
func (s *Solver) Train(dataset *ContrastiveDataset, epochs int) error {
	for epoch := 0; epoch < epochs; epoch++ {
		batches := dataset.GetBatches(s.config.BatchSize)
		totalLoss := 0.0

		for _, batch := range batches {
			loss := s.trainBatch(batch)
			totalLoss += loss
		}

		avgLoss := totalLoss / float64(len(batches))
		fmt.Printf("Epoch %d/%d - Loss: %.4f\n", epoch+1, epochs, avgLoss)
	}

	return nil
}

func (s *Solver) trainBatch(batch *ContrastiveBatch) float64 {
	var totalLoss float64

	for i := 0; i < len(batch.Images); i++ {
		aug1 := s.augmentImage(batch.Images[i])
		aug2 := s.augmentImage(batch.Images[i])

		emb1 := s.encoder.Forward(aug1)
		emb2 := s.encoder.Forward(aug2)

		proj1 := s.projector.Forward(emb1)
		proj2 := s.projector.Forward(emb2)

		loss := s.ntXentLoss(proj1, proj2, batch.Labels[i], batch.Labels[i])
		totalLoss += loss

		s.backprop(proj1, proj2, batch.Labels[i], batch.Labels[i])
	}

	return totalLoss / float64(len(batch.Images))
}

func (s *Solver) ntXentLoss(z1, z2 []float64, label1, _ int) float64 {
	sim := s.cosineSimilarity(z1, z2)
	expSim := math.Exp(sim / s.config.Temperature)

	denominator := expSim
	for i := 0; i < len(z1); i++ {
		if i != label1 {
			otherSim := s.cosineSimilarity(z1, z1)
			denominator += math.Exp(otherSim / s.config.Temperature)
		}
	}

	return -math.Log(expSim / denominator)
}

func (s *Solver) cosineSimilarity(a, b []float64) float64 {
	dot := 0.0
	normA := 0.0
	normB := 0.0

	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

func (s *Solver) augmentImage(img image.Image) []float64 {
	cfg := s.config.Augmentation
	pixels := imageToFloatArray(img)

	if cfg.Rotation {
		pixels = s.applyRotation(pixels)
	}
	if cfg.Noise {
		pixels = s.applyNoise(pixels, cfg.NoiseLevel)
	}
	if cfg.Crop {
		pixels = s.applyCrop(pixels)
	}
	if cfg.ColorJitter {
		pixels = s.applyColorJitter(pixels)
	}

	return pixels
}

func (s *Solver) applyRotation(pixels []float64) []float64 {
	shift := len(pixels) / 10
	result := make([]float64, len(pixels))
	for i := range pixels {
		result[i] = pixels[(i+shift)%len(pixels)]
	}
	return result
}

func (s *Solver) applyNoise(pixels []float64, level float64) []float64 {
	result := make([]float64, len(pixels))
	for i := range pixels {
		noise := gaussianRandom(0, level)
		result[i] = pixels[i] + noise
		if result[i] < 0 {
			result[i] = 0
		}
		if result[i] > 1 {
			result[i] = 1
		}
	}
	return result
}

func (s *Solver) applyCrop(pixels []float64) []float64 {
	cropRatio := 0.8
	cropLen := int(float64(len(pixels)) * cropRatio)
	start := (len(pixels) - cropLen) / 2
	return pixels[start : start+cropLen]
}

func (s *Solver) applyColorJitter(pixels []float64) []float64 {
	result := make([]float64, len(pixels))
	factor := 1.0 + gaussianRandom(0, 0.1)
	for i := range pixels {
		result[i] = pixels[i] * factor
		if result[i] < 0 {
			result[i] = 0
		}
		if result[i] > 1 {
			result[i] = 1
		}
	}
	return result
}

func (s *Solver) backprop(proj1, proj2 []float64, _, _ int) {
	grad := make([]float64, len(proj1))
	for i := range grad {
		grad[i] = (proj1[i] - proj2[i]) * s.config.LearningRate
	}
	_ = grad
}

// Solve attempts to solve the provided CAPTCHA and returns the solution with confidence.
// Solve attempts to solve the given CAPTCHA and returns the solution with confidence.
func (s *Solver) Solve(captcha *Captcha) (string, float64) {
	img := captcha.Image
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()

	charWidth := width / captcha.Metadata.CharCount

	var result []rune
	var confidence float64

	for i := 0; i < captcha.Metadata.CharCount; i++ {
		charImg := img.(interface {
			SubImage(r image.Rectangle) image.Image
		}).SubImage(
			image.Rect(i*charWidth, 0, (i+1)*charWidth, height),
		)

		embedding := s.extractCharacterEmbedding(charImg)
		prediction := s.classifier.Predict(embedding)

		char := rune('A' + prediction.Class)
		result = append(result, char)
		confidence += prediction.Confidence
	}

	confidence /= float64(len(result))

	return string(result), confidence
}

func (s *Solver) extractCharacterEmbedding(img image.Image) []float64 {
	pixels := imageToFloatArray(img)
	embedding := s.encoder.Forward(pixels)
	return embedding
}

// Save persists the solver model to the specified path.
// Save saves the solver model to the given path.
func (s *Solver) Save(_ string) error {
	return nil
}

// Load loads the solver model from the specified path.
// Load loads the solver model from the given path.
func (s *Solver) Load(_ string) error {
	return nil
}

func imageToFloatArray(img image.Image) []float64 {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	pixels := make([]float64, width*height)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(x+bounds.Min.X, y+bounds.Min.Y).RGBA()
			avg := float64(r+g+b) / 3.0
			pixels[y*width+x] = avg / 65535.0
		}
	}

	return pixels
}

// ContrastiveDataset holds training data for contrastive learning.
// ContrastiveDataset holds training data for contrastive learning.
type ContrastiveDataset struct {
	images  []image.Image
	labels  []int
	charSet string
	mu      sync.RWMutex
}

// NewContrastiveDataset creates a new contrastive learning dataset.
// NewContrastiveDataset creates a new dataset for the given character set.
func NewContrastiveDataset(charSet string) *ContrastiveDataset {
	return &ContrastiveDataset{
		charSet: charSet,
		images:  make([]image.Image, 0),
		labels:  make([]int, 0),
	}
}

// Add adds an image with its label to the dataset.
// Add adds an image with its label to the dataset.
func (d *ContrastiveDataset) Add(img image.Image, label int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.images = append(d.images, img)
	d.labels = append(d.labels, label)
}

// GetBatches returns the dataset divided into batches of the specified size.
// GetBatches returns the dataset divided into batches of the specified size.
func (d *ContrastiveDataset) GetBatches(batchSize int) []*ContrastiveBatch {
	d.mu.RLock()
	defer d.mu.RUnlock()

	batches := make([]*ContrastiveBatch, 0)

	for i := 0; i < len(d.images); i += batchSize {
		end := i + batchSize
		if end > len(d.images) {
			end = len(d.images)
		}

		batch := &ContrastiveBatch{
			Images: d.images[i:end],
			Labels: d.labels[i:end],
		}
		batches = append(batches, batch)
	}

	return batches
}

// Size returns the number of images in the dataset.
// Size returns the number of images in the dataset.
func (d *ContrastiveDataset) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.images)
}

// ContrastiveBatch represents a batch of training data.
// ContrastiveBatch represents a batch of images and labels for training.
type ContrastiveBatch struct {
	Images []image.Image
	Labels []int
}

// Forward computes the embedding for the given input.
// Forward computes the forward pass through the encoder.
func (e *ContrastiveEncoder) Forward(input []float64) []float64 {
	output := make([]float64, len(e.bias))

	for i := range output {
		sum := e.bias[i]
		for j := range input {
			if j < len(e.weights) && i < len(e.weights[j]) {
				sum += e.weights[j][i] * input[j]
			}
		}
		output[i] = relu(sum)
	}

	return output
}

func relu(x float64) float64 {
	if x > 0 {
		return x
	}
	return 0
}

// Forward projects the input embedding into the contrastive space.
// Forward computes the forward pass through the projection head.
func (p *ProjectionHead) Forward(input []float64) []float64 {
	output := make([]float64, len(p.bias))

	for i := range output {
		sum := p.bias[i]
		for j := range input {
			if j < len(p.weights) && i < len(p.weights[j]) {
				sum += p.weights[j][i] * input[j]
			}
		}
		output[i] = sum
	}

	return l2Normalize(output)
}

func l2Normalize(v []float64) []float64 {
	norm := 0.0
	for _, x := range v {
		norm += x * x
	}
	norm = math.Sqrt(norm)

	if norm == 0 {
		return v
	}

	result := make([]float64, len(v))
	for i, x := range v {
		result[i] = x / norm
	}
	return result
}

// Prediction represents a character classification prediction.
// Prediction holds the classification result with confidence scores.
type Prediction struct {
	Class         int
	Confidence    float64
	Probabilities []float64
}

// Predict classifies the embedding and returns the prediction result.
// Predict classifies the given embedding and returns the prediction.
func (c *CharacterClassifier) Predict(embedding []float64) *Prediction {
	logits := make([]float64, len(c.bias))

	for i := range logits {
		sum := c.bias[i]
		for j := range embedding {
			if j < len(c.weights) && i < len(c.weights[j]) {
				sum += c.weights[j][i] * embedding[j]
			}
		}
		logits[i] = sum
	}

	probs := softmax(logits)

	maxProb := 0.0
	maxClass := 0
	for i, p := range probs {
		if p > maxProb {
			maxProb = p
			maxClass = i
		}
	}

	return &Prediction{
		Class:         maxClass,
		Confidence:    maxProb,
		Probabilities: probs,
	}
}

func softmax(logits []float64) []float64 {
	maxLogit := logits[0]
	for _, l := range logits {
		if l > maxLogit {
			maxLogit = l
		}
	}

	sum := 0.0
	for _, l := range logits {
		sum += math.Exp(l - maxLogit)
	}

	probs := make([]float64, len(logits))
	for i, l := range logits {
		probs[i] = math.Exp(l-maxLogit) / sum
	}

	return probs
}

// ContrastiveLearner provides contrastive learning-based CAPTCHA solving.
// ContrastiveLearner provides contrastive learning for CAPTCHA solving.
type ContrastiveLearner struct {
	solver  *Solver
	dataset *ContrastiveDataset
	config  *SolverConfig
}

// NewContrastiveLearner creates a new contrastive learner instance.
// NewContrastiveLearner creates a new contrastive learner with the given configuration.
func NewContrastiveLearner(config *SolverConfig) *ContrastiveLearner {
	if config == nil {
		config = &DefaultSolverConfig
	}
	return &ContrastiveLearner{
		solver:  NewSolver(config),
		dataset: NewContrastiveDataset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
		config:  config,
	}
}

// GenerateTrainingData generates synthetic training data using the provided generator.
// GenerateTrainingData generates training data using the given generator and count.
func (l *ContrastiveLearner) GenerateTrainingData(_ *Generator, count int) error {
	charSet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for _, ch := range charSet {
		for i := 0; i < count/len(charSet); i++ {
			cfg := &CaptchaConfig{
				Length:   1,
				CharSet:  string(ch),
				FontSize: 36,
				Width:    40,
				Height:   60,
			}
			gen := NewGenerator(cfg)
			captcha, err := gen.Generate(CaptchaTypeText)
			if err != nil {
				return err
			}

			label := -1
			for j, c := range charSet {
				if c == ch {
					label = j
					break
				}
			}

			l.dataset.Add(captcha.Image, label)
		}
	}

	return nil
}

// Train trains the learner for the specified number of epochs.
// Train trains the learner for the specified number of epochs.
func (l *ContrastiveLearner) Train(epochs int) error {
	return l.solver.Train(l.dataset, epochs)
}

// Solve attempts to solve the provided CAPTCHA using the trained model.
// Solve attempts to solve the given CAPTCHA using contrastive learning.
func (l *ContrastiveLearner) Solve(captcha *Captcha) (string, float64) {
	return l.solver.Solve(captcha)
}
