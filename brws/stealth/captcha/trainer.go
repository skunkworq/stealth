package captcha

import (
	"fmt"
	"image"
	"math"
	"time"
)

// Trainer manages the training process for CAPTCHA solving models.
type Trainer struct {
	model     *Model
	config    *TrainerConfig
	optimizer *Optimizer
	scheduler *LearningRateScheduler
	metrics   *TrainingMetrics
}

// TrainerConfig holds configuration for model training.
type TrainerConfig struct {
	Epochs          int
	BatchSize       int
	LearningRate    float64
	Momentum        float64
	WeightDecay     float64
	ValidationSplit float64
	EarlyStopping   bool
	Patience        int
	CheckpointDir   string
	LogInterval     int
}

// DefaultTrainerConfig provides default training configuration.
var DefaultTrainerConfig = TrainerConfig{
	Epochs:          100,
	BatchSize:       32,
	LearningRate:    0.001,
	Momentum:        0.9,
	WeightDecay:     0.0001,
	ValidationSplit: 0.2,
	EarlyStopping:   true,
	Patience:        10,
	LogInterval:     10,
}

// Optimizer implements gradient descent optimization.
type Optimizer struct {
	learningRate float64
	weightDecay  float64
}

// NewOptimizer creates a new optimizer with the given parameters.
func NewOptimizer(learningRate, _ /* momentum */, weightDecay float64) *Optimizer {
	return &Optimizer{
		learningRate: learningRate,
		weightDecay:  weightDecay,
	}
}

// Update updates weights and biases using computed gradients (SGD with weight decay).
func (o *Optimizer) Update(weights, gradients [][]float64, biases, biasGradients []float64) {
	for i := range weights {
		for j := range weights[i] {
			grad := gradients[i][j] + o.weightDecay*weights[i][j]
			weights[i][j] -= o.learningRate * grad
		}
	}

	for i := range biases {
		biasGrad := biasGradients[i] + o.weightDecay*biases[i]
		biases[i] -= o.learningRate * biasGrad
	}
}

// LearningRateScheduler adjusts the learning rate during training.
type LearningRateScheduler struct {
	initialLR    float64
	currentEpoch int
	decayType    string
	decayRate    float64
	stepSize     int
}

// NewLearningRateScheduler creates a new learning rate scheduler.
func NewLearningRateScheduler(initialLR float64, decayType string, decayRate float64, stepSize int) *LearningRateScheduler {
	return &LearningRateScheduler{
		initialLR: initialLR,
		decayType: decayType,
		decayRate: decayRate,
		stepSize:  stepSize,
	}
}

// Step returns the learning rate for the given epoch.
func (s *LearningRateScheduler) Step(epoch int) float64 {
	s.currentEpoch = epoch

	switch s.decayType {
	case "step":
		return s.stepDecay(epoch)
	case "exponential":
		return s.exponentialDecay(epoch)
	case "cosine":
		return s.cosineDecay(epoch)
	case "plateau":
		return s.initialLR
	default:
		return s.initialLR
	}
}

func (s *LearningRateScheduler) stepDecay(epoch int) float64 {
	drop := math.Pow(s.decayRate, float64(epoch/s.stepSize))
	return s.initialLR * drop
}

func (s *LearningRateScheduler) exponentialDecay(epoch int) float64 {
	return s.initialLR * math.Pow(s.decayRate, float64(epoch))
}

func (s *LearningRateScheduler) cosineDecay(epoch int) float64 {
	cosineAnnealing := 0.5 * (1 + math.Cos(math.Pi*float64(epoch)/float64(s.stepSize)))
	return s.initialLR * cosineAnnealing
}

// TrainingMetrics holds training and validation metrics over epochs.
type TrainingMetrics struct {
	TrainLoss     []float64
	TrainAcc      []float64
	ValLoss       []float64
	ValAcc        []float64
	EpochTimes    []time.Duration
	LearningRates []float64
}

// NewTrainingMetrics creates a new TrainingMetrics instance.
func NewTrainingMetrics() *TrainingMetrics {
	return &TrainingMetrics{
		TrainLoss:     make([]float64, 0),
		TrainAcc:      make([]float64, 0),
		ValLoss:       make([]float64, 0),
		ValAcc:        make([]float64, 0),
		EpochTimes:    make([]time.Duration, 0),
		LearningRates: make([]float64, 0),
	}
}

// Record records metrics for a training epoch.
func (m *TrainingMetrics) Record(_ int, trainLoss, trainAcc, valLoss, valAcc float64, epochTime time.Duration, lr float64) {
	m.TrainLoss = append(m.TrainLoss, trainLoss)
	m.TrainAcc = append(m.TrainAcc, trainAcc)
	m.ValLoss = append(m.ValLoss, valLoss)
	m.ValAcc = append(m.ValAcc, valAcc)
	m.EpochTimes = append(m.EpochTimes, epochTime)
	m.LearningRates = append(m.LearningRates, lr)
}

// GetBestEpoch returns the epoch with the lowest validation loss.
func (m *TrainingMetrics) GetBestEpoch() (int, float64) {
	bestEpoch := 0
	bestLoss := math.MaxFloat64

	for i, loss := range m.ValLoss {
		if loss < bestLoss {
			bestLoss = loss
			bestEpoch = i
		}
	}

	return bestEpoch, bestLoss
}

// NewTrainer creates a new Trainer instance with the given model and configuration.
func NewTrainer(model *Model, config *TrainerConfig) *Trainer {
	if config == nil {
		config = &DefaultTrainerConfig
	}

	return &Trainer{
		model:     model,
		config:    config,
		optimizer: NewOptimizer(config.LearningRate, config.Momentum, config.WeightDecay),
		scheduler: NewLearningRateScheduler(config.LearningRate, "cosine", 0.1, config.Epochs),
		metrics:   NewTrainingMetrics(),
	}
}

// TrainingData holds image and label data for training.
type TrainingData struct {
	Images [][]float64
	Labels []int
}

// NewTrainingData creates a new TrainingData instance.
func NewTrainingData() *TrainingData {
	return &TrainingData{
		Images: make([][]float64, 0),
		Labels: make([]int, 0),
	}
}

// Add adds an image and its label to the training data.
func (t *TrainingData) Add(image []float64, label int) {
	t.Images = append(t.Images, image)
	t.Labels = append(t.Labels, label)
}

// Split splits the training data into training and validation sets by ratio.
func (t *TrainingData) Split(ratio float64) (*TrainingData, *TrainingData) {
	splitIdx := int(float64(len(t.Images)) * ratio)

	newData := &TrainingData{
		Images: t.Images[:splitIdx],
		Labels: t.Labels[:splitIdx],
	}
	val := &TrainingData{
		Images: t.Images[splitIdx:],
		Labels: t.Labels[splitIdx:],
	}

	return newData, val
}

// Train trains the model on the provided training data.
func (t *Trainer) Train(data *TrainingData) error {
	trn, val := data.Split(t.config.ValidationSplit)

	fmt.Printf("Training on %d samples, validating on %d samples\n", len(trn.Images), len(val.Images))

	bestValLoss := math.MaxFloat64
	patienceCounter := 0

	for epoch := 0; epoch < t.config.Epochs; epoch++ {
		startTime := time.Now()

		lr := t.scheduler.Step(epoch)
		t.optimizer.learningRate = lr

		trainLoss, trainAcc := t.trainEpoch(trn)
		valLoss, valAcc := t.validate(val)

		epochTime := time.Since(startTime)

		t.metrics.Record(epoch, trainLoss, trainAcc, valLoss, valAcc, epochTime, lr)

		if epoch%t.config.LogInterval == 0 {
			fmt.Printf("Epoch %d/%d - Time: %v - LR: %.6f - Train Loss: %.4f - Train Acc: %.4f - Val Loss: %.4f - Val Acc: %.4f\n",
				epoch+1, t.config.Epochs, epochTime, lr, trainLoss, trainAcc, valLoss, valAcc)
		}

		if valLoss < bestValLoss {
			bestValLoss = valLoss
			patienceCounter = 0
		} else {
			patienceCounter++
		}

		if t.config.EarlyStopping && patienceCounter >= t.config.Patience {
			fmt.Printf("Early stopping at epoch %d\n", epoch+1)
			break
		}
	}

	bestEpoch, bestLoss := t.metrics.GetBestEpoch()
	fmt.Printf("Best epoch: %d with validation loss: %.4f\n", bestEpoch+1, bestLoss)

	return nil
}

func (t *Trainer) trainEpoch(data *TrainingData) (float64, float64) {
	totalLoss := 0.0
	correct := 0
	total := 0

	batches := data.getBatches(t.config.BatchSize)

	for _, batch := range batches {
		batchLoss := 0.0

		learningRate := t.optimizer.learningRate
		for i, img := range batch.Images {
			label := batch.Labels[i]
			output := t.model.Forward(img)

			loss := t.crossEntropyLoss(output, label)
			batchLoss += loss

			if t.argmax(output) == label {
				correct++
			}
			total++

			t.model.Backward(label, learningRate)
		}

		batchLoss /= float64(len(batch.Images))
		totalLoss += batchLoss
	}

	avgLoss := totalLoss / float64(len(batches))
	accuracy := float64(correct) / float64(total)

	return avgLoss, accuracy
}

func (t *Trainer) validate(data *TrainingData) (float64, float64) {
	totalLoss := 0.0
	correct := 0
	total := 0

	batches := data.getBatches(t.config.BatchSize)

	for _, batch := range batches {
		for i := range batch.Images {
			img := batch.Images[i]
			label := batch.Labels[i]
			output := t.model.Forward(img)

			loss := t.crossEntropyLoss(output, label)
			totalLoss += loss

			if t.argmax(output) == label {
				correct++
			}
			total++
		}
	}

	if total == 0 {
		return 0, 0
	}
	avgLoss := totalLoss / float64(total)
	accuracy := float64(correct) / float64(total)

	return avgLoss, accuracy
}

func (t *Trainer) crossEntropyLoss(output []float64, target int) float64 {
	if target < 0 || target >= len(output) {
		return 0
	}
	return -math.Log(output[target] + 1e-10)
}

func (t *Trainer) argmax(slice []float64) int {
	maxIdx := 0
	maxVal := math.Inf(-1)
	for i, v := range slice {
		if v > maxVal {
			maxVal = v
			maxIdx = i
		}
	}
	return maxIdx
}

func (t *TrainingData) getBatches(batchSize int) []TrainingData {
	batches := make([]TrainingData, 0)

	for i := 0; i < len(t.Images); i += batchSize {
		end := i + batchSize
		if end > len(t.Images) {
			end = len(t.Images)
		}

		batch := TrainingData{
			Images: t.Images[i:end],
			Labels: t.Labels[i:end],
		}
		batches = append(batches, batch)
	}

	return batches
}

// GetMetrics returns the training metrics.
func (t *Trainer) GetMetrics() *TrainingMetrics {
	return t.metrics
}

// DataAugmenter provides data augmentation for training images.
type DataAugmenter struct {
	config *AugmentationConfig
}

// ImageAugmentation is a function type for image augmentation.
type ImageAugmentation func(image.Image) image.Image

// NewDataAugmenter creates a new data augmenter with the given configuration.
func NewDataAugmenter(config *AugmentationConfig) *DataAugmenter {
	if config == nil {
		config = &AugmentationConfig{
			Rotation:    true,
			Noise:       true,
			Crop:        true,
			ColorJitter: true,
		}
	}
	return &DataAugmenter{config: config}
}

// Augment applies Gaussian noise to an image and returns the result.
func (a *DataAugmenter) Augment(img image.Image) image.Image {
	if !a.config.Noise {
		return img
	}
	bounds := img.Bounds()
	out := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, alpha := img.At(x, y).RGBA()
			noise := uint32((x*31+y*17)%21) - 10 // deterministic ±10 out of 65535
			clamp := func(v uint32) uint8 {
				if int32(v)+int32(noise) < 0 {
					return 0
				}
				if int32(v)+int32(noise) > 65535 {
					return 255
				}
				return uint8((v + noise) >> 8)
			}
			out.SetRGBA(x, y, struct{ R, G, B, A uint8 }{clamp(r), clamp(g), clamp(b), uint8(alpha >> 8)})
		}
	}
	return out
}

// CreateAugmentedDataset creates an augmented dataset from the training data.
// Only noise augmentation is applied; rotation and crop require known image
// dimensions and are omitted to avoid silently producing identity duplicates.
func (a *DataAugmenter) CreateAugmentedDataset(data *TrainingData) *TrainingData {
	augmented := NewTrainingData()

	for i, img := range data.Images {
		augmented.Add(img, data.Labels[i])

		if a.config.Noise {
			for j := 0; j < 3; j++ {
				augmented.Add(a.addNoise(img, j+1), data.Labels[i])
			}
		}
	}

	return augmented
}

func (a *DataAugmenter) addNoise(img []float64, seed int) []float64 {
	result := make([]float64, len(img))
	scale := 0.02 * float64(seed)
	for i, v := range img {
		// Pseudo-random noise using index and seed without importing math/rand
		noise := (float64((i*31+seed*17)%21) - 10) * scale * 0.01
		result[i] = math.Max(0, math.Min(1, v+noise))
	}
	return result
}
