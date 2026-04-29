package captcha

import (
	"fmt"
	"math"
)

// ModelConfig holds configuration for a neural network model.
type ModelConfig struct {
	InputDim     int
	HiddenDims   []int
	OutputDim    int
	NumClasses   int
	UseBatchNorm bool
	Dropout      float64
	Activation   string
}

// DefaultModelConfig provides default model configuration.
var DefaultModelConfig = ModelConfig{
	InputDim:     2400,
	HiddenDims:   []int{512, 256, 128},
	OutputDim:    128,
	NumClasses:   36,
	UseBatchNorm: true,
	Dropout:      0.2,
	Activation:   "relu",
}

// Model represents a neural network for CAPTCHA solving.
type Model struct {
	config   *ModelConfig
	layers   []Layer
	classify *ClassificationHead
}

// Layer represents a neural network layer.
type Layer struct {
	Weights     [][]float64
	Bias        []float64
	Output      []float64
	Input       []float64
	GradWeights [][]float64
	GradBias    []float64
	Type        string
}

// ClassificationHead represents the output classification layer.
type ClassificationHead struct {
	weights [][]float64
	bias    []float64
}

// NewModel creates a new neural network model with the given config.
func NewModel(config *ModelConfig) *Model {
	if config == nil {
		config = &DefaultModelConfig
	}

	m := &Model{
		config:   config,
		layers:   make([]Layer, 0),
		classify: &ClassificationHead{},
	}

	prevDim := config.InputDim
	for i, hiddenDim := range config.HiddenDims {
		layer := Layer{
			Weights:     initWeightMatrix(hiddenDim, prevDim),
			Bias:        make([]float64, hiddenDim),
			Output:      make([]float64, hiddenDim),
			Input:       make([]float64, prevDim),
			GradWeights: make([][]float64, hiddenDim),
			GradBias:    make([]float64, hiddenDim),
			Type:        fmt.Sprintf("dense_%d", i),
		}
		for j := range layer.GradWeights {
			layer.GradWeights[j] = make([]float64, prevDim)
		}
		m.layers = append(m.layers, layer)
		prevDim = hiddenDim
	}

	m.classify.weights = initWeightMatrix(config.NumClasses, prevDim)
	m.classify.bias = make([]float64, config.NumClasses)

	return m
}

// Forward runs the model forward pass with the given input.
func (m *Model) Forward(input []float64) []float64 {
	current := input

	for i := range m.layers {
		m.layers[i].Input = current
		m.layers[i].Output = m.layers[i].forward(current)
		current = m.layers[i].Output
	}

	return m.classify.forward(current)
}

func (l *Layer) forward(input []float64) []float64 {
	output := make([]float64, len(l.Bias))

	for i := range output {
		sum := l.Bias[i]
		for j := range input {
			if j < len(l.Weights) && i < len(l.Weights[j]) {
				sum += l.Weights[i][j] * input[j]
			}
		}
		output[i] = activate(sum)
	}

	return output
}

func activate(x float64) float64 {
	switch {
	case x > 0:
		return x
	default:
		return 0
	}
}

func (c *ClassificationHead) forward(input []float64) []float64 {
	logits := make([]float64, len(c.bias))

	for i := range logits {
		sum := c.bias[i]
		for j := range input {
			if j < len(c.weights) && i < len(c.weights[j]) {
				sum += c.weights[i][j] * input[j]
			}
		}
		logits[i] = sum
	}

	return modelSoftmax(logits)
}

func modelSoftmax(logits []float64) []float64 {
	maxLogit := math.Inf(-1)
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

// Backward performs backpropagation to update model weights.
func (m *Model) Backward(target []int, learningRate float64) {
	numClasses := len(target)
	if numClasses == 0 {
		return
	}

	gradOutput := make([]float64, len(m.classify.bias))
	for i := range gradOutput {
		if i < len(target) {
			prob := m.classify.forward(m.layers[len(m.layers)-1].Output)[i]
			gradOutput[i] = prob - 1.0/float64(numClasses)
		}
	}

	for i := len(m.layers) - 1; i >= 0; i-- {
		layer := &m.layers[i]
		gradInput := make([]float64, len(layer.Input))

		for j := range layer.Output {
			for k := range layer.Input {
				if j < len(layer.Weights) && k < len(layer.Weights[j]) {
					layer.GradWeights[j][k] = gradOutput[j] * layer.Input[k]
					layer.Weights[j][k] -= learningRate * layer.GradWeights[j][k]
				}
			}
			layer.Bias[j] -= learningRate * gradOutput[j]
		}

		for k := range gradInput {
			for j := range layer.Output {
				if j < len(layer.Weights) && k < len(layer.Weights[j]) {
					gradInput[k] += gradOutput[j] * layer.Weights[j][k]
				}
			}
		}

		gradOutput = gradInput
	}
}

// Predict returns the predicted class and confidence for the input.
func (m *Model) Predict(input []float64) (int, float64) {
	probs := m.Forward(input)

	maxProb := 0.0
	maxClass := 0
	for i, p := range probs {
		if p > maxProb {
			maxProb = p
			maxClass = i
		}
	}

	return maxClass, maxProb
}

// ResNetBlock represents a residual network block.
type ResNetBlock struct {
	conv1    *Conv2DLayer
	conv2    *Conv2DLayer
	shortcut *Conv2DLayer
	bn1      *BatchNormLayer
	bn2      *BatchNormLayer
}

// Conv2DLayer represents a 2D convolutional layer.
type Conv2DLayer struct {
	Weights [][][]float64
	Bias    []float64
	Stride  int
	Padding int
}

// BatchNormLayer represents a batch normalization layer.
type BatchNormLayer struct {
	Gamma    []float64
	Beta     []float64
	Mean     []float64
	Variance []float64
	Epsilon  float64
}

// NewResNetBlock creates a new residual network block.
func NewResNetBlock(inputChannels, outputChannels int) *ResNetBlock {
	block := &ResNetBlock{}

	block.conv1 = &Conv2DLayer{
		Weights: make([][][]float64, outputChannels),
		Bias:    make([]float64, outputChannels),
		Stride:  1,
		Padding: 1,
	}
	for i := range block.conv1.Weights {
		block.conv1.Weights[i] = make([][]float64, inputChannels)
		for j := range block.conv1.Weights[i] {
			block.conv1.Weights[i][j] = make([]float64, 3)
		}
	}

	block.conv2 = &Conv2DLayer{
		Weights: make([][][]float64, outputChannels),
		Bias:    make([]float64, outputChannels),
		Stride:  1,
		Padding: 1,
	}
	for i := range block.conv2.Weights {
		block.conv2.Weights[i] = make([][]float64, outputChannels)
		for j := range block.conv2.Weights[i] {
			block.conv2.Weights[i][j] = make([]float64, 3)
		}
	}

	if inputChannels != outputChannels {
		block.shortcut = &Conv2DLayer{
			Weights: make([][][]float64, outputChannels),
			Bias:    make([]float64, outputChannels),
			Stride:  1,
			Padding: 0,
		}
	}

	block.bn1 = &BatchNormLayer{
		Gamma:    make([]float64, outputChannels),
		Beta:     make([]float64, outputChannels),
		Mean:     make([]float64, outputChannels),
		Variance: make([]float64, outputChannels),
		Epsilon:  0.001,
	}

	block.bn2 = &BatchNormLayer{
		Gamma:    make([]float64, outputChannels),
		Beta:     make([]float64, outputChannels),
		Mean:     make([]float64, outputChannels),
		Variance: make([]float64, outputChannels),
		Epsilon:  0.001,
	}

	return block
}

// Forward runs the forward pass through the ResNet block.
func (r *ResNetBlock) Forward(x [][][]float64) [][][]float64 {
	out := r.conv1.forward(x)
	out = r.bn1.forward(out)
	out = r.conv2.forward(out)
	out = r.bn2.forward(out)

	if r.shortcut != nil {
		shortcut := r.shortcut.forward(x)
		out = addTensors(out, shortcut)
	}

	return out
}

func (c *Conv2DLayer) forward(x [][][]float64) [][][]float64 {
	return x
}

func (b *BatchNormLayer) forward(x [][][]float64) [][][]float64 {
	return x
}

func addTensors(a, b [][][]float64) [][][]float64 {
	if len(a) != len(b) {
		return a
	}
	return a
}

// CNNModel represents a convolutional neural network model.
type CNNModel struct {
	config     *ModelConfig
	convLayers []Conv2DLayer
	bnLayers   []BatchNormLayer
	fcLayers   []Layer
	classify   *ClassificationHead
}

// NewCNNModel creates a new CNN model with the given configuration.
func NewCNNModel(config *ModelConfig) *CNNModel {
	if config == nil {
		config = &DefaultModelConfig
	}

	m := &CNNModel{
		config:     config,
		convLayers: make([]Conv2DLayer, 0),
		bnLayers:   make([]BatchNormLayer, 0),
		fcLayers:   make([]Layer, 0),
	}

	channels := []int{32, 64, 128}
	for _, ch := range channels {
		conv := Conv2DLayer{
			Weights: make([][][]float64, ch),
			Bias:    make([]float64, ch),
			Stride:  1,
			Padding: 1,
		}
		for i := range conv.Weights {
			conv.Weights[i] = make([][]float64, ch)
			for j := range conv.Weights[i] {
				conv.Weights[i][j] = make([]float64, 3)
			}
		}
		m.convLayers = append(m.convLayers, conv)

		bn := BatchNormLayer{
			Gamma:    make([]float64, ch),
			Beta:     make([]float64, ch),
			Mean:     make([]float64, ch),
			Variance: make([]float64, ch),
			Epsilon:  0.001,
		}
		m.bnLayers = append(m.bnLayers, bn)
	}

	m.classify = &ClassificationHead{}

	return m
}

// Forward computes the forward pass through the CNN model.
func (m *CNNModel) Forward(input [][][]float64) []float64 {
	current := input

	for i := range m.convLayers {
		current = m.convLayers[i].forward(current)
		current = m.bnLayers[i].forward(current)
	}

	flat := flatten(current)

	for i := range m.fcLayers {
		m.fcLayers[i].Output = m.fcLayers[i].forward(flat)
		flat = m.fcLayers[i].Output
	}

	return m.classify.forward(flat)
}

func flatten(x [][][]float64) []float64 {
	size := len(x) * len(x[0]) * len(x[0][0])
	result := make([]float64, 0, size)
	for i := range x {
		for j := range x[i] {
			result = append(result, x[i][j]...)
		}
	}
	return result
}

// Predict makes a prediction using the CNN model and returns the class with confidence.
func (m *CNNModel) Predict(input [][][]float64) (int, float64) {
	probs := m.Forward(input)

	maxProb := 0.0
	maxClass := 0
	for i, p := range probs {
		if p > maxProb {
			maxProb = p
			maxClass = i
		}
	}

	return maxClass, maxProb
}
