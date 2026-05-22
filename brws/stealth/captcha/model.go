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
	layers   []layer
	classify *ClassificationHead
}

// layer represents a neural network layer.
type layer struct {
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
		layers:   make([]layer, 0),
		classify: &ClassificationHead{},
	}

	prevDim := config.InputDim
	for i, hiddenDim := range config.HiddenDims {
		layer := layer{
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

func (l *layer) forward(input []float64) []float64 {
	output := make([]float64, len(l.Bias))

	for i := range output {
		sum := l.Bias[i]
		for j := range input {
			if i < len(l.Weights) && j < len(l.Weights[i]) {
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
			if i < len(c.weights) && j < len(c.weights[i]) {
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
// target must be a one-hot encoded slice of length numClasses (e.g. [0,0,1,0,...])
// where target[i]=1 for the correct class and 0 elsewhere. Passing a class index
// instead (e.g. [2]) will produce incorrect gradients.
func (m *Model) Backward(target []int, learningRate float64) {
	if len(target) == 0 {
		return
	}

	// If target looks like a single class index (len==1 and target[0] >= len(bias)),
	// it's a misuse; skip silently to avoid corrupting weights.
	if len(target) == 1 && len(m.classify.bias) > 1 {
		return
	}

	// Cross-entropy gradient: dL/dlogit_i = prob_i - target_i (one-hot)
	probs := m.classify.forward(m.layers[len(m.layers)-1].Output)
	gradOutput := make([]float64, len(m.classify.bias))
	for i := range gradOutput {
		label := 0.0
		if i < len(target) {
			label = float64(target[i])
		}
		gradOutput[i] = probs[i] - label
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
	conv1    *conv2DLayer
	conv2    *conv2DLayer
	shortcut *conv2DLayer
	bn1      *batchNormLayer
	bn2      *batchNormLayer
}

// conv2DLayer represents a 2D convolutional layer.
type conv2DLayer struct {
	Weights [][][]float64
	Bias    []float64
	Stride  int
	Padding int
}

// batchNormLayer represents a batch normalization layer.
type batchNormLayer struct {
	Gamma    []float64
	Beta     []float64
	Mean     []float64
	Variance []float64
	Epsilon  float64
}

// NewResNetBlock creates a new residual network block.
func NewResNetBlock(inputChannels, outputChannels int) *ResNetBlock {
	block := &ResNetBlock{}

	block.conv1 = &conv2DLayer{
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

	block.conv2 = &conv2DLayer{
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
		block.shortcut = &conv2DLayer{
			Weights: make([][][]float64, outputChannels),
			Bias:    make([]float64, outputChannels),
			Stride:  1,
			Padding: 0,
		}
	}

	block.bn1 = &batchNormLayer{
		Gamma:    make([]float64, outputChannels),
		Beta:     make([]float64, outputChannels),
		Mean:     make([]float64, outputChannels),
		Variance: make([]float64, outputChannels),
		Epsilon:  0.001,
	}

	block.bn2 = &batchNormLayer{
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

func (c *conv2DLayer) forward(x [][][]float64) [][][]float64 {
	if len(x) == 0 || len(x[0]) == 0 || len(x[0][0]) == 0 {
		return x
	}

	inChannels := len(x)
	inHeight := len(x[0])
	inWidth := len(x[0][0])
	outChannels := len(c.Weights)
	if outChannels == 0 {
		return x
	}

	// Derive kernel dimensions from flattened weight storage.
	kernelElements := len(c.Weights[0][0])
	kernelSize := int(math.Sqrt(float64(kernelElements)))
	var kernelHeight, kernelWidth int
	if kernelSize*kernelSize == kernelElements {
		kernelHeight, kernelWidth = kernelSize, kernelSize
	} else {
		kernelHeight, kernelWidth = 1, kernelElements
	}

	pad := c.Padding
	stride := c.Stride
	outHeight := (inHeight+2*pad-kernelHeight)/stride + 1
	outWidth := (inWidth+2*pad-kernelWidth)/stride + 1
	if outHeight <= 0 || outWidth <= 0 {
		return x
	}

	// Allocate output tensor.
	output := make([][][]float64, outChannels)
	for oc := range output {
		output[oc] = make([][]float64, outHeight)
		for h := range output[oc] {
			output[oc][h] = make([]float64, outWidth)
		}
	}

	// Perform convolution: for each output channel and spatial position,
	// sum over input channels and kernel elements.
	for oc := 0; oc < outChannels; oc++ {
		for oh := 0; oh < outHeight; oh++ {
			for ow := 0; ow < outWidth; ow++ {
				sum := c.Bias[oc]
				for ic := 0; ic < inChannels; ic++ {
					for kh := 0; kh < kernelHeight; kh++ {
						for kw := 0; kw < kernelWidth; kw++ {
							ih := oh*stride + kh - pad
							iw := ow*stride + kw - pad
							if ih >= 0 && ih < inHeight && iw >= 0 && iw < inWidth {
								wIdx := kh*kernelWidth + kw
								sum += c.Weights[oc][ic][wIdx] * x[ic][ih][iw]
							}
						}
					}
				}
				output[oc][oh][ow] = sum
			}
		}
	}

	return output
}

func (b *batchNormLayer) forward(x [][][]float64) [][][]float64 {
	if len(x) == 0 {
		return x
	}

	channels := len(x)
	height := len(x[0])
	if height == 0 {
		return x
	}
	width := len(x[0][0])

	output := make([][][]float64, channels)
	for c := 0; c < channels; c++ {
		output[c] = make([][]float64, height)
		for h := 0; h < height; h++ {
			output[c][h] = make([]float64, width)
			for w := 0; w < width; w++ {
				normalized := (x[c][h][w] - b.Mean[c]) / math.Sqrt(b.Variance[c]+b.Epsilon)
				output[c][h][w] = b.Gamma[c]*normalized + b.Beta[c]
			}
		}
	}

	return output
}

func addTensors(a, b [][][]float64) [][][]float64 {
	if len(a) != len(b) {
		return a
	}

	output := make([][][]float64, len(a))
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return a
		}
		output[i] = make([][]float64, len(a[i]))
		for j := range a[i] {
			if len(a[i][j]) != len(b[i][j]) {
				return a
			}
			output[i][j] = make([]float64, len(a[i][j]))
			for k := range a[i][j] {
				output[i][j][k] = a[i][j][k] + b[i][j][k]
			}
		}
	}

	return output
}

// CNNModel represents a convolutional neural network model.
type CNNModel struct {
	config     *ModelConfig
	convLayers []conv2DLayer
	bnLayers   []batchNormLayer
	fcLayers   []layer
	classify   *ClassificationHead
}

// NewCNNModel creates a new CNN model with the given configuration.
func NewCNNModel(config *ModelConfig) *CNNModel {
	if config == nil {
		config = &DefaultModelConfig
	}

	m := &CNNModel{
		config:     config,
		convLayers: make([]conv2DLayer, 0),
		bnLayers:   make([]batchNormLayer, 0),
		fcLayers:   make([]layer, 0),
	}

	channels := []int{32, 64, 128}
	for _, ch := range channels {
		conv := conv2DLayer{
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

		bn := batchNormLayer{
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
