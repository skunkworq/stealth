package captcha

import (
	"math"
	"testing"
)

func TestConv2DLayerForward(t *testing.T) {
	// 1-channel 4x4 input
	input := [][][]float64{
		{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		},
	}

	// 1 output channel, 1 input channel, kernel size 3 (flattened)
	conv := &Conv2DLayer{
		Weights: [][][]float64{
			{
				{0, 1, 0, 1, 0, 1, 0, 1, 0}, // 3x3 kernel (identity-ish)
			},
		},
		Bias:    []float64{0},
		Stride:  1,
		Padding: 1,
	}

	output := conv.forward(input)

	if len(output) != 1 {
		t.Fatalf("expected 1 output channel, got %d", len(output))
	}
	if len(output[0]) != 4 {
		t.Fatalf("expected height 4, got %d", len(output[0]))
	}
	if len(output[0][0]) != 4 {
		t.Fatalf("expected width 4, got %d", len(output[0][0]))
	}

	// With padding=1 and 3x3 kernel, the center pixel at (1,1) should be
	// the weighted sum of its 3x3 neighborhood.
	// Check that output is not just a copy of input (the stub behavior).
	if output[0][1][1] == input[0][1][1] {
		t.Fatal("conv forward produced same value as input — likely still stubbed")
	}
}

func TestConv2DLayerForwardNoPadding(t *testing.T) {
	// 1-channel 4x4 input, no padding, 3x3 kernel → 2x2 output
	input := [][][]float64{
		{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		},
	}

	conv := &Conv2DLayer{
		Weights: [][][]float64{
			{
				{1, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
		Bias:    []float64{0},
		Stride:  1,
		Padding: 0,
	}

	output := conv.forward(input)

	if len(output) != 1 || len(output[0]) != 2 || len(output[0][0]) != 2 {
		t.Fatalf("expected 1x2x2 output, got %dx%dx%d", len(output), len(output[0]), len(output[0][0]))
	}

	// Top-left 3x3 convolved with kernel that picks top-left element.
	if output[0][0][0] != 1 {
		t.Fatalf("expected output[0][0][0] = 1, got %f", output[0][0][0])
	}
	// Second position (shifted right by 1).
	if output[0][0][1] != 2 {
		t.Fatalf("expected output[0][0][1] = 2, got %f", output[0][0][1])
	}
}

func TestBatchNormLayerForward(t *testing.T) {
	input := [][][]float64{
		{
			{1, 2, 3},
			{4, 5, 6},
		},
	}

	bn := &BatchNormLayer{
		Gamma:    []float64{1},
		Beta:     []float64{0},
		Mean:     []float64{3.5},
		Variance: []float64{2.9167},
		Epsilon:  0.001,
	}

	output := bn.forward(input)

	if len(output) != 1 || len(output[0]) != 2 || len(output[0][0]) != 3 {
		t.Fatalf("expected same spatial dims, got %dx%dx%d", len(output), len(output[0]), len(output[0][0]))
	}

	// With mean=3.5 and gamma=1, beta=0, the normalized values should
	// differ from the raw input.
	if output[0][0][0] == input[0][0][0] {
		t.Fatal("batchnorm forward produced same value as input — likely still stubbed")
	}

	// Verify the math: (1 - 3.5) / sqrt(2.9167 + 0.001) ≈ -1.4638
	expected := (1.0 - 3.5) / math.Sqrt(2.9167+0.001)
	if math.Abs(output[0][0][0]-expected) > 0.001 {
		t.Fatalf("expected %f, got %f", expected, output[0][0][0])
	}
}

func TestAddTensors(t *testing.T) {
	a := [][][]float64{
		{{1, 2}, {3, 4}},
		{{5, 6}, {7, 8}},
	}
	b := [][][]float64{
		{{10, 20}, {30, 40}},
		{{50, 60}, {70, 80}},
	}

	result := addTensors(a, b)

	if len(result) != 2 || len(result[0]) != 2 || len(result[0][0]) != 2 {
		t.Fatal("output dimensions mismatch")
	}

	if result[0][0][0] != 11 {
		t.Fatalf("expected 11, got %f", result[0][0][0])
	}
	if result[1][1][1] != 88 {
		t.Fatalf("expected 88, got %f", result[1][1][1])
	}
}

func TestResNetBlockForward(t *testing.T) {
	block := NewResNetBlock(1, 1)
	// Set a simple kernel: picks top-left element of 3x3 neighborhood
	block.conv1.Weights[0][0] = []float64{1, 0, 0, 0, 0, 0, 0, 0, 0}
	block.conv2.Weights[0][0] = []float64{1, 0, 0, 0, 0, 0, 0, 0, 0}

	input := [][][]float64{
		{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		},
	}

	output := block.Forward(input)

	// After two conv layers with padding=1, output should still be 4x4.
	if len(output) != 1 || len(output[0]) != 4 || len(output[0][0]) != 4 {
		t.Fatalf("expected 1x4x4 output, got %dx%dx%d", len(output), len(output[0]), len(output[0][0]))
	}

	// The forward pass should no longer be an identity.
	if output[0][1][1] == input[0][1][1] {
		t.Fatal("ResNet block forward produced identity — conv/bn still stubbed")
	}
}
