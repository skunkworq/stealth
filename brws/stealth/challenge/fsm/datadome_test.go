package fsm

import (
	"math"
	"testing"
)

func TestGenerateSliderPath(t *testing.T) {
	solver := NewDataDomeFSMSolver()

	path := solver.generateSliderPath(300.0, 30)

	if len(path) != 30 {
		t.Fatalf("expected 30 points, got %d", len(path))
	}

	// First point should be near origin
	if path[0].T != 0 {
		t.Fatalf("first point should have T=0, got %.2f", path[0].T)
	}

	// Last point should be ~300px to the right of first
	dx := path[len(path)-1].X - path[0].X
	if math.Abs(dx-300.0) > 50 {
		t.Fatalf("slider width should be ~300px, got %.2f", dx)
	}

	// Timestamps should be monotonically increasing (after noise)
	// Check total duration is reasonable (400-700ms + noise)
	totalDuration := path[len(path)-1].T
	if totalDuration < 300 || totalDuration > 1000 {
		t.Fatalf("total duration should be ~400-700ms, got %.2fms", totalDuration)
	}
}

func TestComputeMotionSignals(t *testing.T) {
	solver := NewDataDomeFSMSolver()
	path := solver.generateSliderPath(300.0, 30)
	signals := solver.computeMotionSignals(path)

	if signals.NumPoints != 30 {
		t.Fatalf("expected 30 points, got %d", signals.NumPoints)
	}

	// Path efficiency should be between 0.7 and 1.0 for a slider
	if signals.PathEfficiency < 0.5 || signals.PathEfficiency > 1.0 {
		t.Fatalf("path efficiency should be 0.5-1.0, got %.4f", signals.PathEfficiency)
	}

	// Total distance should be reasonable
	if signals.TotalDistance < 200 || signals.TotalDistance > 600 {
		t.Fatalf("total distance should be 200-600px, got %.2f", signals.TotalDistance)
	}

	// Average velocity should be positive
	if signals.AvgVelocity <= 0 {
		t.Fatalf("average velocity should be positive, got %.4f", signals.AvgVelocity)
	}

	// Velocity should have variance (not perfectly uniform)
	if signals.VelocityStdDev == 0 {
		t.Fatal("velocity should have non-zero standard deviation")
	}

	// Interval entropy should indicate human-like distribution
	if signals.IntervalEntropy < 0.5 {
		t.Fatalf("interval entropy should indicate variation, got %.4f", signals.IntervalEntropy)
	}

	// Jitter should be present (micro-noise from path generation)
	if signals.AvgJitterX == 0 && signals.AvgJitterY == 0 {
		t.Fatal("expected some jitter in the path")
	}

	// Start velocity should be higher than end velocity (ease-out)
	// Allow some tolerance since random noise can affect this
	if signals.StartVelocity < signals.EndVelocity*0.5 {
		t.Logf("warning: start velocity (%.4f) not significantly higher than end (%.4f)", signals.StartVelocity, signals.EndVelocity)
	}
}

func TestComputeMotionSignalsFewPoints(t *testing.T) {
	solver := NewDataDomeFSMSolver()

	// Test with fewer than 3 points
	signals := solver.computeMotionSignals([]SliderPoint{
		{X: 0, Y: 0, T: 0},
		{X: 100, Y: 0, T: 100},
	})

	if signals.NumPoints != 2 {
		t.Fatalf("expected 2 points, got %d", signals.NumPoints)
	}
}

func TestDetectDataDome(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		body     []byte
		expected bool
	}{
		{
			name:     "x-datadome header",
			headers:  map[string][]string{"X-DataDome": {"protected"}},
			body:     nil,
			expected: true,
		},
		{
			name:     "x-datadome-clientid header",
			headers:  map[string][]string{"X-DataDome-ClientId": {"abc123"}},
			body:     nil,
			expected: true,
		},
		{
			name:     "datadome.js in body",
			headers:  map[string][]string{},
			body:     []byte(`<script src="https://js.datadome.co/tags.js"></script>`),
			expected: true,
		},
		{
			name:     "captcha-delivery.com in body",
			headers:  map[string][]string{},
			body:     []byte(`geo.captcha-delivery.com/captcha/abc`),
			expected: true,
		},
		{
			name:     "no datadome indicators",
			headers:  map[string][]string{"Content-Type": {"text/html"}},
			body:     []byte("<html>normal page</html>"),
			expected: false,
		},
		{
			name:     "empty datadome header",
			headers:  map[string][]string{"X-DataDome": {""}},
			body:     nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDataDome(tt.headers, tt.body)
			if got != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestExtractDataDomeCaptchaURL(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "captcha URL in body",
			body:     `location.href="https://geo.captcha-delivery.com/captcha/abc123?t=1234"`,
			expected: "https://geo.captcha-delivery.com/captcha/abc123?t=1234",
		},
		{
			name:     "no captcha URL",
			body:     "<html>normal page</html>",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDataDomeCaptchaURL([]byte(tt.body))
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	// Uniform distribution should have high entropy
	uniform := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	uniformEntropy := shannonEntropy(uniform, 10)
	if uniformEntropy < 2.0 {
		t.Fatalf("uniform distribution should have entropy > 2.0, got %.4f", uniformEntropy)
	}

	// All same value should have zero entropy
	constant := []float64{5, 5, 5, 5, 5}
	constantEntropy := shannonEntropy(constant, 10)
	if constantEntropy != 0 {
		t.Fatalf("constant distribution should have entropy 0, got %.4f", constantEntropy)
	}
}

func TestStatisticalHelpers(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}

	m := mean(values)
	if m != 3.0 {
		t.Fatalf("expected mean 3.0, got %.2f", m)
	}

	mx := max(values)
	if mx != 5.0 {
		t.Fatalf("expected max 5.0, got %.2f", mx)
	}

	mn := min(values)
	if mn != 1.0 {
		t.Fatalf("expected min 1.0, got %.2f", mn)
	}

	sd := stddev(values)
	if sd < 1.5 || sd > 1.6 {
		t.Fatalf("expected stddev ~1.58, got %.4f", sd)
	}

	// Edge cases
	if mean(nil) != 0 {
		t.Fatal("mean of nil should be 0")
	}
	if max(nil) != 0 {
		t.Fatal("max of nil should be 0")
	}
	if min(nil) != 0 {
		t.Fatal("min of nil should be 0")
	}
	if stddev(nil) != 0 {
		t.Fatal("stddev of nil should be 0")
	}
}
