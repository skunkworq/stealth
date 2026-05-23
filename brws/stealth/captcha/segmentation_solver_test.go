package captcha

import (
	"image"
	"image/color"
	"testing"
)

// TestNewSegmentationSolver verifies constructor returns a properly initialized solver.
func TestNewSegmentationSolver(t *testing.T) {
	ss := NewSegmentationSolver()
	if ss == nil {
		t.Fatal("NewSegmentationSolver() returned nil")
	}
	if ss.charW != 5 {
		t.Errorf("charW: want 5, got %d", ss.charW)
	}
	if ss.charH != 7 {
		t.Errorf("charH: want 7, got %d", ss.charH)
	}
	if ss.charset == "" {
		t.Error("charset should be non-empty")
	}
	if len(ss.templates) == 0 {
		t.Error("expected non-empty templates map after construction")
	}
}

// TestSegmentationSolver_TemplatesMatchCharset verifies that a template exists
// for every character in the charset that also has a font5x7 entry.
func TestSegmentationSolver_TemplatesMatchCharset(t *testing.T) {
	ss := NewSegmentationSolver()

	for _, ch := range ss.charset {
		if _, ok := font5x7[ch]; !ok {
			// Character not in the bitmap font — that's fine, skip
			continue
		}
		if _, ok := ss.templates[ch]; !ok {
			t.Errorf("missing template for charset character %q (present in font5x7)", string(ch))
		}
	}
}

// TestSegmentationSolver_NilImage verifies that SolveWithSegmentation handles
// an edge-case where the image has zero dimensions without panicking.
func TestSegmentationSolver_ZeroBoundsImage(t *testing.T) {
	ss := NewSegmentationSolver()

	// image.NewRGBA with empty bounds produces a zero-dimension image
	img := image.NewRGBA(image.Rectangle{})
	solution, conf := ss.SolveWithSegmentation(img, 6)

	// Must not panic; result should be empty/zero
	if solution != "" {
		t.Errorf("expected empty solution for zero-bounds image, got %q", solution)
	}
	if conf != 0 {
		t.Errorf("expected zero confidence for zero-bounds image, got %f", conf)
	}
}

// TestSegmentationSolver_ZeroNumChars verifies graceful handling of numChars <= 0.
func TestSegmentationSolver_ZeroNumChars(t *testing.T) {
	ss := NewSegmentationSolver()
	img := makeBlankImage(100, 40)

	solution, conf := ss.SolveWithSegmentation(img, 0)
	if solution != "" {
		t.Errorf("expected empty solution for numChars=0, got %q", solution)
	}
	if conf != 0 {
		t.Errorf("expected zero confidence for numChars=0, got %f", conf)
	}
}

// TestSegmentationSolver_NegativeNumChars ensures SolveWithSegmentation doesn't
// panic or produce garbage for negative numChars.
func TestSegmentationSolver_NegativeNumChars(t *testing.T) {
	ss := NewSegmentationSolver()
	img := makeBlankImage(100, 40)

	solution, conf := ss.SolveWithSegmentation(img, -1)
	if solution != "" {
		t.Errorf("expected empty solution for numChars=-1, got %q", solution)
	}
	if conf != 0 {
		t.Errorf("expected zero confidence for numChars=-1, got %f", conf)
	}
}

// TestSegmentationSolver_WhiteImage verifies that a completely white (blank) image
// returns a result of the requested length without panicking.
func TestSegmentationSolver_WhiteImage(t *testing.T) {
	ss := NewSegmentationSolver()
	img := makeBlankImage(60, 20)

	solution, conf := ss.SolveWithSegmentation(img, 6)

	// Should return 6-char string (one rune per segment)
	if len([]rune(solution)) != 6 {
		t.Errorf("expected 6-char solution for 60x20 white image, got %q (len=%d)", solution, len([]rune(solution)))
	}
	// Confidence should be in [0, 1]
	if conf < 0 || conf > 1 {
		t.Errorf("confidence out of range [0,1]: %f", conf)
	}
}

// TestSegmentationSolver_BlackImage verifies that a completely black (all-ink) image
// returns a result of the requested length without panicking.
func TestSegmentationSolver_BlackImage(t *testing.T) {
	ss := NewSegmentationSolver()
	img := makeBlackImage(60, 20)

	solution, conf := ss.SolveWithSegmentation(img, 4)

	if len([]rune(solution)) != 4 {
		t.Errorf("expected 4-char solution for black image, got %q (len=%d)", solution, len([]rune(solution)))
	}
	if conf < 0 || conf > 1 {
		t.Errorf("confidence out of range [0,1]: %f", conf)
	}
}

// TestSegmentationSolver_SingleChar verifies a single-character solve.
func TestSegmentationSolver_SingleChar(t *testing.T) {
	ss := NewSegmentationSolver()
	img := makeBlankImage(20, 20)

	solution, conf := ss.SolveWithSegmentation(img, 1)
	if len([]rune(solution)) != 1 {
		t.Errorf("expected 1-char solution, got %q", solution)
	}
	if conf < 0 || conf > 1 {
		t.Errorf("confidence out of range: %f", conf)
	}
}

// TestSegmentationSolver_VerticalProjection checks that verticalProjection
// returns a slice of length equal to the image width.
func TestSegmentationSolver_VerticalProjection(t *testing.T) {
	ss := NewSegmentationSolver()

	w, h := 30, 10
	binarized := make([]float64, w*h)
	// Set some pixels to 1 for a non-trivial projection
	for i := 0; i < w; i++ {
		binarized[i] = 1.0
	}

	proj := ss.verticalProjection(binarized, w, h)
	if len(proj) != w {
		t.Errorf("expected projection length %d, got %d", w, len(proj))
	}
	// First row was all 1.0, so each column should have at least 1.0 ink
	for i, v := range proj {
		if v < 1.0 {
			t.Errorf("column %d: expected >= 1.0, got %f", i, v)
		}
	}
}

// TestSegmentationSolver_SmoothProjection checks that smoothProjection
// returns a slice of the same length as the input.
func TestSegmentationSolver_SmoothProjection(t *testing.T) {
	ss := NewSegmentationSolver()
	proj := []float64{1, 3, 5, 3, 1, 2, 4, 2}
	smoothed := ss.smoothProjection(proj, 3)

	if len(smoothed) != len(proj) {
		t.Errorf("smoothed length %d != original %d", len(smoothed), len(proj))
	}
}

// TestSegmentationSolver_SelectEvenlySpaced verifies that selecting n valleys
// returns exactly n values.
func TestSegmentationSolver_SelectEvenlySpaced(t *testing.T) {
	ss := NewSegmentationSolver()

	valleys := []int{10, 20, 30, 40, 50, 60}
	result := ss.selectEvenlySpaced(valleys, 3, 80)

	if len(result) != 3 {
		t.Errorf("expected 3 selected valleys, got %d: %v", len(result), result)
	}
	// All selected values should be in the valley list
	valleySet := make(map[int]bool)
	for _, v := range valleys {
		valleySet[v] = true
	}
	for _, v := range result {
		if !valleySet[v] {
			t.Errorf("selected value %d not in valley list %v", v, valleys)
		}
	}
}

// TestSegmentationSolver_SelectEvenlySpaced_EmptyValleys verifies behavior
// with fewer valleys than requested.
func TestSegmentationSolver_SelectEvenlySpaced_Zero(t *testing.T) {
	ss := NewSegmentationSolver()
	result := ss.selectEvenlySpaced([]int{}, 3, 100)
	// With no valleys, should return what it can (empty slice)
	_ = result // must not panic
}

// TestSegmentationSolver_ExtractSegment verifies that extractSegment returns
// a slice of exactly segW*segH elements.
func TestSegmentationSolver_ExtractSegment(t *testing.T) {
	ss := NewSegmentationSolver()

	fullW := 60
	binarized := make([]float64, fullW*20) // 60x20 image

	seg := ss.extractSegment(binarized, fullW, 10, 0, 15, 20)
	if len(seg) != 15*20 {
		t.Errorf("expected segment length %d, got %d", 15*20, len(seg))
	}
}

// TestSegmentationSolver_RotateSegment_Zero verifies that a zero-angle rotation
// returns the original segment unchanged.
func TestSegmentationSolver_RotateSegment_Zero(t *testing.T) {
	ss := NewSegmentationSolver()

	seg := []float64{1, 0, 1, 0, 1, 0, 1}
	seg = append(seg, make([]float64, 7*7-len(seg))...)
	rotated := ss.rotateSegment(seg, 7, 7, 0)

	for i, v := range seg {
		if rotated[i] != v {
			t.Errorf("zero-angle rotation changed pixel at %d: want %f, got %f", i, v, rotated[i])
		}
	}
}

// makeBlankImage creates a white RGBA image of the given dimensions.
func makeBlankImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, white)
		}
	}
	return img
}

// makeBlackImage creates a black RGBA image of the given dimensions.
func makeBlackImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	black := color.RGBA{R: 0, G: 0, B: 0, A: 255}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, black)
		}
	}
	return img
}
