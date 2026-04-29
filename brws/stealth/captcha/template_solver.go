package captcha

import (
	"image"
	"math"
	"strings"
)

// TemplateSolver solves captchas using pixel-correlation template matching against
// clean character bitmaps rendered with the same font as the generator.
// Intentionally imperfect (~60-80% per-char) to make the arms race interesting.
type TemplateSolver struct {
	templates  map[rune][]float64 // flattened grayscale bitmap per char
	charWidth  int
	charHeight int
	charset    string
}

// NewTemplateSolver creates a TemplateSolver with pre-rendered character templates
// matching the generator's font5x7 bitmap font.
func NewTemplateSolver() *TemplateSolver {
	ts := &TemplateSolver{
		templates:  make(map[rune][]float64),
		charWidth:  5,
		charHeight: 7,
		charset:    DefaultConfig.CharSet,
	}
	ts.initTemplates()
	return ts
}

// initTemplates renders each character from the charset into a normalized float template.
func (ts *TemplateSolver) initTemplates() {
	for _, ch := range ts.charset {
		bitmap, ok := font5x7[ch]
		if !ok {
			continue
		}
		template := make([]float64, ts.charWidth*ts.charHeight)
		for row := 0; row < 7; row++ {
			for col := 0; col < 5; col++ {
				if (bitmap[row]>>(7-col))&1 == 1 {
					template[row*ts.charWidth+col] = 1.0
				}
			}
		}
		ts.templates[ch] = template
	}
}

// SolveWithTemplates attempts to solve a captcha image by template matching.
// Returns the predicted string and average per-character confidence.
func (ts *TemplateSolver) SolveWithTemplates(img image.Image, numChars int) (string, float64) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if numChars <= 0 || width == 0 || height == 0 {
		return "", 0
	}

	charSliceWidth := width / numChars

	var result strings.Builder
	totalConf := 0.0

	for i := 0; i < numChars; i++ {
		// Extract the region for this character slot
		x0 := bounds.Min.X + i*charSliceWidth
		x1 := x0 + charSliceWidth
		y0 := bounds.Min.Y
		y1 := bounds.Min.Y + height

		charPixels := ts.extractGrayscaleRegion(img, x0, y0, x1, y1)

		bestChar, bestConf := ts.matchBestTemplate(charPixels, x1-x0, y1-y0)
		result.WriteRune(bestChar)
		totalConf += bestConf
	}

	avgConf := totalConf / float64(numChars)
	return result.String(), avgConf
}

// extractGrayscaleRegion extracts a region from the image as a normalized grayscale array.
func (ts *TemplateSolver) extractGrayscaleRegion(img image.Image, x0, y0, x1, y1 int) []float64 {
	w := x1 - x0
	h := y1 - y0
	pixels := make([]float64, w*h)

	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			// Convert to grayscale luminance [0, 1]
			gray := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)) / 65535.0
			pixels[(y-y0)*w+(x-x0)] = gray
		}
	}
	return pixels
}

// matchBestTemplate finds the best matching character template for the given pixels.
// It searches across multiple pixel sizes and positions to find the best match,
// since the font renderer's pixelSize (fontSize/7) determines the actual scale.
func (ts *TemplateSolver) matchBestTemplate(regionPixels []float64, regionW, regionH int) (rune, float64) {
	bestChar := rune('A')
	bestCorr := -1.0

	binarized := ts.binarize(regionPixels)

	// Try pixel sizes 3-8 (common range for fontSize 21-56, pixelSize = fontSize/7)
	for pixSz := 3; pixSz <= 8; pixSz++ {
		scaleX := float64(pixSz)
		scaleY := float64(pixSz)
		charW := ts.charWidth * pixSz
		charH := ts.charHeight * pixSz

		if charW > regionW || charH > regionH {
			continue
		}

		// Search offsets across the full region with step = pixSz/2
		step := pixSz / 2
		if step < 1 {
			step = 1
		}

		for offX := 0; offX <= regionW-charW; offX += step {
			for offY := 0; offY <= regionH-charH; offY += step {
				for ch, tmpl := range ts.templates {
					corr := ts.correlate(binarized, regionW, tmpl,
						float64(offX), float64(offY), scaleX, scaleY)
					if corr > bestCorr {
						bestCorr = corr
						bestChar = ch
					}
				}
			}
		}
	}

	if bestCorr < 0 {
		bestCorr = 0
	}
	if bestCorr > 1 {
		bestCorr = 1
	}

	return bestChar, bestCorr
}

// binarize converts grayscale pixels to binary: 1.0 for "ink" (dark), 0.0 for background.
func (ts *TemplateSolver) binarize(pixels []float64) []float64 {
	result := make([]float64, len(pixels))

	// Compute mean to find threshold
	sum := 0.0
	for _, p := range pixels {
		sum += p
	}
	mean := sum / float64(len(pixels))

	// Threshold: pixels darker than mean are ink (inverted: lower value = darker)
	threshold := mean * 0.85
	if threshold < 0.3 {
		threshold = 0.3
	}

	for i, p := range pixels {
		if p < threshold {
			result[i] = 1.0 // ink
		}
	}
	return result
}

// correlate computes normalized cross-correlation between a region and a scaled template.
func (ts *TemplateSolver) correlate(region []float64, regionW int, tmpl []float64, offX, offY, scaleX, scaleY float64) float64 {
	var sumAB, sumAA, sumBB float64
	count := 0

	for ty := 0; ty < ts.charHeight; ty++ {
		for tx := 0; tx < ts.charWidth; tx++ {
			// Map template coord to region coord
			rx := int(float64(tx)*scaleX + offX)
			ry := int(float64(ty)*scaleY + offY)

			if rx < 0 || ry < 0 || rx >= regionW || ry*regionW+rx >= len(region) {
				continue
			}

			a := tmpl[ty*ts.charWidth+tx]
			b := region[ry*regionW+rx]

			sumAB += a * b
			sumAA += a * a
			sumBB += b * b
			count++
		}
	}

	if count == 0 || sumAA == 0 || sumBB == 0 {
		return 0
	}

	return sumAB / (math.Sqrt(sumAA) * math.Sqrt(sumBB))
}
