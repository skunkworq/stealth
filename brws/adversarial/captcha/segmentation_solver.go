package captcha

import (
	"image"
	"math"
	"sort"
	"strings"
)

// SegmentationSolver solves deformed captchas using vertical ink projection
// to find character boundaries, then template matching with rotation search.
// Falls back to connected-component analysis, then fixed-width slicing when
// segmentation finds fewer characters than expected.
type SegmentationSolver struct {
	templates     map[rune][]float64
	charW         int
	charH         int
	charset       string
	lastBinarized []float64 // cached for connected-component fallback
}

// NewSegmentationSolver creates a SegmentationSolver with the same font5x7 templates
// as TemplateSolver, but uses smarter segmentation for deformed captchas.
func NewSegmentationSolver() *SegmentationSolver {
	ss := &SegmentationSolver{
		templates: make(map[rune][]float64),
		charW:     5,
		charH:     7,
		charset:   DefaultConfig.CharSet,
	}
	ss.initTemplates()
	return ss
}

func (ss *SegmentationSolver) initTemplates() {
	for _, ch := range ss.charset {
		bitmap, ok := font5x7[ch]
		if !ok {
			continue
		}
		template := make([]float64, ss.charW*ss.charH)
		for row := 0; row < 7; row++ {
			for col := 0; col < 5; col++ {
				if (bitmap[row]>>(7-col))&1 == 1 {
					template[row*ss.charW+col] = 1.0
				}
			}
		}
		ss.templates[ch] = template
	}
}

// SolveWithSegmentation attempts to solve a captcha image by:
// 1. Binarizing the image
// 2. Computing vertical ink projection to find character boundaries
// 3. For each segment, trying multiple rotation angles and template matching
// Falls back to fixed-width slicing if segmentation finds too few characters.
func (ss *SegmentationSolver) SolveWithSegmentation(img image.Image, numChars int) (string, float64) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if numChars <= 0 || width == 0 || height == 0 {
		return "", 0
	}

	// Binarize the entire image
	binarized := ss.binarizeImage(img)
	ss.lastBinarized = binarized // cache for connected-component fallback

	// Compute vertical ink projection
	projection := ss.verticalProjection(binarized, width, height)

	// Find character boundaries via valleys in smoothed projection
	boundaries := ss.findBoundaries(projection, width, numChars)

	// If segmentation didn't find enough segments, fall back to fixed-width
	if len(boundaries) < numChars+1 {
		return ss.solveFixedWidth(binarized, width, height, numChars)
	}

	var result strings.Builder
	totalConf := 0.0

	for i := 0; i < numChars && i+1 < len(boundaries); i++ {
		x0 := boundaries[i]
		x1 := boundaries[i+1]
		if x1 <= x0 {
			x1 = x0 + width/numChars
		}
		if x1 > width {
			x1 = width
		}

		segW := x1 - x0
		segment := ss.extractSegment(binarized, width, x0, 0, segW, height)

		bestChar, bestConf := ss.matchWithRotation(segment, segW, height)
		result.WriteRune(bestChar)
		totalConf += bestConf
	}

	return result.String(), totalConf / float64(numChars)
}

// binarizeImage converts an image to a binary (ink/background) float array.
func (ss *SegmentationSolver) binarizeImage(img image.Image) []float64 {
	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	pixels := make([]float64, w*h)

	// First pass: compute grayscale
	sum := 0.0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b, _ := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
			gray := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)) / 65535.0
			pixels[y*w+x] = gray
			sum += gray
		}
	}

	// Adaptive threshold
	mean := sum / float64(w*h)
	threshold := mean * 0.85
	if threshold < 0.3 {
		threshold = 0.3
	}

	// Binarize: dark pixels = 1.0 (ink), light = 0.0
	for i, p := range pixels {
		if p < threshold {
			pixels[i] = 1.0
		} else {
			pixels[i] = 0.0
		}
	}

	return pixels
}

// verticalProjection computes the count of ink pixels in each column.
func (ss *SegmentationSolver) verticalProjection(binarized []float64, w, h int) []float64 {
	proj := make([]float64, w)
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			proj[x] += binarized[y*w+x]
		}
	}
	return proj
}

// findBoundaries finds character boundaries via valleys in the smoothed projection.
// Uses three strategies in priority order:
// 1. Valley-based: local minima in vertical ink projection (best for well-separated chars)
// 2. Connected-component: BFS flood-fill to find ink blobs (handles overlapping chars)
// 3. Fixed-width: equal slicing (last resort)
func (ss *SegmentationSolver) findBoundaries(projection []float64, width, numChars int) []int {
	// Strategy 1: Valley-based segmentation
	smoothed := ss.smoothProjection(projection, 3)

	valleys := make([]int, 0)
	margin := width / 20
	if margin < 2 {
		margin = 2
	}

	for x := margin; x < width-margin; x++ {
		if smoothed[x] <= smoothed[x-1] && smoothed[x] <= smoothed[x+1] {
			valleys = append(valleys, x)
		}
	}

	boundaries := make([]int, 0, numChars+1)
	boundaries = append(boundaries, 0)

	if len(valleys) >= numChars-1 {
		selected := ss.selectEvenlySpaced(valleys, numChars-1, width)
		boundaries = append(boundaries, selected...)
		boundaries = append(boundaries, width)
		return boundaries
	}

	// Strategy 2: Connected-component analysis
	if ccBounds := ss.connectedComponentBoundaries(width, numChars); len(ccBounds) == numChars+1 {
		return ccBounds
	}

	// Strategy 3: Fixed-width fallback
	boundaries = boundaries[:1] // keep [0]
	boundaries = append(boundaries, valleys...)
	boundaries = append(boundaries, width)

	return boundaries
}

// componentBox is the bounding box of a connected component.
type componentBox struct {
	minX, maxX int
}

// connectedComponentBoundaries uses BFS flood-fill on the stored binarized image
// to find connected components and derive character boundaries.
func (ss *SegmentationSolver) connectedComponentBoundaries(width, numChars int) []int {
	if ss.lastBinarized == nil || width <= 0 {
		return nil
	}

	binarized := ss.lastBinarized
	height := len(binarized) / width
	if height <= 0 {
		return nil
	}

	visited := make([]bool, len(binarized))
	var components []componentBox

	// BFS flood-fill to find connected components
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			idx := y*width + x
			if visited[idx] || binarized[idx] < 0.5 {
				continue
			}
			// New component found — BFS
			box := componentBox{minX: x, maxX: x}
			queue := []int{idx}
			visited[idx] = true

			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				cx := cur % width
				if cx < box.minX {
					box.minX = cx
				}
				if cx > box.maxX {
					box.maxX = cx
				}

				// 4-connected neighbors
				for _, d := range [][2]int{{-1, 0}, {1, 0}, {0, -1}, {0, 1}} {
					nx := cx + d[0]
					ny := cur/width + d[1]
					if nx < 0 || nx >= width || ny < 0 || ny >= height {
						continue
					}
					nIdx := ny*width + nx
					if !visited[nIdx] && binarized[nIdx] >= 0.5 {
						visited[nIdx] = true
						queue = append(queue, nIdx)
					}
				}
			}

			// Filter out tiny noise components (< 3px wide)
			if box.maxX-box.minX >= 2 {
				components = append(components, box)
			}
		}
	}

	if len(components) == 0 {
		return nil
	}

	// Sort components left-to-right
	sort.Slice(components, func(i, j int) bool {
		return components[i].minX < components[j].minX
	})

	// Merge nearest neighbors if too many components
	for len(components) > numChars {
		minGap := width + 1
		mergeIdx := 0
		for i := 0; i < len(components)-1; i++ {
			gap := components[i+1].minX - components[i].maxX
			if gap < minGap {
				minGap = gap
				mergeIdx = i
			}
		}
		// Merge mergeIdx and mergeIdx+1
		components[mergeIdx].maxX = components[mergeIdx+1].maxX
		components = append(components[:mergeIdx+1], components[mergeIdx+2:]...)
	}

	// Split widest components if too few
	for len(components) < numChars {
		widestIdx := 0
		widestW := 0
		for i, c := range components {
			w := c.maxX - c.minX
			if w > widestW {
				widestW = w
				widestIdx = i
			}
		}
		mid := (components[widestIdx].minX + components[widestIdx].maxX) / 2
		right := componentBox{minX: mid, maxX: components[widestIdx].maxX}
		components[widestIdx].maxX = mid
		// Insert right after widestIdx
		components = append(components, componentBox{})
		copy(components[widestIdx+2:], components[widestIdx+1:])
		components[widestIdx+1] = right
	}

	// Convert components to boundaries
	boundaries := make([]int, 0, numChars+1)
	boundaries = append(boundaries, 0)
	for i := 0; i < len(components)-1; i++ {
		boundary := (components[i].maxX + components[i+1].minX) / 2
		boundaries = append(boundaries, boundary)
	}
	boundaries = append(boundaries, width)

	if len(boundaries) != numChars+1 {
		return nil
	}

	return boundaries
}

// smoothProjection applies a moving average to the projection.
func (ss *SegmentationSolver) smoothProjection(proj []float64, windowSize int) []float64 {
	n := len(proj)
	smoothed := make([]float64, n)
	half := windowSize / 2

	for i := 0; i < n; i++ {
		sum := 0.0
		count := 0
		for j := i - half; j <= i+half; j++ {
			if j >= 0 && j < n {
				sum += proj[j]
				count++
			}
		}
		if count > 0 {
			smoothed[i] = sum / float64(count)
		}
	}

	return smoothed
}

// selectEvenlySpaced selects n valleys that are most evenly spaced across the width.
func (ss *SegmentationSolver) selectEvenlySpaced(valleys []int, n, width int) []int {
	if n <= 0 {
		return nil
	}
	if len(valleys) <= n {
		return valleys
	}

	// Target positions for n evenly-spaced boundaries
	targets := make([]int, n)
	for i := 0; i < n; i++ {
		targets[i] = width * (i + 1) / (n + 1)
	}

	// Greedy: for each target, pick the closest unused valley
	used := make(map[int]bool)
	result := make([]int, n)

	for i, target := range targets {
		bestIdx := -1
		bestDist := width + 1
		for j, v := range valleys {
			if used[j] {
				continue
			}
			d := target - v
			if d < 0 {
				d = -d
			}
			if d < bestDist {
				bestDist = d
				bestIdx = j
			}
		}
		if bestIdx >= 0 {
			result[i] = valleys[bestIdx]
			used[bestIdx] = true
		} else {
			result[i] = target
		}
	}

	// Sort the result
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// extractSegment extracts a rectangular region from the binarized image.
func (ss *SegmentationSolver) extractSegment(binarized []float64, fullW, x0, y0, segW, segH int) []float64 {
	segment := make([]float64, segW*segH)
	for y := 0; y < segH; y++ {
		for x := 0; x < segW; x++ {
			sx := x0 + x
			sy := y0 + y
			if sx >= 0 && sx < fullW && sy >= 0 {
				idx := sy*fullW + sx
				if idx < len(binarized) {
					segment[y*segW+x] = binarized[idx]
				}
			}
		}
	}
	return segment
}

// matchWithRotation tries multiple rotation angles (-15° to +15° in 5° steps)
// and returns the best matching character and confidence.
func (ss *SegmentationSolver) matchWithRotation(segment []float64, segW, segH int) (rune, float64) {
	bestChar := rune('A')
	bestCorr := -1.0

	for angleDeg := -15; angleDeg <= 15; angleDeg += 5 {
		angleRad := float64(angleDeg) * math.Pi / 180.0
		rotated := ss.rotateSegment(segment, segW, segH, angleRad)

		ch, corr := ss.matchBestTemplate(rotated, segW, segH)
		if corr > bestCorr {
			bestCorr = corr
			bestChar = ch
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

// rotateSegment rotates a binarized segment by the given angle around its center.
func (ss *SegmentationSolver) rotateSegment(segment []float64, w, h int, angle float64) []float64 {
	if angle == 0 {
		return segment
	}

	result := make([]float64, w*h)
	cx := float64(w) / 2
	cy := float64(h) / 2
	cosA := math.Cos(-angle)
	sinA := math.Sin(-angle)

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// Reverse-map from destination to source
			rx := float64(x) - cx
			ry := float64(y) - cy
			srcX := int(math.Round(rx*cosA-ry*sinA+cx))
			srcY := int(math.Round(rx*sinA+ry*cosA+cy))

			if srcX >= 0 && srcX < w && srcY >= 0 && srcY < h {
				result[y*w+x] = segment[srcY*w+srcX]
			}
		}
	}

	return result
}

// matchBestTemplate finds the best matching template for a binarized region.
func (ss *SegmentationSolver) matchBestTemplate(region []float64, regionW, regionH int) (rune, float64) {
	bestChar := rune('A')
	bestCorr := -1.0

	// Try multiple pixel sizes (3-8) to match the generator's scale
	for pixSz := 3; pixSz <= 8; pixSz++ {
		scaleX := float64(pixSz)
		scaleY := float64(pixSz)
		charW := ss.charW * pixSz
		charH := ss.charH * pixSz

		if charW > regionW || charH > regionH {
			continue
		}

		step := pixSz / 2
		if step < 1 {
			step = 1
		}

		for offX := 0; offX <= regionW-charW; offX += step {
			for offY := 0; offY <= regionH-charH; offY += step {
				for ch, tmpl := range ss.templates {
					corr := ss.correlate(region, regionW, tmpl,
						float64(offX), float64(offY), scaleX, scaleY)
					if corr > bestCorr {
						bestCorr = corr
						bestChar = ch
					}
				}
			}
		}
	}

	return bestChar, bestCorr
}

// correlate computes normalized cross-correlation.
func (ss *SegmentationSolver) correlate(region []float64, regionW int, tmpl []float64, offX, offY, scaleX, scaleY float64) float64 {
	var sumAB, sumAA, sumBB float64
	count := 0

	for ty := 0; ty < ss.charH; ty++ {
		for tx := 0; tx < ss.charW; tx++ {
			rx := int(float64(tx)*scaleX + offX)
			ry := int(float64(ty)*scaleY + offY)

			if rx < 0 || ry < 0 || rx >= regionW || ry*regionW+rx >= len(region) {
				continue
			}

			a := tmpl[ty*ss.charW+tx]
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

// solveFixedWidth falls back to TemplateSolver-style fixed-width slicing.
func (ss *SegmentationSolver) solveFixedWidth(binarized []float64, width, height, numChars int) (string, float64) {
	sliceW := width / numChars

	var result strings.Builder
	totalConf := 0.0

	for i := 0; i < numChars; i++ {
		x0 := i * sliceW
		segment := ss.extractSegment(binarized, width, x0, 0, sliceW, height)
		ch, conf := ss.matchWithRotation(segment, sliceW, height)
		result.WriteRune(ch)
		totalConf += conf
	}

	return result.String(), totalConf / float64(numChars)
}
