package captcha

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Generator creates various types of CAPTCHA challenges.
type Generator struct {
	config *CaptchaConfig
	rng    *RNG
}

// RNG provides random number generation for CAPTCHA creation.
type RNG struct{}

// NewRNG creates a new random number generator.
func NewRNG() *RNG {
	return &RNG{}
}

// Intn returns a random int in the range [0, n).
func (r *RNG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

// Float64 returns a random float64 in the range [0.0, 1.0).
func (r *RNG) Float64() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(int64FromBytes(b[:])) / (1 << 64)
}

func int64FromBytes(b []byte) int64 {
	var n int64
	for i := 0; i < 8; i++ {
		n = n<<8 + int64(b[i])
	}
	return n
}

// IntBetween returns a random int in the range [minVal, maxVal).
// IntBetween returns a random int in the range [minVal, maxVal).
func (r *RNG) IntBetween(minVal, maxVal int) int {
	if minVal >= maxVal {
		return minVal
	}
	return minVal + r.Intn(maxVal-minVal)
}

// FloatBetween returns a random float64 in the range [minVal, maxVal).
func (r *RNG) FloatBetween(minVal, maxVal float64) float64 {
	return minVal + r.Float64()*(maxVal-minVal)
}

// NewGenerator creates a new CAPTCHA generator with the given config.
func NewGenerator(config *CaptchaConfig) *Generator {
	if config == nil {
		config = &DefaultConfig
	}
	return &Generator{
		config: config,
		rng:    NewRNG(),
	}
}

// Generate creates a new CAPTCHA of the specified type.
func (g *Generator) Generate(captchaType CaptchaType) (*Captcha, error) {
	startTime := time.Now()

	var captcha *Captcha
	var err error

	switch captchaType {
	case CaptchaTypeText:
		captcha, err = g.generateText()
	case CaptchaTypeMath:
		captcha, err = g.generateMath()
	case CaptchaTypeImage:
		captcha, err = g.generateImage()
	case CaptchaTypeSlider:
		captcha, err = g.generateSlider()
	default:
		captcha, err = g.generateText()
	}

	if err != nil {
		return nil, err
	}

	captcha.Metadata.GenerationMs = time.Since(startTime).Milliseconds()
	captcha.CreatedAt = time.Now()

	return captcha, nil
}

// GenerateBatch creates multiple CAPTCHAs of the specified type.
func (g *Generator) GenerateBatch(count int, captchaType CaptchaType) ([]*Captcha, error) {
	captchas := make([]*Captcha, count)
	for i := 0; i < count; i++ {
		c, err := g.Generate(captchaType)
		if err != nil {
			return nil, err
		}
		captchas[i] = c
	}
	return captchas, nil
}

// Validate checks if the answer matches the CAPTCHA solution.
func (g *Generator) Validate(captcha *Captcha, answer string) bool {
	switch sol := captcha.Solution.(type) {
	case TextSolution:
		return strings.EqualFold(sol.Text, answer)
	case MathSolution:
		return fmt.Sprintf("%d", sol.Answer) == answer
	case SliderSolution:
		return g.validateSlider(sol, answer)
	case ImageSolution:
		return g.validateImage(sol, answer)
	}
	return false
}

func (g *Generator) generateText() (*Captcha, error) {
	cfg := g.config

	img := image.NewRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))

	draw.Draw(img, img.Bounds(), &image.Uniform{cfg.BackgroundColor}, image.Point{}, draw.Src)

	// Draw background grid first (anti-segmentation)
	if cfg.BackgroundGrid {
		g.addBackgroundGrid(img)
	}

	text := g.generateRandomText(cfg.Length, cfg.CharSet)

	// Calculate character placement with overlap support
	baseCharWidth := cfg.Width / cfg.Length
	spacing := baseCharWidth
	if cfg.OverlapPx > 0 {
		spacing = baseCharWidth - cfg.OverlapPx
		if spacing < baseCharWidth/2 {
			spacing = baseCharWidth / 2 // don't collapse below half-width
		}
	}
	totalWidth := spacing*(cfg.Length-1) + baseCharWidth
	startX := (cfg.Width - totalWidth) / 2

	for i := 0; i < len(text); i++ {
		x := startX + i*spacing + g.rng.Intn(3) - 1 // ±1px jitter

		// Per-character font size variation (±20%)
		fontSize := cfg.FontSize
		if cfg.PerCharSize {
			variation := float64(cfg.FontSize) * 0.2
			fontSize = cfg.FontSize + int(g.rng.FloatBetween(-variation, variation))
			if fontSize < 12 {
				fontSize = 12
			}
		}

		// Per-character y-offset for baseline wobble (±5px)
		yOffset := 10 + g.rng.Intn(11) - 5

		if cfg.PerCharColor {
			g.drawCharAtWithColor(img, string(text[i]), x, yOffset, fontSize, g.randomDarkColor())
		} else {
			g.drawCharAt(img, string(text[i]), x, yOffset, fontSize)
		}
	}

	if cfg.NoiseLines > 0 {
		if cfg.ThickNoiseLines {
			g.addThickNoiseLines(img, cfg.NoiseLines)
		} else {
			g.addNoiseLines(img, cfg.NoiseLines)
		}
	}

	if cfg.NoiseDots > 0 {
		g.addNoiseDots(img, cfg.NoiseDots)
	}

	// Apply whole-image wave deformation if enabled
	if cfg.Wave {
		if cfg.WaveFrequencies > 1 {
			g.applyMultiWaveDeformation(img)
		} else {
			g.applyWaveDeformation(img)
		}
	}

	id := g.generateID(text)

	solution := TextSolution{
		Text:   text,
		Chars:  []rune(text),
		Tokens: g.tokenize(text),
	}

	return &Captcha{
		ID:       id,
		Type:     CaptchaTypeText,
		Image:    img,
		Solution: solution,
		Metadata: CaptchaMetadata{
			Difficulty:  cfg.Difficulty,
			CharCount:   len(text),
			CharSetUsed: cfg.CharSet,
			HasNoise:    cfg.NoiseLines > 0 || cfg.NoiseDots > 0,
			HasRotation: cfg.Rotate,
			HasWarp:     cfg.Wave,
			EntropyBits: float64(len(text)) * math.Log2(float64(len(cfg.CharSet))),
		},
	}, nil
}

func (g *Generator) generateMath() (*Captcha, error) {
	cfg := g.config

	operand1 := g.rng.IntBetween(1, 20)
	operand2 := g.rng.IntBetween(1, 20)
	operator := []string{"+", "-", "*"}[g.rng.Intn(3)]

	var answer int
	var expression string

	switch operator {
	case "+":
		answer = operand1 + operand2
		expression = fmt.Sprintf("%d + %d = ?", operand1, operand2)
	case "-":
		if operand1 < operand2 {
			operand1, operand2 = operand2, operand1
		}
		answer = operand1 - operand2
		expression = fmt.Sprintf("%d - %d = ?", operand1, operand2)
	case "*":
		operand1 = g.rng.IntBetween(1, 10)
		operand2 = g.rng.IntBetween(1, 10)
		answer = operand1 * operand2
		expression = fmt.Sprintf("%d × %d = ?", operand1, operand2)
	}

	img := image.NewRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))
	draw.Draw(img, img.Bounds(), &image.Uniform{cfg.BackgroundColor}, image.Point{}, draw.Src)

	g.drawCharAt(img, expression, cfg.Width/2-len(expression)*10/2, cfg.Height/2, cfg.FontSize)

	if cfg.NoiseLines > 0 {
		g.addNoiseLines(img, cfg.NoiseLines)
	}

	id := g.generateID(fmt.Sprintf("%d", answer))

	return &Captcha{
		ID:    id,
		Type:  CaptchaTypeMath,
		Image: img,
		Solution: MathSolution{
			Expression: expression,
			Answer:     answer,
			Operands:   []int{operand1, operand2},
			Operator:   operator,
		},
		Metadata: CaptchaMetadata{
			Difficulty:  cfg.Difficulty,
			CharCount:   len(expression),
			CharSetUsed: "0123456789+-×",
			HasNoise:    cfg.NoiseLines > 0,
		},
	}, nil
}

func (g *Generator) generateImage() (*Captcha, error) {
	cfg := g.config

	img := image.NewRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))
	draw.Draw(img, img.Bounds(), &image.Uniform{cfg.BackgroundColor}, image.Point{}, draw.Src)

	numOptions := 9
	gridSize := 3
	cellWidth := cfg.Width / gridSize
	cellHeight := cfg.Height / gridSize

	targetIdx := g.rng.Intn(numOptions)

	indices := make([]int, numOptions)
	for i := range indices {
		indices[i] = i
	}
	g.shuffle(indices)

	selectedIndices := []int{targetIdx}

	fontSize := 20

	for i, idx := range indices {
		x := (i % gridSize) * cellWidth
		y := (i / gridSize) * cellHeight

		g.drawCharAt(img, string(rune('A'+idx)), x+cellWidth/2-fontSize/3, y+cellHeight/2, fontSize)
	}

	id := g.generateID(fmt.Sprintf("%d", targetIdx))

	return &Captcha{
		ID:    id,
		Type:  CaptchaTypeImage,
		Image: img,
		Solution: ImageSolution{
			SelectedIndices: selectedIndices,
			TargetImage:     string(rune('A' + targetIdx)),
			Distractors:     []string{},
		},
		Metadata: CaptchaMetadata{
			Difficulty:  cfg.Difficulty,
			CharCount:   numOptions,
			CharSetUsed: "ABCDEFGHI",
			HasNoise:    false,
			HasRotation: false,
			HasWarp:     false,
		},
	}, nil
}

func (g *Generator) generateSlider() (*Captcha, error) {
	cfg := g.config

	img := image.NewRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))
	draw.Draw(img, img.Bounds(), &image.Uniform{cfg.BackgroundColor}, image.Point{}, draw.Src)

	trackHeight := 50
	trackY := (cfg.Height - trackHeight) / 2
	trackX := 20
	trackW := cfg.Width - 40

	draw.Draw(img, image.Rect(trackX, trackY, trackX+trackW, trackY+trackHeight),
		&image.Uniform{color.RGBA{200, 200, 200, 255}}, image.Point{}, draw.Src)

	puzzleWidth := 40
	puzzleX := trackX + g.rng.IntBetween(20, trackW-puzzleWidth-20)

	draw.Draw(img, image.Rect(puzzleX, trackY-5, puzzleX+puzzleWidth, trackY+trackHeight+5),
		&image.Uniform{color.RGBA{50, 100, 200, 255}}, image.Point{}, draw.Src)

	g.drawCharAt(img, "→", puzzleX+puzzleWidth/2, trackY+trackHeight/2, 20)

	distance := puzzleX - trackX

	id := g.generateID(fmt.Sprintf("%d", distance))

	return &Captcha{
		ID:    id,
		Type:  CaptchaTypeSlider,
		Image: img,
		Solution: SliderSolution{
			StartX:     trackX,
			EndX:       puzzleX,
			Distance:   distance,
			TrackWidth: trackW,
		},
		Metadata: CaptchaMetadata{
			Difficulty:  cfg.Difficulty,
			CharCount:   distance,
			HasNoise:    false,
			HasRotation: false,
			HasWarp:     false,
		},
	}, nil
}

func (g *Generator) validateSlider(sol SliderSolution, answer string) bool {
	var providedDist int
	_, _ = fmt.Sscanf(answer, "%d", &providedDist)
	return abs(providedDist-sol.Distance) < 10
}

func (g *Generator) validateImage(sol ImageSolution, answer string) bool {
	return sol.TargetImage == answer
}

func (g *Generator) generateRandomText(length int, charSet string) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charSet[g.rng.Intn(len(charSet))]
	}
	return string(result)
}

func (g *Generator) generateID(secret string) string {
	data := fmt.Sprintf("%s-%d", secret, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])[:12]
}

var font5x7 = map[rune][7]byte{
	'A': {0x70, 0x88, 0x88, 0xF8, 0x88, 0x88, 0x88},
	'B': {0xF0, 0x88, 0x88, 0xF0, 0x88, 0x88, 0xF0},
	'C': {0x70, 0x88, 0x80, 0x80, 0x80, 0x88, 0x70},
	'D': {0xE0, 0x90, 0x88, 0x88, 0x88, 0x90, 0xE0},
	'E': {0xF8, 0x80, 0x80, 0xF0, 0x80, 0x80, 0xF8},
	'F': {0xF8, 0x80, 0x80, 0xF0, 0x80, 0x80, 0x80},
	'G': {0x70, 0x88, 0x80, 0x98, 0x88, 0x88, 0x70},
	'H': {0x88, 0x88, 0x88, 0xF8, 0x88, 0x88, 0x88},
	'I': {0x70, 0x20, 0x20, 0x20, 0x20, 0x20, 0x70},
	'J': {0x38, 0x10, 0x10, 0x10, 0x10, 0x90, 0x60},
	'K': {0x88, 0x90, 0xA0, 0xC0, 0xA0, 0x90, 0x88},
	'L': {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xF8},
	'M': {0x88, 0xD8, 0xA8, 0xA8, 0x88, 0x88, 0x88},
	'N': {0x88, 0xC8, 0xA8, 0x98, 0x88, 0x88, 0x88},
	'O': {0x70, 0x88, 0x88, 0x88, 0x88, 0x88, 0x70},
	'P': {0xF0, 0x88, 0x88, 0xF0, 0x80, 0x80, 0x80},
	'Q': {0x70, 0x88, 0x88, 0x88, 0xA8, 0x90, 0x68},
	'R': {0xF0, 0x88, 0x88, 0xF0, 0xA0, 0x90, 0x88},
	'S': {0x70, 0x88, 0x80, 0x70, 0x08, 0x88, 0x70},
	'T': {0xF8, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
	'U': {0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x70},
	'V': {0x88, 0x88, 0x88, 0x88, 0x88, 0x50, 0x20},
	'W': {0x88, 0x88, 0x88, 0xA8, 0xA8, 0xD8, 0x88},
	'X': {0x88, 0x88, 0x50, 0x20, 0x50, 0x88, 0x88},
	'Y': {0x88, 0x88, 0x50, 0x20, 0x20, 0x20, 0x20},
	'Z': {0xF8, 0x08, 0x10, 0x20, 0x40, 0x80, 0xF8},
	'0': {0x70, 0x88, 0x98, 0xA8, 0xC8, 0x88, 0x70},
	'1': {0x20, 0x60, 0x20, 0x20, 0x20, 0x20, 0x70},
	'2': {0x70, 0x88, 0x08, 0x30, 0x40, 0x80, 0xF8},
	'3': {0xF8, 0x08, 0x10, 0x30, 0x08, 0x88, 0x70},
	'4': {0x10, 0x30, 0x50, 0x90, 0xF8, 0x10, 0x10},
	'5': {0xF8, 0x80, 0xF0, 0x08, 0x08, 0x88, 0x70},
	'6': {0x30, 0x40, 0x80, 0xF0, 0x88, 0x88, 0x70},
	'7': {0xF8, 0x08, 0x10, 0x20, 0x40, 0x40, 0x40},
	'8': {0x70, 0x88, 0x88, 0x70, 0x88, 0x88, 0x70},
	'9': {0x70, 0x88, 0x88, 0x78, 0x08, 0x10, 0x60},
	'+': {0x00, 0x20, 0x20, 0xF8, 0x20, 0x20, 0x00},
	'-': {0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00},
	'×': {0x00, 0x88, 0x50, 0x20, 0x50, 0x88, 0x00},
	'=': {0x00, 0x00, 0xF8, 0x00, 0xF8, 0x00, 0x00},
	'?': {0x70, 0x88, 0x08, 0x10, 0x20, 0x00, 0x20},
}

func (g *Generator) drawCharAt(img *image.RGBA, text string, x, y, size int) {
	// Generate color components in range 0-149 (safe for uint8 conversion)
	rVal := g.rng.Intn(150)
	gVal := g.rng.Intn(150)
	bVal := g.rng.Intn(150)
	textColor := color.RGBA{
		R: byte(rVal),
		G: byte(gVal),
		B: byte(bVal),
		A: 255,
	}

	charWidth := size / 2
	charHeight := size
	pixelSize := size / 7

	for i, r := range strings.ToUpper(text) {
		bitmap, ok := font5x7[r]
		if !ok {
			// Fallback rectangle if char not in font
			for py := 0; py < charHeight; py++ {
				for px := 0; px < charWidth; px++ {
					img.Set(x+i*charWidth+px, y+py, textColor)
				}
			}
			continue
		}

		// Calculate rotation if enabled
		angle := 0.0
		if g.config.Rotate {
			angle = g.rng.FloatBetween(-0.15, 0.15) // Random rotation +/- 8.6 degrees
		}
		cosA := math.Cos(angle)
		sinA := math.Sin(angle)

		// Apply optional wave/rotation to the character drawing
		for row := 0; row < 7; row++ {
			for col := 0; col < 5; col++ {
				if (bitmap[row]>>(7-col))&1 == 1 {
					// Center point of the character for rotation
					cx := float64(charWidth) / 2.0
					cy := float64(charHeight) / 2.0

					// Relative coordinates within char
					rx := float64(col*pixelSize+pixelSize/2) - cx
					ry := float64(row*pixelSize+pixelSize/2) - cy

					// Apply rotation
					rotX := rx*cosA - ry*sinA
					rotY := rx*sinA + ry*cosA

					// Back to character coordinates
					charX := int(rotX + cx)
					charY := int(rotY + cy)

					// Draw a block of pixels for this bit
					for py := 0; py < pixelSize; py++ {
						for px := 0; px < pixelSize; px++ {
							fx := x + i*charWidth + charX + px
							fy := y + charY + py

							// Apply some random jitter
							if g.rng.Intn(100) < 15 {
								fx += g.rng.Intn(3) - 1
								fy += g.rng.Intn(3) - 1
							}

							if fx >= 0 && fx < img.Bounds().Dx() && fy >= 0 && fy < img.Bounds().Dy() {
								img.Set(fx, fy, textColor)
							}
						}
					}
				}
			}
		}
	}
}

// drawCharAtWithColor draws a character with a specific color.
func (g *Generator) drawCharAtWithColor(img *image.RGBA, text string, x, y, size int, textColor color.RGBA) {
	charWidth := size / 2
	charHeight := size
	pixelSize := size / 7

	for i, r := range strings.ToUpper(text) {
		bitmap, ok := font5x7[r]
		if !ok {
			for py := 0; py < charHeight; py++ {
				for px := 0; px < charWidth; px++ {
					img.Set(x+i*charWidth+px, y+py, textColor)
				}
			}
			continue
		}

		angle := 0.0
		if g.config.Rotate {
			angle = g.rng.FloatBetween(-0.15, 0.15)
		}
		cosA := math.Cos(angle)
		sinA := math.Sin(angle)

		for row := 0; row < 7; row++ {
			for col := 0; col < 5; col++ {
				if (bitmap[row]>>(7-col))&1 == 1 {
					cx := float64(charWidth) / 2.0
					cy := float64(charHeight) / 2.0

					rx := float64(col*pixelSize+pixelSize/2) - cx
					ry := float64(row*pixelSize+pixelSize/2) - cy

					rotX := rx*cosA - ry*sinA
					rotY := rx*sinA + ry*cosA

					charX := int(rotX + cx)
					charY := int(rotY + cy)

					for py := 0; py < pixelSize; py++ {
						for px := 0; px < pixelSize; px++ {
							fx := x + i*charWidth + charX + px
							fy := y + charY + py
							if g.rng.Intn(100) < 15 {
								fx += g.rng.Intn(3) - 1
								fy += g.rng.Intn(3) - 1
							}
							if fx >= 0 && fx < img.Bounds().Dx() && fy >= 0 && fy < img.Bounds().Dy() {
								img.Set(fx, fy, textColor)
							}
						}
					}
				}
			}
		}
	}
}

// randomDarkColor returns a random dark color suitable for captcha text.
func (g *Generator) randomDarkColor() color.RGBA {
	return color.RGBA{
		R: byte(g.rng.Intn(150)),
		G: byte(g.rng.Intn(150)),
		B: byte(g.rng.Intn(150)),
		A: 255,
	}
}

// applyMultiWaveDeformation layers multiple sine waves with different frequencies.
func (g *Generator) applyMultiWaveDeformation(img *image.RGBA) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	numLayers := g.config.WaveFrequencies
	if numLayers < 1 {
		numLayers = 1
	}

	tempImg := image.NewRGBA(bounds)
	draw.Draw(tempImg, bounds, img, bounds.Min, draw.Src)
	draw.Draw(img, bounds, &image.Uniform{g.config.BackgroundColor}, bounds.Min, draw.Src)

	// Pre-compute wave parameters per layer
	type waveLayer struct {
		ampX, ampY       float64
		periodX, periodY float64
		phaseX, phaseY   float64
	}
	layers := make([]waveLayer, numLayers)
	for l := 0; l < numLayers; l++ {
		decay := 1.0 - 0.3*float64(l)
		layers[l] = waveLayer{
			ampX:    g.config.WaveAmplitude * decay,
			ampY:    g.config.WaveAmplitude * decay * 0.8,
			periodX: float64(60 + g.rng.Intn(80)),
			periodY: float64(60 + g.rng.Intn(80)),
			phaseX:  g.rng.FloatBetween(0, 2*math.Pi),
			phaseY:  g.rng.FloatBetween(0, 2*math.Pi),
		}
	}

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offsetX := 0.0
			offsetY := 0.0
			for _, l := range layers {
				offsetX += l.ampX * math.Sin(float64(y)/l.periodX*2*math.Pi+l.phaseX)
				offsetY += l.ampY * math.Sin(float64(x)/l.periodY*2*math.Pi+l.phaseY)
			}

			srcX := int(math.Round(float64(x) + offsetX))
			srcY := int(math.Round(float64(y) + offsetY))

			if srcX >= 0 && srcX < width && srcY >= 0 && srcY < height {
				img.Set(x, y, tempImg.At(srcX, srcY))
			}
		}
	}
}

// addThickNoiseLines draws noise lines 2-4px wide by drawing at multiple offsets.
func (g *Generator) addThickNoiseLines(img *image.RGBA, count int) {
	for i := 0; i < count; i++ {
		x1 := g.rng.Intn(img.Bounds().Dx())
		y1 := g.rng.Intn(img.Bounds().Dy())
		x2 := g.rng.Intn(img.Bounds().Dx())
		y2 := g.rng.Intn(img.Bounds().Dy())

		c := color.RGBA{
			R: byte(g.rng.Intn(256)),
			G: byte(g.rng.Intn(256)),
			B: byte(g.rng.Intn(256)),
			A: 128,
		}

		thickness := 2 + g.rng.Intn(3) // 2-4px
		for off := 0; off < thickness; off++ {
			g.drawLine(img, x1, y1+off, x2, y2+off, c)
			g.drawLine(img, x1+off, y1, x2+off, y2, c)
		}
	}
}

// addBackgroundGrid draws a faint grid pattern that defeats vertical projection segmentation.
func (g *Generator) addBackgroundGrid(img *image.RGBA) {
	bounds := img.Bounds()
	gridSpacing := 8 + g.rng.Intn(5) // 8-12px
	gridColor := color.RGBA{R: 200, G: 200, B: 200, A: 40}

	// Vertical lines
	for x := gridSpacing; x < bounds.Dx(); x += gridSpacing {
		for y := 0; y < bounds.Dy(); y++ {
			img.Set(x, y, gridColor)
		}
	}
	// Horizontal lines
	for y := gridSpacing; y < bounds.Dy(); y += gridSpacing {
		for x := 0; x < bounds.Dx(); x++ {
			img.Set(x, y, gridColor)
		}
	}
}

// applyWaveDeformation applies a sine wave distortion to the entire image
func (g *Generator) applyWaveDeformation(img *image.RGBA) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Create a temporary copy to read from while writing to img
	tempImg := image.NewRGBA(bounds)
	draw.Draw(tempImg, bounds, img, bounds.Min, draw.Src)
	draw.Draw(img, bounds, &image.Uniform{g.config.BackgroundColor}, bounds.Min, draw.Src) // clear original

	amplitudeX := float64(g.rng.IntBetween(1, 3))
	amplitudeY := float64(g.rng.IntBetween(1, 3))
	periodX := float64(g.rng.IntBetween(80, 150))
	periodY := float64(g.rng.IntBetween(80, 150))

	phaseX := g.rng.FloatBetween(0, 2*math.Pi)
	phaseY := g.rng.FloatBetween(0, 2*math.Pi)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Calculate source pixel coordinates with reverse sine wave offset
			srcX := float64(x) + amplitudeX*math.Sin(float64(y)/periodX*2*math.Pi+phaseX)
			srcY := float64(y) + amplitudeY*math.Sin(float64(x)/periodY*2*math.Pi+phaseY)

			// Nearest neighbor interpolation
			ix := int(math.Round(srcX))
			iy := int(math.Round(srcY))

			if ix >= 0 && ix < width && iy >= 0 && iy < height {
				img.Set(x, y, tempImg.At(ix, iy))
			}
		}
	}
}

// EncodeToBase64 encodes an image to a base64 PNG string.
func EncodeToBase64(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func (g *Generator) addNoiseLines(img *image.RGBA, count int) {
	for i := 0; i < count; i++ {
		x1 := g.rng.Intn(img.Bounds().Dx())
		y1 := g.rng.Intn(img.Bounds().Dy())
		x2 := g.rng.Intn(img.Bounds().Dx())
		y2 := g.rng.Intn(img.Bounds().Dy())

		// Color values 0-255 are safe for byte conversion
		rVal := g.rng.Intn(256)
		gVal := g.rng.Intn(256)
		bVal := g.rng.Intn(256)
		c := color.RGBA{
			R: byte(rVal),
			G: byte(gVal),
			B: byte(bVal),
			A: 128,
		}

		g.drawLine(img, x1, y1, x2, y2, c)
	}
}

func (g *Generator) addNoiseDots(img *image.RGBA, count int) {
	for i := 0; i < count; i++ {
		x := g.rng.Intn(img.Bounds().Dx())
		y := g.rng.Intn(img.Bounds().Dy())

		// Color values 0-255 are safe for byte conversion
		rVal := g.rng.Intn(256)
		gVal := g.rng.Intn(256)
		bVal := g.rng.Intn(256)
		c := color.RGBA{
			R: byte(rVal),
			G: byte(gVal),
			B: byte(bVal),
			A: 128,
		}

		img.Set(x, y, c)
	}
}

func (g *Generator) drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	sx := -1
	if x1 < x2 {
		sx = 1
	}
	sy := -1
	if y1 < y2 {
		sy = 1
	}
	err := dx - dy

	for {
		if x1 >= 0 && x1 < img.Bounds().Dx() && y1 >= 0 && y1 < img.Bounds().Dy() {
			img.Set(x1, y1, c)
		}

		if x1 == x2 && y1 == y2 {
			break
		}

		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x1 += sx
		}
		if e2 < dx {
			err += dx
			y1 += sy
		}
	}
}

func (g *Generator) shuffle(arr []int) {
	for i := len(arr) - 1; i > 0; i-- {
		j := g.rng.Intn(i + 1)
		arr[i], arr[j] = arr[j], arr[i]
	}
}

func (g *Generator) tokenize(text string) []string {
	tokens := make([]string, len(text))
	for i, ch := range text {
		tokens[i] = string(ch)
	}
	return tokens
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// SaveToPNG saves an image to a PNG file.
func SaveToPNG(img image.Image, filePath string) error {
	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	file, err := os.Create(cleanPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return png.Encode(file, img)
}
