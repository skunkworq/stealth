package tlsfprint

import (
	"math"
	"math/rand"
	"time"
)

type BehavioralFingerprint struct {
	MouseMovements  []MouseMovement
	KeyboardTyping  []KeystrokeTiming
	ScrollBehavior  []ScrollEvent
	TouchEvents     []TouchEvent
	JSMutations     []JSMutation
	NetworkPatterns []NetworkRequest
	ResourceTiming  []ResourceTiming
}

type MouseMovement struct {
	Timestamp    time.Time
	X            float64
	Y            float64
	VelocityX    float64
	VelocityY    float64
	Acceleration float64
	IsClick      bool
	Button       int
}

type KeystrokeTiming struct {
	Timestamp   time.Time
	Key         string
	PressTime   time.Duration
	ReleaseTime time.Duration
	HoldTime    time.Duration
	InterKey    time.Duration
}

type ScrollEvent struct {
	Timestamp time.Time
	X         float64
	Y         float64
	DeltaX    float64
	DeltaY    float64
	Velocity  float64
	IsTouch   bool
}

type TouchEvent struct {
	Timestamp time.Time
	X         float64
	Y         float64
	TouchType string
	TouchID   int
}

type JSMutation struct {
	Timestamp    time.Time
	MutationType string
	Element      string
	Attribute    string
	Value        string
}

type NetworkRequest struct {
	Timestamp    time.Time
	URL          string
	Method       string
	Status       int
	Duration     time.Duration
	RequestSize  int64
	ResponseSize int64
	Cached       bool
}

type ResourceTiming struct {
	Name         string
	StartTime    time.Duration
	Duration     time.Duration
	TransferSize int64
	DecodedSize  int64
}

// BehaviorProfileAnalyzer analyzes raw behavioral fingerprint data (mouse, typing,
// scroll, network) captured from a live browser session. Distinct from
// challenge.BehavioralAnalyzer, which scores EnhancedBehavioralEvents against
// shield detection vectors.
type BehaviorProfileAnalyzer struct {
	fingerprints []BehavioralFingerprint
}

func NewBehaviorProfileAnalyzer() *BehaviorProfileAnalyzer {
	return &BehaviorProfileAnalyzer{
		fingerprints: make([]BehavioralFingerprint, 0),
	}
}

func (a *BehaviorProfileAnalyzer) AnalyzeMouseMovement(movements []MouseMovement) MouseAnalysisResult {
	if len(movements) < 2 {
		return MouseAnalysisResult{IsHuman: false, Confidence: 0}
	}

	var totalVelocity float64
	var clickCount, moveCount int
	var varianceX, varianceY float64

	prevX, prevY := movements[0].X, movements[0].Y
	prevTime := movements[0].Timestamp

	for _, m := range movements {
		if m.IsClick {
			clickCount++
		} else {
			moveCount++
			dx := m.X - prevX
			dy := m.Y - prevY
			dt := m.Timestamp.Sub(prevTime).Seconds()
			if dt > 0 {
				velocity := math.Sqrt(dx*dx+dy*dy) / dt
				totalVelocity += velocity
				varianceX += dx * dx
				varianceY += dy * dy
			}
		}
		prevX, prevY = m.X, m.Y
		prevTime = m.Timestamp
	}

	avgVelocity := totalVelocity / float64(moveCount)
	varianceX = varianceX / float64(moveCount)
	varianceY = varianceY / float64(moveCount)

	humanLike := avgVelocity > 50 && avgVelocity < 2000
	confidence := 0.5
	if humanLike {
		confidence = 0.8
	}
	if varianceX > 0 || varianceY > 0 {
		confidence += 0.1
	}

	return MouseAnalysisResult{
		IsHuman:     humanLike,
		Confidence:  confidence,
		AvgVelocity: avgVelocity,
		ClickCount:  clickCount,
		MoveCount:   moveCount,
		VarianceX:   varianceX,
		VarianceY:   varianceY,
	}
}

func (a *BehaviorProfileAnalyzer) AnalyzeTyping(typing []KeystrokeTiming) TypingAnalysisResult {
	if len(typing) < 2 {
		return TypingAnalysisResult{IsHuman: false, Confidence: 0}
	}

	var totalHoldTime, totalInterKey time.Duration
	var keyCount int

	for i, k := range typing {
		keyCount++
		totalHoldTime += k.HoldTime
		if i > 0 {
			totalInterKey += k.InterKey
		}
	}

	avgHoldTime := totalHoldTime / time.Duration(keyCount)
	avgInterKey := time.Duration(0)
	if keyCount > 1 {
		avgInterKey = totalInterKey / time.Duration(keyCount-1)
	}

	humanLike := avgHoldTime > 20*time.Millisecond && avgHoldTime < 500*time.Millisecond
	humanLike = humanLike && (avgInterKey > 30*time.Millisecond && avgInterKey < 1000*time.Millisecond)

	confidence := 0.5
	if humanLike {
		confidence = 0.8
	}

	return TypingAnalysisResult{
		IsHuman:     humanLike,
		Confidence:  confidence,
		AvgHoldTime: avgHoldTime,
		AvgInterKey: avgInterKey,
		KeyCount:    keyCount,
	}
}

func (a *BehaviorProfileAnalyzer) AnalyzeScrolling(scrolls []ScrollEvent) ScrollAnalysisResult {
	if len(scrolls) < 2 {
		return ScrollAnalysisResult{IsHuman: false, Confidence: 0}
	}

	var totalVelocity, totalDistance float64
	var touchScrollCount, wheelScrollCount int

	prevY := scrolls[0].Y
	prevTime := scrolls[0].Timestamp

	for _, s := range scrolls {
		dy := s.Y - prevY
		dt := s.Timestamp.Sub(prevTime).Seconds()
		if dt > 0 {
			velocity := math.Abs(dy) / dt
			totalVelocity += velocity
			totalDistance += math.Abs(dy)
		}
		if s.IsTouch {
			touchScrollCount++
		} else {
			wheelScrollCount++
		}
		prevY = s.Y
		prevTime = s.Timestamp
	}

	avgVelocity := totalVelocity / float64(len(scrolls))
	humanLike := avgVelocity > 100 && avgVelocity < 10000

	confidence := 0.5
	if humanLike {
		confidence = 0.7
	}

	return ScrollAnalysisResult{
		IsHuman:          humanLike,
		Confidence:       confidence,
		AvgVelocity:      avgVelocity,
		TotalDistance:    totalDistance,
		TouchScrollCount: touchScrollCount,
		WheelScrollCount: wheelScrollCount,
	}
}

func (a *BehaviorProfileAnalyzer) AnalyzeNetworkPatterns(requests []NetworkRequest) NetworkAnalysisResult {
	if len(requests) == 0 {
		return NetworkAnalysisResult{IsHuman: false, Confidence: 0}
	}

	var totalDuration time.Duration
	var cachedCount, xhrCount int

	for _, r := range requests {
		totalDuration += r.Duration
		if r.Cached {
			cachedCount++
		}
		if r.Method == "XMLHttpRequest" || (r.Method == "GET" && r.URL != "" &&
			(strContains(r.URL, ".json") || strContains(r.URL, "/api/"))) {
			xhrCount++
		}
	}

	avgDuration := totalDuration / time.Duration(len(requests))
	cacheRatio := float64(cachedCount) / float64(len(requests))

	humanLike := cacheRatio > 0.1 && cacheRatio < 0.9
	confidence := 0.5
	if humanLike {
		confidence = 0.7
	}

	return NetworkAnalysisResult{
		IsHuman:      humanLike,
		Confidence:   confidence,
		AvgDuration:  avgDuration,
		CacheRatio:   cacheRatio,
		RequestCount: len(requests),
		XHRCount:     xhrCount,
	}
}

func strContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && strContainsHelper(s, substr))
}

func strContainsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type MouseAnalysisResult struct {
	IsHuman     bool
	Confidence  float64
	AvgVelocity float64
	ClickCount  int
	MoveCount   int
	VarianceX   float64
	VarianceY   float64
}

type TypingAnalysisResult struct {
	IsHuman     bool
	Confidence  float64
	AvgHoldTime time.Duration
	AvgInterKey time.Duration
	KeyCount    int
}

type ScrollAnalysisResult struct {
	IsHuman          bool
	Confidence       float64
	AvgVelocity      float64
	TotalDistance    float64
	TouchScrollCount int
	WheelScrollCount int
}

type NetworkAnalysisResult struct {
	IsHuman      bool
	Confidence   float64
	AvgDuration  time.Duration
	CacheRatio   float64
	RequestCount int
	XHRCount     int
}

type BehavioralSignature struct {
	Name           string
	Browser        string
	MouseVariance  float64
	TypingSpeed    float64
	ScrollVelocity float64
	CacheRatio     float64
}

var BehavioralSignatures = map[string]*BehavioralSignature{
	"chrome-human": {
		Name:           "Chrome Human-like",
		Browser:        "chrome",
		MouseVariance:  100,
		TypingSpeed:    200,
		ScrollVelocity: 500,
		CacheRatio:     0.3,
	},
	"firefox-human": {
		Name:           "Firefox Human-like",
		Browser:        "firefox",
		MouseVariance:  150,
		TypingSpeed:    180,
		ScrollVelocity: 600,
		CacheRatio:     0.35,
	},
	"safari-human": {
		Name:           "Safari Human-like",
		Browser:        "safari",
		MouseVariance:  80,
		TypingSpeed:    220,
		ScrollVelocity: 450,
		CacheRatio:     0.25,
	},
	"bot-typical": {
		Name:           "Typical Bot",
		Browser:        "bot",
		MouseVariance:  0,
		TypingSpeed:    5000,
		ScrollVelocity: 100000,
		CacheRatio:     0,
	},
}

type BehavioralGenerator struct {
	signature *BehavioralSignature
	rng       *rand.Rand
}

func NewBehavioralGenerator(sig *BehavioralSignature, seed int64) *BehavioralGenerator {
	return &BehavioralGenerator{
		signature: sig,
		rng:       rand.New(rand.NewSource(seed)), //nolint:gosec // G404: math/rand is sufficient for behavioral generation
	}
}

func (g *BehavioralGenerator) GenerateMouseMovement(duration time.Duration) []MouseMovement {
	var movements []MouseMovement
	startTime := time.Now()
	intervals := int(duration / (50 * time.Millisecond))

	x, y := 100.0, 100.0
	for i := 0; i < intervals; i++ {
		noise := g.rng.Float64() * g.signature.MouseVariance
		x += (g.rng.Float64() - 0.5) * 10 * noise
		y += (g.rng.Float64() - 0.5) * 10 * noise

		movements = append(movements, MouseMovement{
			Timestamp: startTime.Add(time.Duration(i) * 50 * time.Millisecond),
			X:         x,
			Y:         y,
			VelocityX: (g.rng.Float64() - 0.5) * 100,
			VelocityY: (g.rng.Float64() - 0.5) * 100,
		})
	}

	return movements
}

func (g *BehavioralGenerator) GenerateTyping(text string) []KeystrokeTiming {
	var typing []KeystrokeTiming
	startTime := time.Now()

	avgDelay := time.Duration(g.signature.TypingSpeed) * time.Millisecond

	for i, r := range text {
		pressTime := startTime.Add(time.Duration(i) * avgDelay)
		holdTime := time.Duration(50+g.rng.Intn(150)) * time.Millisecond

		interKey := time.Duration(0)
		if i > 0 {
			interKey = time.Duration(float64(avgDelay) * (0.8 + g.rng.Float64()*0.4))
		}

		typing = append(typing, KeystrokeTiming{
			Timestamp: pressTime,
			Key:       string(r),
			PressTime: holdTime,
			HoldTime:  holdTime,
			InterKey:  interKey,
		})
	}

	return typing
}

func (g *BehavioralGenerator) GenerateScrolling(duration time.Duration) []ScrollEvent {
	var scrolls []ScrollEvent
	startTime := time.Now()
	intervals := int(duration / (100 * time.Millisecond))

	y := 0.0
	for i := 0; i < intervals; i++ {
		delta := (g.rng.Float64() - 0.3) * g.signature.ScrollVelocity / 10
		y += delta

		scrolls = append(scrolls, ScrollEvent{
			Timestamp: startTime.Add(time.Duration(i) * 100 * time.Millisecond),
			Y:         y,
			DeltaY:    delta,
			Velocity:  math.Abs(delta) * 10,
			IsTouch:   g.rng.Float64() > 0.5,
		})
	}

	return scrolls
}
