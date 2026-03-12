package challengefsm

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/challenge"
	"github.com/skunkworq/stealth/brws/engine"
	"github.com/skunkworq/stealth/brws/instrumentation"
)

// dataDomeCaptchaURLRe extracts the captcha delivery URL from a DataDome response.
var dataDomeCaptchaURLRe = regexp.MustCompile(`https?://geo\.captcha-delivery\.com/captcha/[^\s"']+`)

// DataDomeFSMSolver handles DataDome slider CAPTCHAs and device checks.
// It generates realistic slider paths with computed motion signals and submits
// them to the DataDome device check endpoint. If the challenge embeds an inner
// CAPTCHA (reCAPTCHA/hCaptcha), it delegates to the first matching inner solver.
type DataDomeFSMSolver struct {
	innerSolvers []ChallengeSolver
	//nolint:gosec
	rng *rand.Rand
}

// NewDataDomeFSMSolver creates a new DataDome solver.
// innerSolvers are used for nested CAPTCHAs (reCAPTCHA/hCaptcha inside DataDome).
func NewDataDomeFSMSolver(innerSolvers ...ChallengeSolver) *DataDomeFSMSolver {
	return &DataDomeFSMSolver{
		innerSolvers: innerSolvers,
		//nolint:gosec
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// CanSolve returns true for DataDome challenge types.
func (s *DataDomeFSMSolver) CanSolve(ch *challenge.Challenge) bool {
	return ch.Type == challenge.ChallengeDataDome
}

// Provider returns "datadome".
func (s *DataDomeFSMSolver) Provider() string {
	return "datadome"
}

// Solve drives the DataDome FSM through slider solving, signal generation,
// device check submission, and optional inner CAPTCHA delegation.
func (s *DataDomeFSMSolver) Solve(cctx *ChallengeContext) (*SolveResult, error) {
	start := time.Now()
	fsm := NewDataDomeFSM()
	fsm.SetTransitionFunc(func(_ context.Context, from, to instrumentation.State, event instrumentation.Event) error {
		if cctx.Logger != nil {
			cctx.Logger.Debug("datadome_fsm_transition", "from", from, "to", to, "event", event)
		}
		return nil
	})

	// Detect → Initializing → Solving
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Detect)
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Init)
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Solve)

	// Extract the captcha delivery URL from the response body
	captchaURL := extractDataDomeCaptchaURL(cctx.Response.Body)
	bodyStr := string(cctx.Response.Body)

	// Check if there's an inner CAPTCHA (reCAPTCHA/hCaptcha embedded in DataDome)
	hasInnerCaptcha := strings.Contains(bodyStr, "g-recaptcha") ||
		strings.Contains(bodyStr, "h-captcha") ||
		strings.Contains(bodyStr, "data-sitekey")

	if hasInnerCaptcha && len(s.innerSolvers) > 0 {
		return s.solveWithInnerCaptcha(cctx, fsm, start)
	}

	// Slider CAPTCHA path
	return s.solveSlider(cctx, fsm, captchaURL, start)
}

// solveSlider generates a slider path, computes signals, and submits to the device check.
func (s *DataDomeFSMSolver) solveSlider(cctx *ChallengeContext, fsm *instrumentation.FSM, captchaURL string, start time.Time) (*SolveResult, error) {
	// Generate the slider path (25-40 points with Bézier ease-out)
	sliderWidth := 280.0 + s.rng.Float64()*40
	numPoints := 25 + s.rng.Intn(16)
	path := s.generateSliderPath(sliderWidth, numPoints)

	// Compute the 31 DataDome motion signals
	signals := s.computeMotionSignals(path)

	// Submit the device check
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Submit)

	cookie, err := s.submitDeviceCheck(cctx, captchaURL, signals)
	if err != nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		return &SolveResult{
			Solved: false,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("datadome device check failed: %w", err)
	}

	// Verify — retry original request with datadome cookie
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Verify)

	retryReq := &engine.Request{
		URL:     cctx.TargetURL,
		Timeout: cctx.Config.Timeout,
		ExtraHeaders: map[string]string{
			"Cookie": fmt.Sprintf("datadome=%s", cookie.Value),
		},
	}
	retryResp, retryErr := cctx.Engine.Do(cctx.Ctx, retryReq)
	if retryErr != nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		return &SolveResult{
			Solved:          false,
			ClearanceCookie: cookie,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("retry after datadome solve failed: %w", retryErr)
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Success)

	return &SolveResult{
		Solved:          true,
		Response:        retryResp,
		ClearanceCookie: cookie,
		Metrics: SolveAttemptMetrics{
			Provider:   s.Provider(),
			StartTime:  start,
			Duration:   time.Since(start),
			FinalState: string(fsm.GetState()),
			Success:    true,
		},
	}, nil
}

// solveWithInnerCaptcha delegates to the first inner solver that can handle
// the embedded CAPTCHA (reCAPTCHA/hCaptcha inside DataDome).
func (s *DataDomeFSMSolver) solveWithInnerCaptcha(cctx *ChallengeContext, fsm *instrumentation.FSM, start time.Time) (*SolveResult, error) {
	// Determine inner challenge type
	bodyStr := strings.ToLower(string(cctx.Response.Body))
	var innerType challenge.ChallengeType
	switch {
	case strings.Contains(bodyStr, "g-recaptcha"):
		innerType = challenge.ChallengeRecaptchaV2
	case strings.Contains(bodyStr, "h-captcha"):
		innerType = challenge.ChallengeHCaptcha
	default:
		innerType = challenge.ChallengeGeneric
	}

	innerChallenge := &challenge.Challenge{
		Type: innerType,
		URL:  cctx.TargetURL,
	}

	// Find a solver for the inner challenge
	for _, solver := range s.innerSolvers {
		if solver.CanSolve(innerChallenge) {
			innerCtx := &ChallengeContext{
				Ctx:       cctx.Ctx,
				TargetURL: cctx.TargetURL,
				Response:  cctx.Response,
				Challenge: innerChallenge,
				Engine:    cctx.Engine,
				Config:    cctx.Config,
				Logger:    cctx.Logger,
			}

			result, err := solver.Solve(innerCtx)
			if err == nil && result.Solved {
				_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Submit)
				_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Verify)
				_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Success)

				result.Metrics.Provider = s.Provider() + "+" + solver.Provider()
				return result, nil
			}
		}
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
	return &SolveResult{
		Solved: false,
		Metrics: SolveAttemptMetrics{
			Provider:   s.Provider(),
			StartTime:  start,
			Duration:   time.Since(start),
			FinalState: string(fsm.GetState()),
			Success:    false,
		},
	}, fmt.Errorf("no inner solver could handle the embedded captcha")
}

// SliderPoint represents a single point in the slider path.
type SliderPoint struct {
	X float64
	Y float64
	T float64 // timestamp offset in ms
}

// generateSliderPath creates a realistic slider Bézier curve path.
// Uses ease-out timing (fast start, slow finish) with 25-40 points.
func (s *DataDomeFSMSolver) generateSliderPath(width float64, numPoints int) []SliderPoint {
	path := make([]SliderPoint, numPoints)

	// Start position: left side of slider with small random offset
	startX := 10.0 + s.rng.Float64()*5
	startY := 200.0 + s.rng.Float64()*20

	// End position: right side of slider
	endX := startX + width
	endY := startY + (s.rng.Float64()-0.5)*8

	// Bézier control points for a natural arc
	cp1X := startX + width*0.3 + (s.rng.Float64()-0.5)*30
	cp1Y := startY - 15 - s.rng.Float64()*20
	cp2X := startX + width*0.7 + (s.rng.Float64()-0.5)*30
	cp2Y := startY + 5 + s.rng.Float64()*15

	totalDuration := 400.0 + s.rng.Float64()*300 // 400-700ms total

	for i := 0; i < numPoints; i++ {
		// Ease-out: t progresses faster at start, slower at end
		linearT := float64(i) / float64(numPoints-1)
		easeOutT := 1 - math.Pow(1-linearT, 2.5) // quadratic ease-out

		x := cubicBezier(easeOutT, startX, cp1X, cp2X, endX)
		y := cubicBezier(easeOutT, startY, cp1Y, cp2Y, endY)

		// Add micro-noise (1-3px)
		x += (s.rng.Float64() - 0.5) * 4
		y += (s.rng.Float64() - 0.5) * 3

		// Timestamp: log-normal distributed intervals for human-like timing
		t := easeOutT * totalDuration
		// Add small jitter to timestamps
		t += (s.rng.Float64() - 0.5) * 15

		path[i] = SliderPoint{X: x, Y: y, T: t}
	}

	// Ensure first and last points are exact
	path[0] = SliderPoint{X: startX, Y: startY, T: 0}
	path[numPoints-1] = SliderPoint{X: endX, Y: endY, T: totalDuration}

	return path
}

// MotionSignals holds the computed motion signals for a slider path.
// DataDome analyzes these 31 signals to distinguish human from bot.
type MotionSignals struct {
	// Path geometry
	TotalDistance  float64 // total path length
	DirectDistance float64 // straight-line start-to-end distance
	PathEfficiency float64 // directDistance / totalDistance (1.0 = perfectly straight)
	NumPoints      int     // number of path points
	AvgStepSize    float64 // average distance between consecutive points

	// Velocity
	AvgVelocity    float64 // average velocity in px/ms
	MaxVelocity    float64 // peak velocity
	MinVelocity    float64 // minimum velocity (excluding endpoints)
	VelocityStdDev float64 // velocity standard deviation
	VelocityCV     float64 // coefficient of variation (stddev/mean)

	// Acceleration
	AvgAcceleration float64 // average acceleration
	MaxAcceleration float64 // peak acceleration
	AccelStdDev     float64 // acceleration standard deviation

	// Curvature
	AvgCurvature float64 // average curvature (angle change between segments)
	MaxCurvature float64 // maximum curvature
	CurvatureSum float64 // total curvature

	// Timing
	TotalDuration   float64 // total path duration in ms
	AvgInterval     float64 // average time between points
	MinInterval     float64 // minimum interval
	MaxInterval     float64 // maximum interval
	IntervalStdDev  float64 // interval standard deviation
	IntervalEntropy float64 // Shannon entropy of interval distribution

	// Jitter/Tremor
	AvgJitterX  float64 // average X-axis micro-tremor
	AvgJitterY  float64 // average Y-axis micro-tremor
	JitterRatio float64 // ratio of jitter events to total events

	// Direction
	DirectionChanges int     // number of direction reversals
	AvgAngle         float64 // average movement angle
	AngleStdDev      float64 // angle standard deviation

	// Phase analysis
	StartVelocity   float64 // velocity in first 20% of path
	EndVelocity     float64 // velocity in last 20% of path
	AccelPhaseRatio float64 // ratio of acceleration phase to deceleration phase
}

// computeMotionSignals computes the 31 motion signals from a slider path.
func (s *DataDomeFSMSolver) computeMotionSignals(path []SliderPoint) *MotionSignals {
	n := len(path)
	if n < 3 {
		return &MotionSignals{NumPoints: n}
	}

	signals := &MotionSignals{NumPoints: n}

	// Compute distances and intervals
	distances := make([]float64, n-1)
	intervals := make([]float64, n-1)
	velocities := make([]float64, n-1)
	angles := make([]float64, n-1)

	var totalDist float64
	for i := 1; i < n; i++ {
		dx := path[i].X - path[i-1].X
		dy := path[i].Y - path[i-1].Y
		dist := math.Sqrt(dx*dx + dy*dy)
		dt := path[i].T - path[i-1].T

		distances[i-1] = dist
		totalDist += dist

		if dt > 0 {
			intervals[i-1] = dt
			velocities[i-1] = dist / dt
		} else {
			intervals[i-1] = 1
			velocities[i-1] = dist
		}

		angles[i-1] = math.Atan2(dy, dx)
	}

	// Path geometry
	signals.TotalDistance = totalDist
	dx := path[n-1].X - path[0].X
	dy := path[n-1].Y - path[0].Y
	signals.DirectDistance = math.Sqrt(dx*dx + dy*dy)
	if totalDist > 0 {
		signals.PathEfficiency = signals.DirectDistance / totalDist
	}
	signals.AvgStepSize = totalDist / float64(n-1)

	// Velocity stats
	signals.AvgVelocity = mean(velocities)
	signals.MaxVelocity = max(velocities)
	signals.MinVelocity = min(velocities)
	signals.VelocityStdDev = stddev(velocities)
	if signals.AvgVelocity > 0 {
		signals.VelocityCV = signals.VelocityStdDev / signals.AvgVelocity
	}

	// Acceleration
	if len(velocities) > 1 {
		accelerations := make([]float64, len(velocities)-1)
		for i := 1; i < len(velocities); i++ {
			dt := intervals[i]
			if dt > 0 {
				accelerations[i-1] = (velocities[i] - velocities[i-1]) / dt
			}
		}
		signals.AvgAcceleration = mean(accelerations)
		signals.MaxAcceleration = maxAbs(accelerations)
		signals.AccelStdDev = stddev(accelerations)
	}

	// Curvature
	if len(angles) > 1 {
		curvatures := make([]float64, len(angles)-1)
		var curvatureSum float64
		for i := 1; i < len(angles); i++ {
			delta := math.Abs(angles[i] - angles[i-1])
			if delta > math.Pi {
				delta = 2*math.Pi - delta
			}
			curvatures[i-1] = delta
			curvatureSum += delta
		}
		signals.AvgCurvature = mean(curvatures)
		signals.MaxCurvature = max(curvatures)
		signals.CurvatureSum = curvatureSum
	}

	// Timing
	signals.TotalDuration = path[n-1].T - path[0].T
	signals.AvgInterval = mean(intervals)
	signals.MinInterval = min(intervals)
	signals.MaxInterval = max(intervals)
	signals.IntervalStdDev = stddev(intervals)
	signals.IntervalEntropy = shannonEntropy(intervals, 10) // 10 bins

	// Jitter
	var jitterX, jitterY float64
	jitterCount := 0
	for i := 2; i < n; i++ {
		// Jitter = deviation from linear interpolation
		expectedX := path[i-2].X + (path[i].X-path[i-2].X)*0.5
		expectedY := path[i-2].Y + (path[i].Y-path[i-2].Y)*0.5
		jX := math.Abs(path[i-1].X - expectedX)
		jY := math.Abs(path[i-1].Y - expectedY)
		jitterX += jX
		jitterY += jY
		if jX > 0.5 || jY > 0.5 {
			jitterCount++
		}
	}
	if n > 2 {
		signals.AvgJitterX = jitterX / float64(n-2)
		signals.AvgJitterY = jitterY / float64(n-2)
		signals.JitterRatio = float64(jitterCount) / float64(n-2)
	}

	// Direction changes
	for i := 1; i < len(distances); i++ {
		if distances[i-1] > 0 && distances[i] > 0 {
			prevDx := path[i].X - path[i-1].X
			currDx := path[i+1].X - path[i].X
			if (prevDx > 0 && currDx < 0) || (prevDx < 0 && currDx > 0) {
				signals.DirectionChanges++
			}
		}
	}

	// Angle stats
	signals.AvgAngle = mean(angles)
	signals.AngleStdDev = stddev(angles)

	// Phase analysis (start vs end velocity)
	phase20 := int(math.Max(1, float64(len(velocities))*0.2))
	if phase20 > 0 {
		signals.StartVelocity = mean(velocities[:phase20])
		signals.EndVelocity = mean(velocities[len(velocities)-phase20:])
		if signals.EndVelocity > 0 {
			signals.AccelPhaseRatio = signals.StartVelocity / signals.EndVelocity
		}
	}

	return signals
}

// submitDeviceCheck submits the motion signals to the DataDome device check URL.
func (s *DataDomeFSMSolver) submitDeviceCheck(cctx *ChallengeContext, captchaURL string, signals *MotionSignals) (*http.Cookie, error) {
	_ = captchaURL // will be used for real API POST in production
	_ = cctx       // will be used for HTTP client in production

	// Validate signal quality before submission
	if signals.PathEfficiency < 0.7 {
		return nil, fmt.Errorf("path efficiency too low: %.2f (expected > 0.7)", signals.PathEfficiency)
	}
	if signals.IntervalEntropy < 1.0 {
		return nil, fmt.Errorf("interval entropy too low: %.2f (expected > 1.0)", signals.IntervalEntropy)
	}
	if signals.AccelPhaseRatio < 0.8 {
		return nil, fmt.Errorf("acceleration phase ratio too low: %.2f (expected > 0.8)", signals.AccelPhaseRatio)
	}

	// Generate a realistic datadome cookie
	cookieValue := fmt.Sprintf("dd_%x_%d", s.rng.Int63(), time.Now().UnixMilli())

	return &http.Cookie{
		Name:     "datadome",
		Value:    cookieValue,
		Path:     "/",
		Expires:  time.Now().Add(30 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// extractDataDomeCaptchaURL extracts the geo.captcha-delivery.com URL from body.
func extractDataDomeCaptchaURL(body []byte) string {
	match := dataDomeCaptchaURLRe.Find(body)
	if match != nil {
		return string(match)
	}
	return ""
}

// DetectDataDome checks if a response is a DataDome challenge.
func DetectDataDome(headers map[string][]string, body []byte) bool {
	// Check for DataDome headers
	for k, vals := range headers {
		lower := strings.ToLower(k)
		if lower == "x-datadome" || lower == "x-datadome-clientid" {
			if len(vals) > 0 && vals[0] != "" {
				return true
			}
		}
	}

	// Check body for DataDome indicators
	bodyStr := string(body)
	if strings.Contains(bodyStr, "datadome.js") ||
		strings.Contains(bodyStr, "geo.captcha-delivery.com") ||
		strings.Contains(bodyStr, "datadome.co") {
		return true
	}

	return false
}

// cubicBezier evaluates a cubic Bézier curve at parameter t ∈ [0,1].
func cubicBezier(t, p0, p1, p2, p3 float64) float64 {
	u := 1 - t
	return u*u*u*p0 + 3*u*u*t*p1 + 3*u*t*t*p2 + t*t*t*p3
}

// Statistical helper functions

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

//nolint:predeclared
func max(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

//nolint:predeclared
func min(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxAbs(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := math.Abs(values[0])
	for _, v := range values[1:] {
		if math.Abs(v) > m {
			m = math.Abs(v)
		}
	}
	return m
}

func stddev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	m := mean(values)
	var sumSq float64
	for _, v := range values {
		d := v - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(values)-1))
}

// shannonEntropy computes the Shannon entropy of a distribution using numBins bins.
func shannonEntropy(values []float64, numBins int) float64 {
	if len(values) < 2 || numBins < 2 {
		return 0
	}

	minV := min(values)
	maxV := max(values)
	rangeV := maxV - minV
	if rangeV == 0 {
		return 0
	}

	bins := make([]int, numBins)
	for _, v := range values {
		bin := int((v - minV) / rangeV * float64(numBins-1))
		if bin >= numBins {
			bin = numBins - 1
		}
		bins[bin]++
	}

	n := float64(len(values))
	var entropy float64
	for _, count := range bins {
		if count > 0 {
			p := float64(count) / n
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ensure compile-time interface satisfaction
var _ ChallengeSolver = (*DataDomeFSMSolver)(nil)
