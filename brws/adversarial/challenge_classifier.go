package adversarial

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// InteractionType classifies the primary interaction a challenge requires.
type InteractionType string

const (
	InteractionClickButtons   InteractionType = "click_buttons"   // left/right/arrow buttons
	InteractionDragHorizontal InteractionType = "drag_horizontal" // slider/drag handle
	InteractionDragFreeform   InteractionType = "drag_freeform"   // free-form drag (puzzle piece)
	InteractionRotate         InteractionType = "rotate"          // circular dial rotation
	InteractionGridSelect     InteractionType = "grid_select"     // click grid cells (reCAPTCHA v2)
	InteractionCheckbox       InteractionType = "checkbox"        // simple checkbox click
	InteractionTextInput      InteractionType = "text_input"      // type characters
	InteractionWait           InteractionType = "wait"            // just wait (JS challenge)
	InteractionUnknown        InteractionType = "unknown"
)

// ChallengeSignature captures the structural identity of a challenge page.
type ChallengeSignature struct {
	// Fingerprint is a hash of the structural elements for deduplication.
	Fingerprint string `json:"fingerprint"`

	// Provider identifies the challenge provider (cloudflare, recaptcha, hcaptcha, etc.)
	Provider string `json:"provider"`

	// Interaction is the classified primary interaction type.
	Interaction InteractionType `json:"interaction"`

	// Confidence is how confident the classification is (0.0-1.0).
	Confidence float64 `json:"confidence"`

	// Indicators lists the DOM signals that led to the classification.
	Indicators []string `json:"indicators"`

	// WidgetSelector is the best-guess CSS selector for the interactive widget.
	WidgetSelector string `json:"widget_selector,omitempty"`

	// Dimensions are estimated widget dimensions from DOM analysis.
	WidgetWidth  int `json:"widget_width,omitempty"`
	WidgetHeight int `json:"widget_height,omitempty"`
}

// TraceVariantForInteraction maps interaction types to trace challenge variants.
// This is the bridge between classified challenges and the trace library.
var TraceVariantForInteraction = map[InteractionType][]string{
	InteractionClickButtons:   {"orientlr", "orient3d"},
	InteractionDragHorizontal: {"slide", "drag"},
	InteractionDragFreeform:   {"drag"},
	InteractionRotate:         {"rotate"},
	InteractionGridSelect:     {"grid_select"},
	InteractionCheckbox:       {"checkbox"},
	InteractionWait:           {"slide"}, // minimal interaction, just mouse movement
}

// ClassifyChallenge analyzes HTML content to determine the interaction type.
func ClassifyChallenge(body []byte, headers map[string][]string) *ChallengeSignature {
	html := strings.ToLower(string(body))
	sig := &ChallengeSignature{}

	// Step 1: Identify provider
	sig.Provider = detectProvider(html, headers)

	// Step 2: Classify interaction type from DOM signals
	sig.Interaction, sig.Confidence, sig.Indicators = classifyInteraction(html)

	// Step 3: Try to identify the widget selector
	sig.WidgetSelector = detectWidgetSelector(html)

	// Step 4: Compute structural fingerprint
	sig.Fingerprint = computeStructuralFingerprint(html, sig.Provider, sig.Interaction)

	return sig
}

func detectProvider(html string, headers map[string][]string) string {
	// Header-based detection
	for _, v := range headers["Server"] {
		if strings.Contains(strings.ToLower(v), "cloudflare") {
			return "cloudflare"
		}
	}

	// Body-based detection
	providers := []struct {
		name    string
		markers []string
	}{
		{"cloudflare", []string{"cf-turnstile", "cf-challenge", "challenges.cloudflare.com", "cf-chl-widget"}},
		{"recaptcha", []string{"google.com/recaptcha", "g-recaptcha", "grecaptcha"}},
		{"hcaptcha", []string{"hcaptcha.com", "h-captcha", "data-hcaptcha"}},
		{"datadome", []string{"datadome", "dd.js", "captcha-delivery.com"}},
		{"arkose", []string{"arkoselabs.com", "funcaptcha", "arkose"}},
		{"geetest", []string{"geetest.com", "gt_lib", "geetest_"}},
		{"perimeterx", []string{"perimeterx", "px-captcha", "_pxhd"}},
	}

	for _, p := range providers {
		for _, marker := range p.markers {
			if strings.Contains(html, marker) {
				return p.name
			}
		}
	}

	return "unknown"
}

func classifyInteraction(html string) (InteractionType, float64, []string) {
	type signal struct {
		interaction InteractionType
		weight      float64
		indicator   string
	}

	var signals []signal

	// --- Button-based interaction ---
	buttonPatterns := []struct {
		pattern   string
		indicator string
	}{
		{"arrow", "arrow button/icon"},
		{"rotate-left", "rotate-left button"},
		{"rotate-right", "rotate-right button"},
		{"btn-left", "left button"},
		{"btn-right", "right button"},
		{"arrow_back", "back arrow"},
		{"arrow_forward", "forward arrow"},
		{"chevron_left", "left chevron"},
		{"chevron_right", "right chevron"},
	}
	for _, bp := range buttonPatterns {
		if strings.Contains(html, bp.pattern) {
			signals = append(signals, signal{InteractionClickButtons, 0.6, bp.indicator})
		}
	}
	// Multiple directional buttons = strong signal
	dirCount := countPatterns(html, []string{"left", "right"}, "button", "btn", "arrow")
	if dirCount >= 2 {
		signals = append(signals, signal{InteractionClickButtons, 0.4, fmt.Sprintf("%d directional elements", dirCount)})
	}

	// --- Drag/slider interaction ---
	dragPatterns := []struct {
		pattern   string
		indicator string
	}{
		{"slider", "slider element"},
		{"range", "range input"},
		{"draggable", "draggable attribute"},
		{"slide-track", "slide track"},
		{"drag-handle", "drag handle"},
		{"puzzle-piece", "puzzle piece"},
		{"swipe", "swipe element"},
		{"slidecontainer", "slide container"},
	}
	for _, dp := range dragPatterns {
		if strings.Contains(html, dp.pattern) {
			signals = append(signals, signal{InteractionDragHorizontal, 0.5, dp.indicator})
		}
	}
	// input type="range" is a strong slider signal
	if regexp.MustCompile(`<input[^>]+type\s*=\s*["']range["']`).MatchString(html) {
		signals = append(signals, signal{InteractionDragHorizontal, 0.8, "input[type=range]"})
	}

	// --- Rotation interaction ---
	rotatePatterns := []string{"rotate", "dial", "compass", "angle", "orientation", "spin"}
	for _, rp := range rotatePatterns {
		if strings.Contains(html, rp) {
			signals = append(signals, signal{InteractionRotate, 0.4, rp + " keyword"})
		}
	}
	// SVG circle + transform is strong rotation signal
	if strings.Contains(html, "<circle") && strings.Contains(html, "transform") {
		signals = append(signals, signal{InteractionRotate, 0.6, "SVG circle + transform"})
	}

	// --- Grid selection ---
	gridPatterns := []string{"image_grid", "tile", "grid-cell", "rc-imageselect"}
	for _, gp := range gridPatterns {
		if strings.Contains(html, gp) {
			signals = append(signals, signal{InteractionGridSelect, 0.7, gp})
		}
	}
	// Multiple clickable image tiles
	imgTileCount := strings.Count(html, "rc-image-tile")
	if imgTileCount >= 4 {
		signals = append(signals, signal{InteractionGridSelect, 0.9, fmt.Sprintf("%d image tiles", imgTileCount)})
	}

	// --- Checkbox ---
	if strings.Contains(html, "checkbox") && (strings.Contains(html, "captcha") || strings.Contains(html, "verify")) {
		signals = append(signals, signal{InteractionCheckbox, 0.7, "captcha checkbox"})
	}
	if strings.Contains(html, "rc-anchor-checkbox") {
		signals = append(signals, signal{InteractionCheckbox, 0.9, "reCAPTCHA checkbox"})
	}

	// --- Text input ---
	if strings.Contains(html, "captcha") && regexp.MustCompile(`<input[^>]+type\s*=\s*["']text["']`).MatchString(html) {
		signals = append(signals, signal{InteractionTextInput, 0.5, "text input near captcha"})
	}

	// --- Wait (JS challenge) ---
	if strings.Contains(html, "challenge-platform") && !strings.Contains(html, "interactive") {
		signals = append(signals, signal{InteractionWait, 0.6, "non-interactive challenge"})
	}
	if strings.Contains(html, "jschl-answer") || strings.Contains(html, "cf-chl-bypass") {
		signals = append(signals, signal{InteractionWait, 0.7, "JS challenge markers"})
	}

	if len(signals) == 0 {
		return InteractionUnknown, 0.0, nil
	}

	// Aggregate by type: sum weights
	scores := make(map[InteractionType]float64)
	indicatorsByType := make(map[InteractionType][]string)
	for _, s := range signals {
		scores[s.interaction] += s.weight
		indicatorsByType[s.interaction] = append(indicatorsByType[s.interaction], s.indicator)
	}

	// Pick the highest scoring type
	var bestType InteractionType
	var bestScore float64
	for t, score := range scores {
		if score > bestScore {
			bestType = t
			bestScore = score
		}
	}

	// Normalize confidence to [0, 1]
	confidence := bestScore
	if confidence > 1.0 {
		confidence = 1.0
	}

	return bestType, confidence, indicatorsByType[bestType]
}

func detectWidgetSelector(html string) string {
	// Known widget selectors in priority order
	selectors := []struct {
		marker   string
		selector string
	}{
		{"cf-turnstile", "div.cf-turnstile"},
		{"g-recaptcha", "div.g-recaptcha"},
		{"h-captcha", "div.h-captcha"},
		{"rc-anchor", "div.rc-anchor"},
		{"rc-imageselect", "div.rc-imageselect"},
		{"captcha-container", "div.captcha-container"},
		{"challenge-container", "div.challenge-container"},
		{"captcha", "div[id*=captcha]"},
	}

	for _, s := range selectors {
		if strings.Contains(html, s.marker) {
			return s.selector
		}
	}
	return ""
}

func computeStructuralFingerprint(html, provider string, interaction InteractionType) string {
	// Hash key structural elements, not content
	h := sha256.New()
	h.Write([]byte(provider))
	h.Write([]byte(string(interaction)))

	// Count structural elements
	elements := []string{"<button", "<input", "<canvas", "<svg", "<iframe", "<div class="}
	for _, el := range elements {
		count := strings.Count(html, el)
		h.Write([]byte(fmt.Sprintf("%s:%d", el, count)))
	}

	// Hash script sources (not content) for stability
	srcRe := regexp.MustCompile(`src\s*=\s*["']([^"']+)["']`)
	for _, match := range srcRe.FindAllStringSubmatch(html, 20) {
		h.Write([]byte(match[1]))
	}

	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// countPatterns counts how many of the context words co-occur with any of the target words
// in the same approximate region of the HTML.
func countPatterns(html string, targets []string, contexts ...string) int {
	count := 0
	for _, target := range targets {
		idx := 0
		for {
			pos := strings.Index(html[idx:], target)
			if pos == -1 {
				break
			}
			pos += idx
			// Check if any context word is within 200 chars
			start := pos - 200
			if start < 0 {
				start = 0
			}
			end := pos + 200
			if end > len(html) {
				end = len(html)
			}
			region := html[start:end]
			for _, ctx := range contexts {
				if strings.Contains(region, ctx) {
					count++
					break
				}
			}
			idx = pos + len(target)
		}
	}
	return count
}
