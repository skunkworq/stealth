// Package behavior provides mouse and keyboard simulation for stealth browsing.

package behavior

import (
	"fmt"
	"math/rand"
	"time"
)

// behaviorRand is a local random source for behavior simulation.
// math/rand is used intentionally (not crypto/rand) because:
// 1. We need reproducible randomness for testing browser automation
// 2. Performance is more important than cryptographic security for UI simulation
// 3. The randomness is used for visual timing effects, not security purposes
//nolint:gosec // G404: math/rand is intentional for non-cryptographic use
var behaviorRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// MouseSimulator simulates human-like mouse movements for browser automation
type MouseSimulator struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewMouseSimulator creates a simulator. If exact timings are passed, it clones them, else randomizes.
func NewMouseSimulator(baseDelay time.Duration) *MouseSimulator {
	if baseDelay == 0 {
		return &MouseSimulator{
			minDelay: 50 * time.Millisecond,
			maxDelay: 200 * time.Millisecond,
		}
	}
	// Adaptive FSM override
	return &MouseSimulator{
		minDelay: baseDelay,
		maxDelay: baseDelay + (50 * time.Millisecond),
	}
}

// MoveTo generates JavaScript to move the mouse to the specified coordinates
// Returns JavaScript code that simulates natural mouse movement using bezier curves
func (m *MouseSimulator) MoveTo(x, y float64) string {
	delay := randomDuration(m.minDelay, m.maxDelay)
	duration := time.Duration(behaviorRand.Intn(300) + 200)

	ctrlX := x/2 + randomFloat(-100, 100)
	ctrlY := y/2 + randomFloat(-100, 100)
	steps := int(duration.Milliseconds() / 16)

	return fmt.Sprintf(`
		(async () => {
			const startX = 0, startY = 0;
			const ctrlX = %f, ctrlY = %f;
			const endX = %f, endY = %f;
			const steps = %d;
			const duration = %d;
			
			function bezier(p0, p1, p2, t) {
				return (1-t)*(1-t)*p0 + 2*(1-t)*t*p1 + t*t*p2;
			}
			
			function easeInOutCubic(t) {
				return t < 0.5 ? 4*t*t*t : 1-Math.pow(-2*t+2, 3)/2;
			}
			
			function rand(min, max) {
				return Math.random() * (max - min) + min;
			}
			
			await new Promise(r => setTimeout(r, %d));
			
			for (let i = 0; i <= steps; i++) {
				const t = easeInOutCubic(i / steps);
				const px = bezier(startX, ctrlX, endX, t);
				const py = bezier(startY, ctrlY, endY, t);
				const jitter = Math.max(0.5, (1-t) * 2);
				
				window.dispatchEvent(new MouseEvent('mousemove', {
					clientX: px + rand(-jitter, jitter),
					clientY: py + rand(-jitter, jitter),
					bubbles: true
				}));
				
				await new Promise(r => setTimeout(r, duration / steps));
			}
		})()
	`, ctrlX, ctrlY, x, y, steps, duration.Milliseconds(), delay.Milliseconds())
}

// ClickAt generates JavaScript to move to and click at the specified coordinates
// Returns JavaScript code that simulates a natural mouse click
func (m *MouseSimulator) ClickAt(x, y float64) string {
	return fmt.Sprintf(`
		(async () => {
			%s
			window.dispatchEvent(new MouseEvent('mousedown', {clientX: %f, clientY: %f, bubbles: true}));
			window.dispatchEvent(new MouseEvent('mouseup', {clientX: %f, clientY: %f, bubbles: true}));
			window.dispatchEvent(new MouseEvent('click', {clientX: %f, clientY: %f, bubbles: true}));
		})()
	`, m.MoveTo(x, y), x, y, x, y, x, y)
}

// TypingSimulator simulates human-like keyboard input with realistic delays
// and occasional mistakes with corrections
type TypingSimulator struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewTypingSimulator creates a simulator. If baseDelay passed, it overrides typing speed.
func NewTypingSimulator(baseDelay time.Duration) *TypingSimulator {
	if baseDelay == 0 {
		return &TypingSimulator{
			minDelay: 50 * time.Millisecond,
			maxDelay: 150 * time.Millisecond,
		}
	}
	return &TypingSimulator{
		minDelay: baseDelay,
		maxDelay: baseDelay + (30 * time.Millisecond),
	}
}

// Type generates JavaScript to simulate typing the given text
// Includes realistic delays between keystrokes and occasional backspace corrections
func (t *TypingSimulator) Type(text string) string {
	var events string
	runes := []rune(text)

	for i, r := range runes {
		delay := randomDuration(t.minDelay, t.maxDelay)
		char := string(r)

		if r == '\n' {
			char = "Enter"
			events += fmt.Sprintf(`
				await new Promise(r => setTimeout(r, %d));
				window.dispatchEvent(new KeyboardEvent('keydown', {key: '%s', code: 'Enter', bubbles: true}));
				window.dispatchEvent(new KeyboardEvent('keyup', {key: '%s', code: 'Enter', bubbles: true}));
			`, delay.Milliseconds(), char, char)
		} else {
			events += fmt.Sprintf(`
				await new Promise(r => setTimeout(r, %d));
				window.dispatchEvent(new KeyboardEvent('keydown', {key: '%s', code: 'Key%s', bubbles: true}));
				window.dispatchEvent(new InputEvent('input', {data: '%s', inputType: 'insertText', bubbles: true}));
				window.dispatchEvent(new KeyboardEvent('keyup', {key: '%s', code: 'Key%s', bubbles: true}));
			`, delay.Milliseconds(), char, toUpperFirst(char), char, char, toUpperFirst(char))
		}

		if i < len(runes)-1 && behaviorRand.Float32() < 0.05 {
			backspaceDelay := randomDuration(100*time.Millisecond, 300*time.Millisecond)
			events += fmt.Sprintf(`
				await new Promise(r => setTimeout(r, %d));
				window.dispatchEvent(new KeyboardEvent('keydown', {key: 'Backspace', code: 'Backspace', bubbles: true}));
				window.dispatchEvent(new InputEvent('input', {inputType: 'deleteContentBackward', bubbles: true}));
				window.dispatchEvent(new KeyboardEvent('keyup', {key: 'Backspace', code: 'Backspace', bubbles: true}));
			`, backspaceDelay.Milliseconds())
		}
	}

	return fmt.Sprintf(`(async () => { %s })()`, events)
}

// ScrollSimulator simulates human-like scrolling behavior with natural delays
type ScrollSimulator struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewScrollSimulator creates a simulator. If baseDelay passed, scroll physics match origin.
func NewScrollSimulator(baseDelay time.Duration) *ScrollSimulator {
	if baseDelay == 0 {
		return &ScrollSimulator{
			minDelay: 100 * time.Millisecond,
			maxDelay: 300 * time.Millisecond,
		}
	}
	return &ScrollSimulator{
		minDelay: baseDelay,
		maxDelay: baseDelay + (100 * time.Millisecond),
	}
}

// ScrollTo generates JavaScript to scroll to a specific vertical position
// Uses smooth scrolling with natural delays between scroll steps
func (s *ScrollSimulator) ScrollTo(y float64) string {
	return s.ScrollBy(y - 0)
}

// ScrollBy generates JavaScript to scroll by a delta amount
// Returns JavaScript code that simulates incremental scrolling with delays
func (s *ScrollSimulator) ScrollBy(deltaY float64) string {
	delay := randomDuration(s.minDelay, s.maxDelay)
	steps := behaviorRand.Intn(5) + 3
	stepSize := deltaY / float64(steps)

	events := ""
	for i := 0; i < steps; i++ {
		events += fmt.Sprintf(`
			window.scrollBy({top: %f, left: 0, behavior: 'auto'});
			window.dispatchEvent(new Event('scroll', {bubbles: true}));
		`, stepSize)
		if i < steps-1 {
			events += "await new Promise(r => setTimeout(r, " + fmt.Sprintf("%d", behaviorRand.Intn(30)+10) + "));"
		}
	}

	return fmt.Sprintf(`(async () => { await new Promise(r => setTimeout(r, %d)); %s })()`, delay.Milliseconds(), events)
}

// ScrollDown generates JavaScript to scroll down by the specified number of pixels
func (s *ScrollSimulator) ScrollDown(pixels float64) string {
	return s.ScrollBy(pixels)
}

// ScrollUp generates JavaScript to scroll up by the specified number of pixels
func (s *ScrollSimulator) ScrollUp(pixels float64) string {
	return s.ScrollBy(-pixels)
}

// SmoothScrollTo generates JavaScript to smoothly scroll to a vertical position
// Uses native smooth scrolling with a delay to allow animation completion
func (s *ScrollSimulator) SmoothScrollTo(y float64) string {
	return fmt.Sprintf(`
		(async () => {
			await new Promise(r => setTimeout(r, %d));
			window.scrollTo({top: %f, left: 0, behavior: 'smooth'});
			await new Promise(r => setTimeout(r, 1000));
		})()
	`, randomDuration(100*time.Millisecond, 300*time.Millisecond).Milliseconds(), y)
}

func randomDuration(minDuration, maxDuration time.Duration) time.Duration {
	return time.Duration(behaviorRand.Int63n(int64(maxDuration-minDuration))) + minDuration
}

func randomFloat(minVal, maxVal float64) float64 {
	return minVal + behaviorRand.Float64()*(maxVal-minVal)
}

func toUpperFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return string([]byte{[]byte(s)[0] - 32}) + s[1:]
}
