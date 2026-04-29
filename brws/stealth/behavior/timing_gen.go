package behavior

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

// ChromeTiming generates coherent chrome.csi() and chrome.loadTimes() data
// that passes cross-validation checks.
type ChromeTiming struct {
	CSI       CSIData       `json:"chrome_csi"`
	LoadTimes LoadTimesData `json:"chrome_loadTimes"`
}

// CSIData represents data from chrome.csi().
type CSIData struct {
	StartE  float64 `json:"startE"`  // Navigation start epoch ms
	OnLoadT float64 `json:"onLoadT"` // Milliseconds from navigation start to onload
	PageT   float64 `json:"pageT"`   // Current page time (ms since startE)
	Tran    int     `json:"tran"`    // Navigation type (0=typed, 1=link, 2=back/forward)
}

// LoadTimesData represents data from chrome.loadTimes().
type LoadTimesData struct {
	RequestTime                   float64 `json:"requestTime"`                   // Epoch seconds (NOT ms)
	StartLoadTime                 float64 `json:"startLoadTime"`                 // Epoch seconds
	CommitLoadTime                float64 `json:"commitLoadTime"`                // Epoch seconds
	FinishDocumentLoadTime        float64 `json:"finishDocumentLoadTime"`        // Epoch seconds
	FinishLoadTime                float64 `json:"finishLoadTime"`                // Epoch seconds
	FirstPaintTime                float64 `json:"firstPaintTime"`                // Epoch seconds
	FirstPaintAfterLoadTime       float64 `json:"firstPaintAfterLoadTime"`       // 0 if paint before load
	NavigationType                string  `json:"navigationType"`                // "Other", "BackForward", "Reload"
	WasFetchedViaSpdy             bool    `json:"wasFetchedViaSpdy"`             // true for HTTP/2
	WasNpnNegotiated              bool    `json:"wasNpnNegotiated"`              // true for HTTP/2
	NpnNegotiatedProtocol         string  `json:"npnNegotiatedProtocol"`         // "h2"
	WasAlternateProtocolAvailable bool    `json:"wasAlternateProtocolAvailable"` // false typically
	ConnectionInfo                string  `json:"connectionInfo"`                // "h2" for HTTP/2
}

// PerformanceTimingData generates realistic Performance API entries.
type PerformanceTimingData struct {
	NavigationStart float64                `json:"navigationStart"`
	Entries         []PerformanceEntryData `json:"entries"`
}

// PerformanceEntryData represents a single performance entry.
type PerformanceEntryData struct {
	Name      string  `json:"name"`      // URL of the resource
	EntryType string  `json:"entryType"` // "navigation", "resource", "paint"
	StartTime float64 `json:"startTime"`
	Duration  float64 `json:"duration"`
	URL       string  `json:"url"` // Same as name for resources
}

// GenerateChromeTiming creates coherent timing data anchored to the current time.
// The key invariant is: csi.startE == loadTimes.requestTime * 1000 (within a few ms).
func GenerateChromeTiming(seed int64) *ChromeTiming {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	//nolint:gosec // G404: math/rand is intentional for non-cryptographic use
	rng := rand.New(rand.NewSource(seed))

	// Anchor to current time minus a small offset (simulate page loaded recently)
	now := float64(time.Now().UnixMilli())
	pageAge := 500.0 + rng.Float64()*4500.0 // Page loaded 500-5000ms ago

	// requestTime is epoch seconds with microsecond precision
	requestTimeMs := now - pageAge
	requestTime := requestTimeMs / 1000.0

	// startE MUST equal requestTime * 1000 within a few ms of jitter
	// Add tiny jitter (0-2ms) to look natural while staying well within 100ms threshold
	jitter := rng.Float64() * 2.0
	startE := requestTimeMs + jitter

	// startLoadTime = requestTime (same moment)
	startLoadTime := requestTime

	// TTFB: commitLoadTime = requestTime + 50-200ms
	ttfb := 0.05 + rng.Float64()*0.15 // 50-200ms in seconds
	commitLoadTime := requestTime + ttfb

	// Document load: commitLoadTime + 100-500ms
	docLoad := 0.1 + rng.Float64()*0.4
	finishDocumentLoadTime := commitLoadTime + docLoad

	// Full load: finishDocumentLoadTime + 50-300ms
	fullLoad := 0.05 + rng.Float64()*0.25
	finishLoadTime := finishDocumentLoadTime + fullLoad

	// First paint: commitLoadTime + 20-100ms
	paintOffset := 0.02 + rng.Float64()*0.08
	firstPaintTime := commitLoadTime + paintOffset

	// First paint after load: 0 if paint happened before load (common case)
	var firstPaintAfterLoadTime float64
	if firstPaintTime > finishLoadTime {
		firstPaintAfterLoadTime = firstPaintTime
	}

	// onLoadT: milliseconds from navigation start to onload
	onLoadT := (finishLoadTime - requestTime) * 1000.0

	// pageT: time since navigation start (should be ~pageAge)
	pageT := pageAge

	// Navigation type: mostly "Other" (typed/link), occasionally others
	navTypes := []string{"Other", "Other", "Other", "BackForward", "Reload"}
	navigationType := navTypes[rng.Intn(len(navTypes))]

	// CSI tran maps to navigation type
	tran := 0 // typed
	switch navigationType {
	case "BackForward":
		tran = 2
	case "Reload":
		tran = 1 // link click (closest mapping)
	}

	// HTTP/2 is standard for modern sites
	isH2 := rng.Float64() < 0.85 // 85% HTTP/2

	return &ChromeTiming{
		CSI: CSIData{
			StartE:  startE,
			OnLoadT: roundTo(onLoadT, 1),
			PageT:   roundTo(pageT, 1),
			Tran:    tran,
		},
		LoadTimes: LoadTimesData{
			RequestTime:                   roundTo(requestTime, 6),
			StartLoadTime:                 roundTo(startLoadTime, 6),
			CommitLoadTime:                roundTo(commitLoadTime, 6),
			FinishDocumentLoadTime:        roundTo(finishDocumentLoadTime, 6),
			FinishLoadTime:                roundTo(finishLoadTime, 6),
			FirstPaintTime:                roundTo(firstPaintTime, 6),
			FirstPaintAfterLoadTime:       firstPaintAfterLoadTime,
			NavigationType:                navigationType,
			WasFetchedViaSpdy:             isH2,
			WasNpnNegotiated:              isH2,
			NpnNegotiatedProtocol:         h2Protocol(isH2),
			WasAlternateProtocolAvailable: false,
			ConnectionInfo:                h2Protocol(isH2),
		},
	}
}

// GeneratePerformanceTiming creates realistic performance entries for a page load.
// Each entry has a valid URL, realistic timing values, and proper ordering.
func GeneratePerformanceTiming(pageURL string, seed int64) *PerformanceTimingData {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	//nolint:gosec // G404: math/rand is intentional for non-cryptographic use
	rng := rand.New(rand.NewSource(seed))

	if pageURL == "" {
		pageURL = "https://example.com/"
	}

	// Parse the base domain for subresource URLs
	baseDomain := extractDomain(pageURL)

	navigationStart := float64(time.Now().UnixMilli()) - (500.0 + rng.Float64()*4500.0)

	numEntries := 5 + rng.Intn(11)                           // 5-15 entries
	entries := make([]PerformanceEntryData, 0, numEntries+3) // +3 for nav + 2 paint entries

	// First entry: navigation
	navDuration := 200.0 + rng.Float64()*800.0 // 200-1000ms
	entries = append(entries, PerformanceEntryData{
		Name:      pageURL,
		EntryType: "navigation",
		StartTime: 0,
		Duration:  roundTo(navDuration, 1),
		URL:       pageURL,
	})

	// Paint entries
	firstPaintStart := 50.0 + rng.Float64()*150.0 // 50-200ms
	entries = append(entries, PerformanceEntryData{
		Name:      "first-paint",
		EntryType: "paint",
		StartTime: roundTo(firstPaintStart, 1),
		Duration:  0,
		URL:       "first-paint",
	})

	fcpStart := firstPaintStart + rng.Float64()*50.0 // FCP slightly after first-paint
	entries = append(entries, PerformanceEntryData{
		Name:      "first-contentful-paint",
		EntryType: "paint",
		StartTime: roundTo(fcpStart, 1),
		Duration:  0,
		URL:       "first-contentful-paint",
	})

	// Resource entries with realistic URLs
	resourceTemplates := []struct {
		pathFormat string
		extension  string
	}{
		{"/assets/css/main.%s.css", "css"},
		{"/assets/js/app.%s.js", "js"},
		{"/assets/js/vendor.%s.js", "js"},
		{"/assets/js/chunk-%s.js", "js"},
		{"/assets/css/styles.%s.css", "css"},
		{"/assets/images/logo.%s.png", "png"},
		{"/assets/images/hero.%s.webp", "webp"},
		{"/assets/fonts/inter-regular.%s.woff2", "woff2"},
		{"/assets/fonts/inter-bold.%s.woff2", "woff2"},
		{"/api/v1/config.%s.json", "json"},
		{"/assets/js/analytics.%s.js", "js"},
		{"/assets/js/runtime.%s.js", "js"},
		{"/assets/css/tailwind.%s.css", "css"},
		{"/assets/images/favicon.%s.ico", "ico"},
		{"/assets/js/polyfills.%s.js", "js"},
	}

	// Shuffle templates for variety
	rng.Shuffle(len(resourceTemplates), func(i, j int) {
		resourceTemplates[i], resourceTemplates[j] = resourceTemplates[j], resourceTemplates[i]
	})

	currentStart := fcpStart + 10.0

	for i := 0; i < numEntries && i < len(resourceTemplates); i++ {
		tmpl := resourceTemplates[i]
		hash := fmt.Sprintf("%08x", rng.Int31())
		path := fmt.Sprintf(tmpl.pathFormat, hash)
		resourceURL := fmt.Sprintf("https://%s%s", baseDomain, path)

		// Resources start at increasing times with gaps
		gap := 5.0 + rng.Float64()*50.0 // 5-55ms between resource starts
		currentStart += gap

		// Duration depends on resource type
		var duration float64
		switch tmpl.extension {
		case "js":
			duration = 20.0 + rng.Float64()*200.0 // 20-220ms
		case "css":
			duration = 10.0 + rng.Float64()*100.0 // 10-110ms
		case "png", "webp", "ico":
			duration = 30.0 + rng.Float64()*300.0 // 30-330ms
		case "woff2":
			duration = 15.0 + rng.Float64()*80.0 // 15-95ms
		default:
			duration = 10.0 + rng.Float64()*150.0 // 10-160ms
		}

		entries = append(entries, PerformanceEntryData{
			Name:      resourceURL,
			EntryType: "resource",
			StartTime: roundTo(currentStart, 1),
			Duration:  roundTo(duration, 1),
			URL:       resourceURL,
		})
	}

	return &PerformanceTimingData{
		NavigationStart: navigationStart,
		Entries:         entries,
	}
}

// roundTo rounds a float to n decimal places.
func roundTo(val float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int(val*pow+0.5)) / pow
}

// h2Protocol returns "h2" if HTTP/2, empty string otherwise.
func h2Protocol(isH2 bool) string {
	if isH2 {
		return "h2"
	}
	return ""
}

// extractDomain extracts the domain from a URL.
func extractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		// Fallback: try to extract from string
		s := rawURL
		if idx := strings.Index(s, "://"); idx >= 0 {
			s = s[idx+3:]
		}
		if idx := strings.IndexByte(s, '/'); idx >= 0 {
			s = s[:idx]
		}
		if s == "" {
			return "example.com"
		}
		return s
	}
	return parsed.Host
}
