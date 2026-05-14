// Package chromestealth provides StealthPlus anti-detection enhancements.
// These features close the gap with nodriver-style stealth without adding
// tab-management or visual-CAPTCHA capabilities.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter
package chromestealth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// --- StealthPlus: Permission Grants ---

// allPermissions is the full list of permissions nodriver proactively grants.
var allPermissions = []browser.PermissionType{
	browser.PermissionTypeAudioCapture,
	browser.PermissionTypeBackgroundSync,
	browser.PermissionTypeClipboardReadWrite,
	browser.PermissionTypeClipboardSanitizedWrite,
	browser.PermissionTypeDisplayCapture,
	browser.PermissionTypeDurableStorage,
	browser.PermissionTypeGeolocation,
	browser.PermissionTypeIdleDetection,
	browser.PermissionTypeLocalFonts,
	browser.PermissionTypeMidi,
	browser.PermissionTypeMidiSysex,
	browser.PermissionTypeNotifications,
	browser.PermissionTypePaymentHandler,
	browser.PermissionTypePeriodicBackgroundSync,
	browser.PermissionTypeProtectedMediaIdentifier,
	browser.PermissionTypeSensors,
	browser.PermissionTypeStorageAccess,
	browser.PermissionTypeVideoCapture,
	browser.PermissionTypeWakeLockScreen,
	browser.PermissionTypeWindowManagement,
}

// GrantAllPermissions uses CDP Browser.grantPermissions to remove permission
// prompts that can signal automation.  This is the nodriver equivalent of
// browser.grant_all_permissions().
func (s *StealthEngine) GrantAllPermissions(ctx context.Context) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	for _, perm := range allPermissions {
		if err := browser.GrantPermissions([]browser.PermissionType{perm}).
			WithOrigin("*").Do(tabCtx); err != nil {
			// Some permissions may not be supported on all Chrome versions;
			// log and continue rather than failing entirely.
			s.logger.Debug("failed to grant permission", "permission", perm, "error", err)
		}
	}

	s.logger.Info("StealthPlus: all permissions granted")
	return nil
}

// --- StealthPlus: user_gesture evaluation ---

// EvaluateWithGesture executes JavaScript via CDP with userGesture=true.
// This unlocks APIs gated behind user interaction (autoplay, popups, etc.)
// and is the nodriver equivalent of setting user_gesture=True on evaluations.
// The caller must provide a valid chromedp context (e.g. from NewContext).
func (s *StealthEngine) EvaluateWithGesture(ctx context.Context, expression string) (interface{}, error) {
	if !s.config.StealthPlus {
		return nil, fmt.Errorf("StealthPlus is not enabled")
	}

	var result interface{}
	action := chromedp.ActionFunc(func(c context.Context) error {
		// Runtime.evaluate with userGesture=true
		evalParams := runtime.Evaluate(expression).
			WithUserGesture(true).
			WithAwaitPromise(true).
			WithReturnByValue(true)

		remoteObj, exp, err := evalParams.Do(c)
		if err != nil {
			return err
		}
		if exp != nil {
			return fmt.Errorf("js exception: %s", exp.Text)
		}
		if remoteObj != nil && remoteObj.Value != nil {
			result = remoteObj.Value
		}
		return nil
	})

	if err := chromedp.Run(ctx, action); err != nil {
		return nil, fmt.Errorf("evaluate with gesture: %w", err)
	}
	return result, nil
}

// --- StealthPlus: Raw CDP Escape Hatch ---

// SendCDP executes an arbitrary chromedp Action against a fresh tab context.
// This provides the nodriver-style raw CDP access (equivalent to
// tab.send(cdp.command(...))).
func (s *StealthEngine) SendCDP(ctx context.Context, actions ...chromedp.Action) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	return chromedp.Run(tabCtx, actions...)
}

// --- StealthPlus: Network Interception (Fetch Domain) ---

// EnableFetchIntercept enables the CDP Fetch domain so requests can be
// paused, modified, or blocked.  This is the foundation for request/response
// interception that nodriver exposes via EventRequestPaused handlers.
func (s *StealthEngine) EnableFetchIntercept(ctx context.Context, patterns []*fetch.RequestPattern) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	return chromedp.Run(tabCtx, fetch.Enable().WithPatterns(patterns))
}

// FetchHandler is the callback signature for paused fetch requests.
type FetchHandler func(ctx context.Context, req *fetch.EventRequestPaused) error

// ListenFetchPaused registers a handler for fetch request-paused events.
// The handler can call fetch.FulfillRequest, fetch.ContinueRequest, or
// fetch.FailRequest to control the paused request.
func (s *StealthEngine) ListenFetchPaused(ctx context.Context, handler FetchHandler) {
	if !s.config.StealthPlus {
		s.logger.Warn("StealthPlus is not enabled; ListenFetchPaused is a no-op")
		return
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if paused, ok := ev.(*fetch.EventRequestPaused); ok {
			if err := handler(tabCtx, paused); err != nil {
				s.logger.Error("fetch handler error", "error", err)
			}
		}
	})
}

// --- StealthPlus: CDP Object Handle Resolver ---

// ResolveRemoteObject returns the serialized Value from a runtime.RemoteObject
// if available.  For complex objects without an inline value it returns nil.
// This is a lightweight equivalent to nodriver's deep JS object dumps.
func ResolveRemoteObject(_ context.Context, obj *runtime.RemoteObject) (interface{}, error) {
	if obj == nil {
		return nil, nil
	}
	if obj.Value != nil {
		return obj.Value, nil
	}
	return nil, nil
}

// ============================================================================
// StealthPlus: Navigation Profiles & Referrer Seeding
// ============================================================================

// HistoryEntry represents a single fake history entry for same-origin seeding.
type HistoryEntry struct {
	URL   string      `json:"url"`
	Title string      `json:"title"`
	State interface{} `json:"state,omitempty"`
}

// NavigationProfile bundles referrer, history, and storage seeding for a
// realistic navigation context.
type NavigationProfile struct {
	Name           string
	Referrer       string
	HistoryEntries []HistoryEntry
	SessionStorage map[string]string
}

// SeedHistory injects fake same-origin history entries via history.pushState
// so that History.back() / History.forward() behave realistically.
// WARNING: pushState enforces Same-Origin Policy — all entries must share
// the current document's origin.
func (s *StealthEngine) SeedHistory(ctx context.Context, entries []HistoryEntry) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}
	if len(entries) == 0 {
		return nil
	}

	type jsEntry struct {
		URL   string      `json:"url"`
		Title string      `json:"title"`
		State interface{} `json:"state"`
	}
	hist := make([]jsEntry, len(entries))
	for i, e := range entries {
		hist[i] = jsEntry{URL: e.URL, Title: e.Title, State: e.State}
	}
	histJSON, _ := json.Marshal(hist)

	script := fmt.Sprintf(`
(function() {
	const entries = %s;
	for (const entry of entries) {
		history.pushState(entry.state || {}, entry.title || document.title, entry.url);
	}
	// Rewind to the start of the seeded stack so forward/back navigation works
	history.go(-entries.length);
})();`, string(histJSON))

	_, err := s.EvaluateWithGesture(ctx, script)
	return err
}

// SeedSessionStorage injects keys into sessionStorage to imply prior browsing.
func (s *StealthEngine) SeedSessionStorage(ctx context.Context, data map[string]string) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}
	if len(data) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString(`(function() {`)
	for k, v := range data {
		sb.WriteString(fmt.Sprintf(`sessionStorage.setItem(%q, %q);`, k, v))
	}
	sb.WriteString(`})();`)

	_, err := s.EvaluateWithGesture(ctx, sb.String())
	return err
}

// NavigateWithReferrer performs a navigation with an arbitrary referrer.
// This sets both the HTTP Referer header AND document.referrer, and is the
// only cross-origin-safe way to inject a referrer (history.pushState fails
// across origins).
func (s *StealthEngine) NavigateWithReferrer(ctx context.Context, url, referrer string) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	return chromedp.Run(tabCtx, chromedp.ActionFunc(func(c context.Context) error {
		_, _, _, _, err := page.Navigate(url).
			WithReferrer(referrer).
			WithFrameID(cdp.FrameID("")).
			Do(c)
		return err
	}))
}

// NavigateWithProfile navigates to target using a full NavigationProfile:
// referrer injection, same-origin history seeding, and sessionStorage seeding.
// All operations share a single tab context so history and storage are
// applied to the same page.
func (s *StealthEngine) NavigateWithProfile(
	ctx context.Context,
	target string,
	profile NavigationProfile,
) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	s.logger.Info("StealthPlus: navigating with profile",
		"profile", profile.Name,
		"target", target,
		"referrer", profile.Referrer,
	)

	// Use a single tab context for the entire profile sequence
	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	// 1. Navigate with referrer
	if err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(c context.Context) error {
		_, _, _, _, err := page.Navigate(target).
			WithReferrer(profile.Referrer).
			WithFrameID(cdp.FrameID("")).
			Do(c)
		return err
	})); err != nil {
		return fmt.Errorf("navigate with referrer: %w", err)
	}

	// 2. Seed same-origin history if provided
	if len(profile.HistoryEntries) > 0 {
		if err := seedHistoryInContext(tabCtx, profile.HistoryEntries); err != nil {
			return fmt.Errorf("seed history: %w", err)
		}
	}

	// 3. Seed sessionStorage
	if len(profile.SessionStorage) > 0 {
		if err := seedSessionStorageInContext(tabCtx, profile.SessionStorage); err != nil {
			return fmt.Errorf("seed sessionStorage: %w", err)
		}
	}

	// 4. If a scrollDepth was seeded, restore it
	if depthStr, ok := profile.SessionStorage["scrollDepth"]; ok {
		script := fmt.Sprintf(`window.scrollTo(0, document.body.scrollHeight * %s)`, depthStr)
		_, _ = evaluateWithGestureInContext(tabCtx, script)
	}

	return nil
}

// seedHistoryInContext injects history entries into an existing chromedp context.
func seedHistoryInContext(ctx context.Context, entries []HistoryEntry) error {
	type jsEntry struct {
		URL   string      `json:"url"`
		Title string      `json:"title"`
		State interface{} `json:"state"`
	}
	hist := make([]jsEntry, len(entries))
	for i, e := range entries {
		hist[i] = jsEntry{URL: e.URL, Title: e.Title, State: e.State}
	}
	histJSON, _ := json.Marshal(hist)

	script := fmt.Sprintf(`
(function() {
	const entries = %s;
	for (const entry of entries) {
		history.pushState(entry.state || {}, entry.title || document.title, entry.url);
	}
	history.go(-entries.length);
})();`, string(histJSON))

	return chromedp.Run(ctx, chromedp.Evaluate(script, nil))
}

// seedSessionStorageInContext injects sessionStorage into an existing chromedp context.
func seedSessionStorageInContext(ctx context.Context, data map[string]string) error {
	var sb strings.Builder
	sb.WriteString(`(function() {`)
	for k, v := range data {
		sb.WriteString(fmt.Sprintf(`sessionStorage.setItem(%q, %q);`, k, v))
	}
	sb.WriteString(`})();`)
	return chromedp.Run(ctx, chromedp.Evaluate(sb.String(), nil))
}

// evaluateWithGestureInContext evaluates JS with userGesture=true in an existing context.
func evaluateWithGestureInContext(ctx context.Context, expression string) (interface{}, error) {
	var result interface{}
	action := chromedp.ActionFunc(func(c context.Context) error {
		evalParams := runtime.Evaluate(expression).
			WithUserGesture(true).
			WithAwaitPromise(true).
			WithReturnByValue(true)
		remoteObj, exp, err := evalParams.Do(c)
		if err != nil {
			return err
		}
		if exp != nil {
			return fmt.Errorf("js exception: %s", exp.Text)
		}
		if remoteObj != nil && remoteObj.Value != nil {
			result = remoteObj.Value
		}
		return nil
	})
	if err := chromedp.Run(ctx, action); err != nil {
		return nil, err
	}
	return result, nil
}

// ============================================================================
// Pre-built Search Engine Profiles
// ============================================================================

// googleSearchQueries returns a pool of realistic Google search query paths.
func googleSearchQueries(targetDomain string) []string {
	return []string{
		fmt.Sprintf("https://www.google.com/search?q=%s&source=hp&ei=abc", targetDomain),
		fmt.Sprintf("https://www.google.com/search?q=%s+reviews&oq=%s+reviews", targetDomain, targetDomain),
		fmt.Sprintf("https://www.google.com/search?q=site%%3A%s", targetDomain),
		fmt.Sprintf("https://www.google.com/search?q=%s+login&source=lmns", targetDomain),
	}
}

// bingSearchQueries returns a pool of realistic Bing search query paths.
func bingSearchQueries(targetDomain string) []string {
	return []string{
		fmt.Sprintf("https://www.bing.com/search?q=%s&form=QBLH", targetDomain),
		fmt.Sprintf("https://www.bing.com/search?q=%s+official&qs=n", targetDomain),
		fmt.Sprintf("https://www.bing.com/search?q=site%%3A%s&form=QBRE", targetDomain),
	}
}

// duckDuckGoSearchQueries returns a pool of realistic DuckDuckGo search query paths.
func duckDuckGoSearchQueries(targetDomain string) []string {
	return []string{
		fmt.Sprintf("https://duckduckgo.com/?q=%s&ia=web", targetDomain),
		fmt.Sprintf("https://duckduckgo.com/?q=%s+reviews&ia=web", targetDomain),
		fmt.Sprintf("https://duckduckgo.com/?q=site%%3A%s&ia=web", targetDomain),
	}
}

// randomReferrer picks a random referrer from a slice.
func randomReferrer(options []string) string {
	if len(options) == 0 {
		return ""
	}
	return options[rand.Intn(len(options))]
}

// randomPastTime returns an RFC3339 timestamp between 30 min and 4 hours ago.
func randomPastTime() string {
	minAgo := 30
	maxAgo := 240
	minutes := minAgo + rand.Intn(maxAgo-minAgo)
	return time.Now().Add(-time.Duration(minutes) * time.Minute).Format(time.RFC3339)
}

// GoogleSearchProfile returns a NavigationProfile that simulates arriving from
// a Google organic search result.  The referrer is cross-origin, so history
// seeding is skipped (Google cannot be pushState'd from the target origin).
func GoogleSearchProfile(targetDomain string) NavigationProfile {
	q := randomReferrer(googleSearchQueries(targetDomain))
	return NavigationProfile{
		Name:     "google-search",
		Referrer: q,
		SessionStorage: map[string]string{
			"__brwslab_origin":    "google",
			"__brwslab_lastVisit": randomPastTime(),
			"__brwslab_query":     strings.TrimPrefix(q, "https://www.google.com/search?q="),
		},
	}
}

// BingSearchProfile returns a NavigationProfile that simulates arriving from
// a Bing organic search result.
func BingSearchProfile(targetDomain string) NavigationProfile {
	q := randomReferrer(bingSearchQueries(targetDomain))
	return NavigationProfile{
		Name:     "bing-search",
		Referrer: q,
		SessionStorage: map[string]string{
			"__brwslab_origin":    "bing",
			"__brwslab_lastVisit": randomPastTime(),
			"__brwslab_query":     strings.TrimPrefix(q, "https://www.bing.com/search?q="),
		},
	}
}

// DuckDuckGoSearchProfile returns a NavigationProfile that simulates arriving
// from a DuckDuckGo organic search result.
func DuckDuckGoSearchProfile(targetDomain string) NavigationProfile {
	q := randomReferrer(duckDuckGoSearchQueries(targetDomain))
	return NavigationProfile{
		Name:     "duckduckgo-search",
		Referrer: q,
		SessionStorage: map[string]string{
			"__brwslab_origin":    "duckduckgo",
			"__brwslab_lastVisit": randomPastTime(),
			"__brwslab_query":     strings.TrimPrefix(q, "https://duckduckgo.com/?q="),
		},
	}
}

// RandomSearchProfile picks one of the three search engine profiles at random.
func RandomSearchProfile(targetDomain string) NavigationProfile {
	profiles := []func(string) NavigationProfile{
		GoogleSearchProfile,
		BingSearchProfile,
		DuckDuckGoSearchProfile,
	}
	return profiles[rand.Intn(len(profiles))](targetDomain)
}
