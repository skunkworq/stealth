// Package stealth is the main entry point for the brws library.
//
// It wraps a browser engine (or waterfall of engines) with anti-bot layers:
// challenge detection and solving, behavioral simulation, session health
// tracking, proxy tier escalation, and TLS/HTTP fingerprint spoofing.
//
// # Architecture
//
// Client orchestrates the following sub-packages:
//
//   - stealth/challenge     — detects and defeats Cloudflare, DataDome, reCAPTCHA, Turnstile
//   - stealth/challenge/fsm — finite state machine for evasion escalation
//   - stealth/captcha       — CAPTCHA detection and external solver integration
//   - stealth/behavior      — human mouse/keystroke/scroll simulation
//   - stealth/profile       — browser profile and UA management
//   - stealth/profile/session — session health scoring and block detection
//   - browser/engine/browser/chromium        — JS/CDP stealth script injection at page load
//
// # Usage
//
//	client, err := stealth.New(
//	    stealth.WithHeadless(false),
//	    stealth.WithProxy("http://proxy:8080"),
//	    stealth.WithChallengeSolver("capsolver", "YOUR-API-KEY"),
//	    stealth.WithEscalation(stealth.DefaultEscalationConfig()),
//	)
//	if err != nil { return err }
//	defer client.Close()
//
//	resp, err := client.Navigate(ctx, "https://example.com")
//
// # Escalation
//
// When a 401, 403, or 429 response is received, Client.escalate() fires:
// it records the ban signal on the session, promotes the proxy tier via
// network/proxy/connpool, and promotes the waterfall engine tier. If the
// session health score crosses the block threshold, the session is retired
// and no retry is attempted.
//
// Configure escalation behaviour with WithEscalation and WithTieredProxies.
// Configure the engine fallback sequence with WithWaterfall.
//
// # Instrumentation
//
// Logging, tracing, and hooks are provided by core/instrumentation:
//
//	client.Logger().Info("navigating", "url", url)
//
//	client.Hooks().Register("pre-navigate", func(ctx context.Context) error {
//	    // custom pre-navigation logic
//	    return nil
//	})
//
//	for _, span := range client.Tracer().GetAllSpans() {
//	    fmt.Println(span.Name, span.Duration())
//	}
package stealth
