// Package stealth provides a high-level API for stealth browser automation.
//
// # Usage
//
// Basic usage:
//
//	client, err := stealth.New()
//	if err != nil { return err }
//	defer client.Close()
//
//	resp, err := client.Navigate(context.Background(), "https://example.com")
//	if err != nil { return err }
//	fmt.Println(string(resp.Body))
//
// # Configuration
//
// Use functional options to configure the client:
//
//	client, err := stealth.New(
//		stealth.WithHeadless(false),
//		stealth.WithProxy("http://proxy:8080"),
//		stealth.WithChallengeSolver("capsolver", "YOUR-API-KEY"),
//		stealth.WithLogging("debug", false),
//	)
//
// # Instrumentation
//
// The client provides access to logging, tracing, and hooks:
//
//	client.Hooks().Register("my-hook", func(ctx context.Context) error {
//	    // custom logic
//	    return nil
//	})
//
//	for _, span := range client.Tracer().GetAllSpans() {
//	    fmt.Println(span.Name, span.Duration())
//	}
//
// See the examples directory for more usage patterns.
package stealth
