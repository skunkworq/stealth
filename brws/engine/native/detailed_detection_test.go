package native

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/engine/testserver"
)

func TestDetailedDetectionTrace(t *testing.T) {
	server := testserver.NewWithConfig(&testserver.ServerConfig{
		DetectHTTPFingerprint: true,
	})
	defer server.Close()

	// Test different scenarios
	scenarios := []struct {
		name string
		opts engine.Options
	}{
		{
			name: "Standard Go Client",
			opts: engine.Options{},
		},
		{
			name: "Chrome Stealth Profile",
			opts: engine.Options{
				Stealth:     true,
				ProfileName: "chrome-120-macos",
			},
		},
		{
			name: "Firefox Stealth Profile",
			opts: engine.Options{
				Stealth:     true,
				ProfileName: "firefox-120-macos",
			},
		},
		{
			name: "Safari Stealth Profile",
			opts: engine.Options{
				Stealth:     true,
				ProfileName: "safari-16-macos",
			},
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := New(tc.opts)
			if err != nil {
				t.Fatalf("Failed to create engine: %v", err)
			}
			defer eng.Close()

			req := &engine.Request{
				Method:  "GET",
				URL:     server.URL + "/headers",
				Timeout: 30,
			}

			eng.Do(context.Background(), req)

			lastReq := server.GetLastRequest()
			if lastReq == nil {
				t.Fatal("No request captured")
			}

			// Create http.Request for detection
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}

			// Use detailed trace
			trace := adversarial.NewDetailedTrace(mockReq, nil)
			report := trace.GenerateReport()

			fmt.Printf("\n=== %s ===\n", tc.name)
			fmt.Printf("%s\n", report)

			if trace.IsSuspicious {
				fmt.Printf("VERDICT: SUSPICIOUS (Score: %.2f)\n", trace.SuspicionScore)
			} else {
				fmt.Printf("VERDICT: CLEAN (Score: %.2f)\n", trace.SuspicionScore)
			}

			server.ClearRequests()
		})
	}
}
