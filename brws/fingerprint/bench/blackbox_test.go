package benchmark

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/core/types"
)

func TestFilterBlackboxTools(t *testing.T) {
	tools := DefaultBlackboxToolSpecs("python3")
	filtered := FilterBlackboxTools(tools, []string{"nodriver", "scrapy_default"})

	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered tools, got %d", len(filtered))
	}
	if filtered[0].Name != "nodriver" || filtered[1].Name != "scrapy_default" {
		t.Fatalf("unexpected tool order: %s, %s", filtered[0].Name, filtered[1].Name)
	}
}

func TestRunBlackboxBenchmarkWithCurl(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/capture/json":
			fp := types.CompleteFingerprint{
				ID: "cap-1",
				HTTP: &types.HTTPFingerprint{
					Method:    r.Method,
					Path:      r.URL.Path,
					Protocol:  r.Proto,
					UserAgent: r.Header.Get("User-Agent"),
					Headers: []types.HeaderInfo{
						{Name: "User-Agent", Value: r.Header.Get("User-Agent"), Position: 1},
						{Name: "Accept", Value: r.Header.Get("Accept"), Position: 2},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fp)
		case "/api/stealth-test":
			resp := map[string]any{
				"request_id": "req-1",
				"is_bot":     strings.Contains(strings.ToLower(r.Header.Get("User-Agent")), "curl"),
				"is_stealth": false,
				"score":      0.91,
				"confidence": 0.97,
				"vectors": []map[string]any{
					{"category": "http", "score": 0.91},
				},
				"indicators": []map[string]any{
					{"name": "suspicious_ua_curl"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tool := BlackboxToolSpec{
		Name:        "curl_probe",
		Description: "curl-based blackbox probe for e2e testing",
		Phases: []BlackboxPhaseSpec{
			{
				Name:    "capture",
				Kind:    PhaseCapture,
				URLPath: "/capture/json",
				Command: []string{"curl", "-sS", "-H", "User-Agent: curl/8.5.0", urlPlaceholder},
			},
			{
				Name:    "shield",
				Kind:    PhaseShield,
				URLPath: "/api/stealth-test",
				Command: []string{"curl", "-sS", "-H", "User-Agent: curl/8.5.0", urlPlaceholder},
			},
		},
	}

	report, err := RunBlackboxBenchmark(context.Background(), &BlackboxConfig{
		BaseURL:      server.URL,
		Tools:        []BlackboxToolSpec{tool},
		AllowMissing: false,
	})
	if err != nil {
		t.Fatalf("RunBlackboxBenchmark failed: %v", err)
	}

	if report.ExecutedCount != 1 {
		t.Fatalf("expected 1 executed tool, got %d", report.ExecutedCount)
	}

	result := report.Results[0]
	if result.Capture == nil || result.Capture.Summary == nil {
		t.Fatal("expected capture result summary")
	}
	if got := result.Capture.Summary.UserAgent; !strings.Contains(got, "curl/8.5.0") {
		t.Fatalf("unexpected capture user agent: %q", got)
	}
	if result.Shield == nil || !result.Shield.Executed {
		t.Fatal("expected shield phase to execute")
	}
	if !result.Shield.IsBot {
		t.Fatal("expected curl shield result to be bot")
	}
	if result.Shield.Confidence < 0.90 {
		t.Fatalf("expected shield confidence >= 0.90, got %.3f", result.Shield.Confidence)
	}
	if _, ok := result.Shield.VectorScores["http"]; !ok {
		t.Fatal("expected http vector score")
	}
}

func TestParseCompleteFingerprintIgnoresTrailingLogs(t *testing.T) {
	stdout := `{"id":"cap-1","http":{"protocol":"HTTP/1.1","user_agent":"HeadlessChrome","headers":[]}}
successfully removed temp profile /tmp/foo`

	fp, err := parseCompleteFingerprint(stdout)
	if err != nil {
		t.Fatalf("parseCompleteFingerprint failed: %v", err)
	}
	if fp.ID != "cap-1" {
		t.Fatalf("expected fingerprint id cap-1, got %q", fp.ID)
	}
}

func TestParseShieldResponseFromEnvelope(t *testing.T) {
	body := `{"request_id":"req-1","is_bot":true,"is_stealth":false,"score":0.91,"confidence":0.97,"vectors":[{"category":"http","score":0.91}],"indicators":[{"name":"too_few_headers"}]}`
	stdout := `{"success":true,"status_code":403,"body":"` + strings.ReplaceAll(body, `"`, `\"`) + `"}`

	result, err := parseShieldResponse(stdout)
	if err != nil {
		t.Fatalf("parseShieldResponse failed: %v", err)
	}
	if !result.IsBot {
		t.Fatal("expected shield result to be bot")
	}
	if result.RequestID != "req-1" {
		t.Fatalf("expected request id req-1, got %q", result.RequestID)
	}
	if got := result.VectorScores["http"]; got != 0.91 {
		t.Fatalf("expected http vector score 0.91, got %.2f", got)
	}
}

func TestParseAvailabilityJSONIgnoresNoise(t *testing.T) {
	stdout := "probe log line\n{\"available\":false,\"reason\":\"missing playwright\"}\n"

	payload := parseAvailabilityJSON(stdout)
	if payload == nil {
		t.Fatal("expected availability payload")
	}
	if payload.Available {
		t.Fatal("expected unavailable payload")
	}
	if payload.Reason != "missing playwright" {
		t.Fatalf("unexpected reason: %q", payload.Reason)
	}
}

func TestBuildPhaseEnvAddsInsecureTLS(t *testing.T) {
	env := buildPhaseEnv([]string{"A=B"}, true)
	if len(env) != 2 {
		t.Fatalf("expected 2 env entries, got %d", len(env))
	}
	if env[0] != "A=B" {
		t.Fatalf("unexpected first env entry: %q", env[0])
	}
	if env[1] != "BLACKBOX_INSECURE_TLS=1" {
		t.Fatalf("unexpected insecure tls env entry: %q", env[1])
	}
}

func TestExecBlackboxRunnerPreservesProcessEnvironment(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not installed")
	}

	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set in test environment")
	}

	runner := ExecBlackboxRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := runner.Run(ctx, []string{"sh", "-c", "printf %s \"$HOME\""}, []string{"BLACKBOX_INSECURE_TLS=1"}, "")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if got := strings.TrimSpace(result.Stdout); got != home {
		t.Fatalf("expected HOME %q, got %q", home, got)
	}
}
