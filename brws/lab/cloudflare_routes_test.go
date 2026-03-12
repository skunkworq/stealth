package lab

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnhancedServerMountsCloudflareCallbackRoutes(t *testing.T) {
	server := NewEnhancedServer(&ServerConfig{EnableProxy: false}, nil)
	mux := http.NewServeMux()
	server.setupRoutes(mux)

	sessionID := "lab-turnstile-route"
	widgetReq := httptest.NewRequest(http.MethodGet, "/api/cloudflare/turnstile/widget?session_id="+sessionID+"&site_key=1x00000000000000000000AA", nil)
	widgetRes := httptest.NewRecorder()
	mux.ServeHTTP(widgetRes, widgetReq)
	if widgetRes.Code != http.StatusForbidden {
		t.Fatalf("expected widget route to return 403 page, got %d", widgetRes.Code)
	}

	session, ok := server.stealthServer.CloudflareChallenger.GetSession(sessionID)
	if !ok {
		t.Fatal("expected turnstile session to be created")
	}

	callbackBody, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"callback":   "before-interactive",
	})
	callbackReq := httptest.NewRequest(
		http.MethodPost,
		"/cdn-cgi/challenge-platform/h/g/cv/result/"+session.RayID,
		bytes.NewReader(callbackBody),
	)
	callbackReq.Header.Set("Content-Type", "application/json")
	callbackRes := httptest.NewRecorder()
	mux.ServeHTTP(callbackRes, callbackReq)

	if callbackRes.Code != http.StatusOK {
		t.Fatalf("expected callback route to return 200, got %d", callbackRes.Code)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/cloudflare/status?session_id="+sessionID, nil)
	statusRes := httptest.NewRecorder()
	mux.ServeHTTP(statusRes, statusReq)
	if statusRes.Code != http.StatusOK {
		t.Fatalf("expected status route to return 200, got %d", statusRes.Code)
	}

	var status struct {
		WidgetTelemetry struct {
			CallbackState struct {
				BeforeInteractive bool `json:"before_interactive"`
			} `json:"callback_state"`
		} `json:"widget_telemetry"`
	}
	if err := json.NewDecoder(statusRes.Body).Decode(&status); err != nil {
		t.Fatalf("decode status response: %v", err)
	}

	if !status.WidgetTelemetry.CallbackState.BeforeInteractive {
		t.Fatal("expected callback route to update widget telemetry")
	}
}
