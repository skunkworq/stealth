// Package observability provides metrics collection, health checks, and tracing.
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HealthChecker interface for health check endpoints
type HealthChecker interface {
	Health(ctx context.Context) HealthStatus
}

// HealthStatus represents the health of a component
type HealthStatus struct {
	Status    string           `json:"status"` // "healthy", "degraded", "unhealthy"
	Checks    map[string]Check `json:"checks,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// Check represents a single health check
type Check struct {
	Status  string `json:"status"` // "pass", "fail", "warn"
	Message string `json:"message,omitempty"`
}

// HTTPHandler provides HTTP endpoints for observability
type HTTPHandler struct {
	collector MetricsCollector
	health    HealthChecker
	server    *http.Server
	mu        sync.RWMutex
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(collector MetricsCollector, health HealthChecker) *HTTPHandler {
	return &HTTPHandler{
		collector: collector,
		health:    health,
	}
}

// Router returns an http.Handler with all routes
func (h *HTTPHandler) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", h.handleMetrics)
	mux.HandleFunc("/metrics/prometheus", h.handlePrometheus)
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/health/live", h.handleLive)
	mux.HandleFunc("/health/ready", h.handleReady)

	return mux
}

// handleMetrics returns metrics in JSON format
func (h *HTTPHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	metrics := map[string]interface{}{
		"counters":   h.collector.GetAllCounters(),
		"gauges":     h.collector.GetAllGauges(),
		"histograms": h.collector.GetAllHistograms(),
		"timestamp":  time.Now().UTC(),
	}

	jsonBytes, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal metrics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(jsonBytes)
}

// GetAllHistograms returns all histogram stats
func (c *InMemoryCollector) GetAllHistograms() map[string]*HistogramStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*HistogramStats, len(c.histograms))
	for k, v := range c.histograms {
		result[k] = v.Stats()
	}
	return result
}

// handlePrometheus returns metrics in Prometheus format
func (h *HTTPHandler) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	var sb strings.Builder

	// Counters
	counters := h.collector.GetAllCounters()
	for name, value := range counters {
		sb.WriteString(fmt.Sprintf("# TYPE %s counter\n", sanitizeMetricName(name)))
		sb.WriteString(fmt.Sprintf("%s %d\n", sanitizeMetricName(name), value))
	}

	// Gauges
	gauges := h.collector.GetAllGauges()
	for name, value := range gauges {
		sb.WriteString(fmt.Sprintf("# TYPE %s gauge\n", sanitizeMetricName(name)))
		sb.WriteString(fmt.Sprintf("%s %f\n", sanitizeMetricName(name), value))
	}

	// Histograms
	histograms := h.collector.GetAllHistograms()
	for name, stats := range histograms {
		sb.WriteString(fmt.Sprintf("# TYPE %s histogram\n", sanitizeMetricName(name)))
		sb.WriteString(fmt.Sprintf("%s_count %d\n", sanitizeMetricName(name), stats.Count))
		sb.WriteString(fmt.Sprintf("%s_sum %f\n", sanitizeMetricName(name), stats.Sum))
		if stats.Count > 0 {
			sb.WriteString(fmt.Sprintf("%s_min %f\n", sanitizeMetricName(name), stats.Min))
			sb.WriteString(fmt.Sprintf("%s_max %f\n", sanitizeMetricName(name), stats.Max))
		}
	}

	w.Write([]byte(sb.String()))
}

// sanitizeMetricName makes a metric name Prometheus-compatible
func sanitizeMetricName(name string) string {
	// Replace colons and special chars with underscores
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, ",", "_")
	name = strings.ReplaceAll(name, "=", "_")
	return name
}

// handleHealth returns overall health status
func (h *HTTPHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := h.health.Health(ctx)
	jsonBytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal health: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(jsonBytes)
}

// handleLive returns liveness probe (always returns ok if service is running)
func (h *HTTPHandler) handleLive(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleReady returns readiness probe
func (h *HTTPHandler) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := h.health.Health(ctx)

	if status.Status == "healthy" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		jsonBytes, _ := json.Marshal(status)
		w.Write(jsonBytes)
	}
}

// Start starts the HTTP server
func (h *HTTPHandler) Start(addr string) error {
	h.mu.Lock()
	if h.server != nil {
		h.mu.Unlock()
		return fmt.Errorf("server already started")
	}

	h.server = &http.Server{
		Addr:         addr,
		Handler:      h.Router(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	h.mu.Unlock()

	return h.server.ListenAndServe()
}

// Stop gracefully stops the HTTP server
func (h *HTTPHandler) Stop(ctx context.Context) error {
	h.mu.RLock()
	server := h.server
	h.mu.RUnlock()

	if server == nil {
		return nil
	}

	return server.Shutdown(ctx)
}
