package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type MetricsServer struct {
	pipeline *Pipeline
	addr     string
	server   *http.Server
}

func NewMetricsServer(pipeline *Pipeline, addr string) *MetricsServer {
	return &MetricsServer{
		pipeline: pipeline,
		addr:     addr,
	}
}

func (s *MetricsServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/traces", s.handleTraces)
	mux.HandleFunc("/stats", s.handleStats)

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	return s.server.ListenAndServe()
}

func (s *MetricsServer) Shutdown() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *MetricsServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.pipeline.Metrics()

	counters := metrics.GetAllCounters()
	gauges := metrics.GetAllGauges()

	output := map[string]any{
		"counters":  counters,
		"gauges":    gauges,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func (s *MetricsServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

func (s *MetricsServer) handleTraces(w http.ResponseWriter, r *http.Request) {
	traceID := r.URL.Query().Get("trace_id")

	if traceID == "" {
		http.Error(w, "trace_id required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "trace storage not implemented",
	})
}

func (s *MetricsServer) handleStats(w http.ResponseWriter, r *http.Request) {
	metrics := s.pipeline.Metrics()

	counters := metrics.GetAllCounters()

	totalURLs := counters["pipeline_urls_processed"]
	errors := counters["pipeline_fetch_errors"] + counters["pipeline_extract_errors"]

	var successRate float64
	if totalURLs > 0 {
		successRate = float64(totalURLs-errors) / float64(totalURLs) * 100
	}

	stats := map[string]any{
		"urls_processed": totalURLs,
		"errors":         errors,
		"success_rate":   successRate,
		"index_size":     0,
		"cache_hits":     counters["stage_extract_chunks_cached"],
		"llm_calls":      counters["stage_extract_chunks_llm"],
		"total_bytes":    counters["stage_fetch_bytes_total"],
	}

	if s.pipeline.index != nil {
		stats["index_size"] = len(s.pipeline.Index().Search(nil, 1))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *MetricsServer) IndexStats() *IndexStats {
	return nil
}

type IndexStats struct {
	TotalVectors   int
	UniqueURLs     int
	LastInsertTime time.Time
}
