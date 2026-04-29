package pipeline

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetrics struct {
	URLsProcessed    prometheus.Counter
	URLsFailed       prometheus.Counter
	FetchDuration    prometheus.Histogram
	ExtractDuration  prometheus.Histogram
	EmbedDuration    prometheus.Histogram
	TokensCompressed prometheus.Counter
	TokensFull       prometheus.Counter
	ChunksLLM        prometheus.Counter
	ChunksCached     prometheus.Counter
	BytesFetched     prometheus.Counter
	CompressionRatio prometheus.Gauge
}

func NewPrometheusMetrics(namespace string) *PrometheusMetrics {
	if namespace == "" {
		namespace = "pipeline"
	}

	return &PrometheusMetrics{
		URLsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "urls_processed_total",
			Help:      "Total number of URLs processed",
		}),
		URLsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "urls_failed_total",
			Help:      "Total number of URLs that failed processing",
		}),
		FetchDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "fetch_duration_seconds",
			Help:      "Duration of HTTP fetch operations",
			Buckets:   []float64{.1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		}),
		ExtractDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "extract_duration_seconds",
			Help:      "Duration of semantic extraction operations",
			Buckets:   []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		}),
		EmbedDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "embed_duration_seconds",
			Help:      "Duration of vector embedding operations",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1},
		}),
		TokensCompressed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tokens_compressed_total",
			Help:      "Total tokens after compression",
		}),
		TokensFull: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tokens_full_total",
			Help:      "Total tokens before compression",
		}),
		ChunksLLM: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "chunks_llm_total",
			Help:      "Total chunks processed by LLM",
		}),
		ChunksCached: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "chunks_cached_total",
			Help:      "Total chunks served from cache",
		}),
		BytesFetched: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "bytes_fetched_total",
			Help:      "Total bytes fetched from URLs",
		}),
		CompressionRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "compression_ratio",
			Help:      "Current compression ratio (compressed/full)",
		}),
	}
}

func (m *PrometheusMetrics) Register() error {
	return prometheus.Register(m.URLsProcessed)
}

func (m *PrometheusMetrics) MustRegister() {
	prometheus.MustRegister(
		m.URLsProcessed,
		m.URLsFailed,
		m.FetchDuration,
		m.ExtractDuration,
		m.EmbedDuration,
		m.TokensCompressed,
		m.TokensFull,
		m.ChunksLLM,
		m.ChunksCached,
		m.BytesFetched,
		m.CompressionRatio,
	)
}

func (m *PrometheusMetrics) RecordURLProcessed() {
	m.URLsProcessed.Inc()
}

func (m *PrometheusMetrics) RecordURLFailed() {
	m.URLsFailed.Inc()
}

func (m *PrometheusMetrics) RecordFetchDuration(d time.Duration) {
	m.FetchDuration.Observe(d.Seconds())
}

func (m *PrometheusMetrics) RecordExtractDuration(d time.Duration) {
	m.ExtractDuration.Observe(d.Seconds())
}

func (m *PrometheusMetrics) RecordEmbedDuration(d time.Duration) {
	m.EmbedDuration.Observe(d.Seconds())
}

func (m *PrometheusMetrics) RecordTokens(compressed, full int) {
	m.TokensCompressed.Add(float64(compressed))
	m.TokensFull.Add(float64(full))
	if full > 0 {
		m.CompressionRatio.Set(float64(compressed) / float64(full))
	}
}

func (m *PrometheusMetrics) RecordChunks(llm, cached int) {
	m.ChunksLLM.Add(float64(llm))
	m.ChunksCached.Add(float64(cached))
}

func (m *PrometheusMetrics) RecordBytes(bytes int64) {
	m.BytesFetched.Add(float64(bytes))
}

type PrometheusServer struct {
	addr   string
	server *http.Server
}

func NewPrometheusServer(addr string) *PrometheusServer {
	return &PrometheusServer{addr: addr}
}

func (s *PrometheusServer) Start() error {
	if s.addr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	return s.server.ListenAndServe()
}

func (s *PrometheusServer) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
