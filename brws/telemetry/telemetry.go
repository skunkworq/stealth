package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

type Telemetry struct {
	TracerProvider *sdktrace.TracerProvider
	MeterProvider  *sdkmetric.MeterProvider
	Tracer         trace.Tracer
	Meter          metric.Meter
	Shutdown       func(context.Context) error
}

type Config struct {
	ServiceName    string
	ServiceVersion string
	OTLPEndpoint   string
	PrometheusAddr string
	SampleRate     float64
}

func New(ctx context.Context, cfg *Config) (*Telemetry, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	var tp *sdktrace.TracerProvider
	if cfg.OTLPEndpoint != "" {
		exporter, err := otlptrace.New(ctx,
			otlptracegrpc.NewClient(
				otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
				otlptracegrpc.WithInsecure(),
			),
		)
		if err != nil {
			return nil, fmt.Errorf("create OTLP exporter: %w", err)
		}

		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRate)),
		)
	} else {
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRate)),
		)
	}

	otel.SetTracerProvider(tp)
	tracer := tp.Tracer(cfg.ServiceName)

	promExporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("create prometheus exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(promExporter),
	)
	otel.SetMeterProvider(mp)
	meter := mp.Meter(cfg.ServiceName)

	return &Telemetry{
		TracerProvider: tp,
		MeterProvider:  mp,
		Tracer:         tracer,
		Meter:          meter,
		Shutdown: func(ctx context.Context) error {
			var errs []error
			if err := tp.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("shutdown tracer: %w", err))
			}
			if err := mp.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("shutdown meter: %w", err))
			}
			if len(errs) > 0 {
				return fmt.Errorf("telemetry shutdown: %v", errs)
			}
			return nil
		},
	}, nil
}

func (t *Telemetry) StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return t.Tracer.Start(ctx, name)
}

func (t *Telemetry) StartSpanWithParent(ctx context.Context, name string, parent trace.SpanContext) (context.Context, trace.Span) {
	ctx = trace.ContextWithSpanContext(ctx, parent)
	return t.Tracer.Start(ctx, name)
}

func (t *Telemetry) RecordMetric(ctx context.Context, name string, value float64, attrs ...attribute.KeyValue) {
	counter, err := t.Meter.Float64Counter(name)
	if err != nil {
		return
	}
	counter.Add(ctx, value, metric.WithAttributes(attrs...))
}

func (t *Telemetry) RecordHistogram(ctx context.Context, name string, value float64, attrs ...attribute.KeyValue) {
	histogram, err := t.Meter.Float64Histogram(name)
	if err != nil {
		return
	}
	histogram.Record(ctx, value, metric.WithAttributes(attrs...))
}

func (t *Telemetry) NewCounter(name string, description string) (metric.Float64Counter, error) {
	return t.Meter.Float64Counter(name,
		metric.WithDescription(description),
	)
}

func (t *Telemetry) NewHistogram(name string, description string, buckets []float64) (metric.Float64Histogram, error) {
	return t.Meter.Float64Histogram(name,
		metric.WithDescription(description),
		metric.WithExplicitBucketBoundaries(buckets...),
	)
}

type MetricServer struct {
	addr   string
	server *http.Server
}

func NewMetricServer(cfg *Config) *MetricServer {
	return &MetricServer{
		addr: cfg.PrometheusAddr,
	}
}

func (s *MetricServer) Start() error {
	if s.addr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	return s.server.ListenAndServe()
}

func (s *MetricServer) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *MetricServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
}

type SpanInfo struct {
	Name       string
	TraceID    string
	SpanID     string
	ParentID   string
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Attributes map[string]interface{}
	Events     []EventInfo
	Status     string
	Error      error
}

type EventInfo struct {
	Name      string
	Timestamp time.Time
	Attrs     map[string]interface{}
}
