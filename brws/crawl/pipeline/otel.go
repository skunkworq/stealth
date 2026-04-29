package pipeline

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type OtelTracer struct {
	tracer trace.Tracer
}

func NewOtelTracer(name string) *OtelTracer {
	return &OtelTracer{
		tracer: otel.Tracer(name),
	}
}

func (t *OtelTracer) StartSpan(ctx context.Context, name string) (context.Context, *OtelSpan) {
	ctx, span := t.tracer.Start(ctx, name)
	return ctx, &OtelSpan{span: span}
}

type OtelSpan struct {
	span trace.Span
}

func (s *OtelSpan) End() {
	s.span.End()
}

func (s *OtelSpan) SetAttribute(key string, value interface{}) {
	switch v := value.(type) {
	case string:
		s.span.SetAttributes(attribute.String(key, v))
	case int:
		s.span.SetAttributes(attribute.Int(key, v))
	case int64:
		s.span.SetAttributes(attribute.Int64(key, v))
	case float64:
		s.span.SetAttributes(attribute.Float64(key, v))
	case bool:
		s.span.SetAttributes(attribute.Bool(key, v))
	}
}

func (s *OtelSpan) SetError(err error) {
	s.span.RecordError(err)
	s.span.SetStatus(codes.Error, err.Error())
}

func (s *OtelSpan) AddEvent(name string, attrs map[string]interface{}) {
	otelAttrs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		switch val := v.(type) {
		case string:
			otelAttrs = append(otelAttrs, attribute.String(k, val))
		case int:
			otelAttrs = append(otelAttrs, attribute.Int(k, val))
		case int64:
			otelAttrs = append(otelAttrs, attribute.Int64(k, val))
		case float64:
			otelAttrs = append(otelAttrs, attribute.Float64(k, val))
		case bool:
			otelAttrs = append(otelAttrs, attribute.Bool(k, val))
		}
	}
	s.span.AddEvent(name, trace.WithAttributes(otelAttrs...))
}

func (s *OtelSpan) SpanContext() trace.SpanContext {
	return s.span.SpanContext()
}

func ContextWithSpan(ctx context.Context, span *OtelSpan) context.Context {
	return trace.ContextWithSpan(ctx, span.span)
}
