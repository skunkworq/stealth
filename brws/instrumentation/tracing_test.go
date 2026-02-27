package instrumentation

import (
	"context"
	"testing"
)

func TestTracer_NewTracer(t *testing.T) {
	tracer := NewTracer()
	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}
}

func TestTracer_StartSpan(t *testing.T) {
	tracer := NewTracer()
	ctx := context.Background()

	ctx, span := tracer.StartSpan(ctx, "test-span", SpanKindRequest)
	if span == nil {
		t.Fatal("expected non-nil span")
	}

	if span.Name != "test-span" {
		t.Errorf("expected span name 'test-span', got %q", span.Name)
	}

	if span.Kind != SpanKindRequest {
		t.Errorf("expected span kind 'request', got %q", span.Kind)
	}

	// Span should be retrievable
	retrieved := tracer.GetSpan(span.TraceID)
	if retrieved == nil {
		t.Error("expected to retrieve span by trace ID")
	}
}

func TestTracer_StartSpan_Nested(t *testing.T) {
	tracer := NewTracer()
	ctx := context.Background()

	ctx, parent := tracer.StartSpan(ctx, "parent", SpanKindRequest)
	ctx, child := tracer.StartSpan(ctx, "child", SpanKindInternal)

	// Child should have parent ID
	if child.ParentSpanID != parent.SpanID {
		t.Errorf("expected child parent ID to match parent span ID")
	}

	// Parent should have child in children
	if len(parent.Children) != 1 {
		t.Errorf("expected 1 child, got %d", len(parent.Children))
	}
}

func TestSpan_End(t *testing.T) {
	span := NewSpan("test", SpanKindRequest)
	span.End()

	d := span.Duration()
	if d <= 0 {
		t.Error("expected positive duration after End()")
	}
}

func TestSpan_SetAttribute(t *testing.T) {
	span := NewSpan("test", SpanKindRequest)
	span.SetAttribute("key", "value")

	if span.Attributes["key"] != "value" {
		t.Errorf("expected attribute value 'value', got %v", span.Attributes["key"])
	}
}

func TestSpan_AddEvent(t *testing.T) {
	span := NewSpan("test", SpanKindRequest)
	span.AddEvent("test-event", map[string]interface{}{"foo": "bar"})

	if len(span.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(span.Events))
	}

	if span.Events[0].Name != "test-event" {
		t.Errorf("expected event name 'test-event', got %q", span.Events[0].Name)
	}
}

func TestSpan_ContextPropagation(t *testing.T) {
	tracer := NewTracer()
	ctx := context.Background()

	ctx, span := tracer.StartSpan(ctx, "test", SpanKindRequest)

	// Retrieve span from context
	retrieved := SpanFromContext(ctx)
	if retrieved == nil {
		t.Fatal("expected to retrieve span from context")
	}

	if retrieved.SpanID != span.SpanID {
		t.Errorf("expected retrieved span ID to match original")
	}
}

func TestTracer_GetAllSpans(t *testing.T) {
	tracer := NewTracer()
	ctx := context.Background()

	// Start two separate traces
	ctx1, span1 := tracer.StartSpan(ctx, "span1", SpanKindRequest)
	span1.TraceID = "trace-1"
	span1.End()
	_ = ctx1

	ctx2, span2 := tracer.StartSpan(ctx, "span2", SpanKindRequest)
	span2.TraceID = "trace-2"
	span2.End()
	_ = ctx2

	spans := tracer.GetAllSpans()
	// Each call creates a new trace
	if len(spans) < 1 {
		t.Errorf("expected at least 1 span, got %d", len(spans))
	}
}

func TestTracer_Clear(t *testing.T) {
	tracer := NewTracer()
	ctx := context.Background()

	tracer.StartSpan(ctx, "span1", SpanKindRequest)
	tracer.Clear()

	spans := tracer.GetAllSpans()
	if len(spans) != 0 {
		t.Errorf("expected 0 spans after clear, got %d", len(spans))
	}
}

func TestTrace_ToTrace(t *testing.T) {
	span := NewSpan("root", SpanKindRequest)
	child := NewSpan("child", SpanKindInternal)
	span.AddChild(child)
	span.End()

	trace := span.ToTrace()
	if trace == nil {
		t.Fatal("expected non-nil trace")
	}

	if len(trace.Spans) != 2 {
		t.Errorf("expected 2 spans in trace, got %d", len(trace.Spans))
	}
}

func TestGenerateIDs(t *testing.T) {
	traceID := GenerateTraceID()
	if traceID == "" {
		t.Error("expected non-empty trace ID")
	}

	spanID := GenerateSpanID()
	if spanID == "" {
		t.Error("expected non-empty span ID")
	}
}
