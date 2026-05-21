// Package instrumentation provides tracing for the stealth browser engine.
package instrumentation

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TraceID represents a unique trace identifier.
type TraceID string

// SpanID represents a unique span identifier.
type SpanID string

// SpanKind defines the type of span.
type SpanKind string

const (
	// SpanKindInternal represents internal spans
	SpanKindInternal SpanKind = "internal"
	// SpanKindRequest represents request spans
	SpanKindRequest SpanKind = "request"
	// SpanKindBrowser represents browser spans
	SpanKindBrowser SpanKind = "browser"
	// SpanKindNetwork represents network spans
	SpanKindNetwork SpanKind = "network"
	// SpanKindStealth represents stealth spans
	SpanKindStealth SpanKind = "stealth"
)

// Span represents a unit of work in a trace.
type Span struct {
	TraceID      TraceID
	SpanID       SpanID
	ParentSpanID SpanID
	Name         string
	Kind         SpanKind
	StartTime    time.Time
	EndTime      time.Time
	Attributes   map[string]interface{}
	Status       SpanStatus
	Events       []SpanEvent
	Children     []*Span

	mu sync.RWMutex
}

// SpanStatus represents the status of a span.
type SpanStatus struct {
	Code    string
	Message string
}

// SpanEvent represents an event within a span.
type SpanEvent struct {
	Name       string
	Timestamp  time.Time
	Attributes map[string]interface{}
}

// NewSpan creates a new span.
func NewSpan(name string, kind SpanKind) *Span {
	return &Span{
		Name:       name,
		Kind:       kind,
		StartTime:  time.Now(),
		Attributes: make(map[string]interface{}),
		Events:     make([]SpanEvent, 0),
		Children:   make([]*Span, 0),
	}
}

// End marks the span as complete.
func (s *Span) End() {
	s.EndTime = time.Now()
}

// SetAttribute sets a span attribute.
func (s *Span) SetAttribute(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Attributes[key] = value
}

// AddEvent adds an event to the span.
func (s *Span) AddEvent(name string, attrs map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attrs,
	})
}

// AddChild adds a child span.
func (s *Span) AddChild(child *Span) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Children = append(s.Children, child)
}

// Duration returns the span duration.
func (s *Span) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// Tracer provides tracing functionality.
type Tracer struct {
	mu           sync.RWMutex
	spans        map[TraceID]*Span
	currentSpans map[context.Context]*Span
}

// NewTracer creates a new tracer.
func NewTracer() *Tracer {
	return &Tracer{
		spans:        make(map[TraceID]*Span),
		currentSpans: make(map[context.Context]*Span),
	}
}

// StartSpan starts a new span.
func (t *Tracer) StartSpan(ctx context.Context, name string, kind SpanKind) (context.Context, *Span) {
	span := NewSpan(name, kind)

	// Try to get parent from context
	if parentSpan := SpanFromContext(ctx); parentSpan != nil {
		span.ParentSpanID = parentSpan.SpanID
		parentSpan.AddChild(span)
	}

	// Store span
	t.mu.Lock()
	t.spans[span.TraceID] = span
	t.currentSpans[ctx] = span
	t.mu.Unlock()

	// Add to context
	ctx = ContextWithSpan(ctx, span)

	return ctx, span
}

// EndSpan ends a span.
func (t *Tracer) EndSpan(ctx context.Context) {
	span := SpanFromContext(ctx)
	if span != nil {
		span.End()
	}
}

// GetSpan retrieves a span by trace ID.
func (t *Tracer) GetSpan(traceID TraceID) *Span {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.spans[traceID]
}

// GetAllSpans returns all spans.
func (t *Tracer) GetAllSpans() []*Span {
	t.mu.RLock()
	defer t.mu.RUnlock()

	spans := make([]*Span, 0, len(t.spans))
	for _, span := range t.spans {
		spans = append(spans, span)
	}
	return spans
}

// Clear clears all spans.
func (t *Tracer) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.spans = make(map[TraceID]*Span)
	t.currentSpans = make(map[context.Context]*Span)
}

var (
	spanKey = contextKey("span")
	_       = contextKey("trace")
)

type contextKey string

// ContextWithSpan adds a span to the context.
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, spanKey, span)
}

// SpanFromContext retrieves a span from the context.
func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(spanKey).(*Span); ok {
		return span
	}
	return nil
}

// Trace represents a complete trace.
type Trace struct {
	TraceID  TraceID
	RootSpan *Span
	Spans    []*Span
	Start    time.Time
	End      time.Time
}

// ToTrace converts a root span to a trace.
func (s *Span) ToTrace() *Trace {
	trace := &Trace{
		TraceID:  s.TraceID,
		RootSpan: s,
		Spans:    s.collectSpans(),
		Start:    s.StartTime,
		End:      s.EndTime,
	}
	if s.EndTime.IsZero() {
		trace.End = time.Now()
	}
	return trace
}

func (s *Span) collectSpans() []*Span {
	spans := []*Span{s}
	for _, child := range s.Children {
		spans = append(spans, child.collectSpans()...)
	}
	return spans
}

// String returns a string representation of the trace.
func (t *Trace) String() string {
	return fmt.Sprintf("Trace(%s, %d spans, %v)", t.TraceID, len(t.Spans), t.End.Sub(t.Start))
}

// GenerateTraceID generates a new trace ID.
func GenerateTraceID() TraceID {
	return TraceID(fmt.Sprintf("%016x", time.Now().UnixNano()))
}

// GenerateSpanID generates a new span ID.
func GenerateSpanID() SpanID {
	return SpanID(fmt.Sprintf("%016x", time.Now().UnixNano()))
}

