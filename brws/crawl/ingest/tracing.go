package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skunkworq/stealth/brws/core/observability"
)

type TraceID string

type SpanID string

type Span struct {
	TraceID    TraceID        `json:"trace_id"`
	SpanID     SpanID         `json:"span_id"`
	ParentID   SpanID         `json:"parent_id,omitempty"`
	Name       string         `json:"name"`
	StartTime  time.Time      `json:"start_time"`
	EndTime    time.Time      `json:"end_time,omitempty"`
	Duration   time.Duration  `json:"duration"`
	Status     string         `json:"status"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Events     []SpanEvent    `json:"events,omitempty"`
	Error      error          `json:"-"`
}

type SpanEvent struct {
	Name      string         `json:"name"`
	Timestamp time.Time      `json:"timestamp"`
	Attrs     map[string]any `json:"attrs,omitempty"`
}

type TraceContext struct {
	TraceID  TraceID
	SpanID   SpanID
	ParentID SpanID
	spans    []*Span
	mu       chan struct{}
}

func NewTraceContext() *TraceContext {
	return &TraceContext{
		TraceID: TraceID(generateTraceID()),
		SpanID:  SpanID(generateSpanID()),
		spans:   make([]*Span, 0),
		mu:      make(chan struct{}, 1),
	}
}

type traceKey struct{}

func ContextWithTrace(ctx context.Context, tc *TraceContext) context.Context {
	return context.WithValue(ctx, traceKey{}, tc)
}

func TraceFromContext(ctx context.Context) *TraceContext {
	if tc, ok := ctx.Value(traceKey{}).(*TraceContext); ok {
		return tc
	}
	return nil
}

func (tc *TraceContext) StartSpan(name string) *Span {
	span := &Span{
		TraceID:    tc.TraceID,
		SpanID:     SpanID(generateSpanID()),
		ParentID:   tc.SpanID,
		Name:       name,
		StartTime:  time.Now(),
		Status:     "running",
		Attributes: make(map[string]any),
	}

	tc.mu <- struct{}{}
	tc.spans = append(tc.spans, span)
	<-tc.mu

	observability.IncCounter("trace_spans_started", map[string]string{
		"trace_id": string(tc.TraceID),
		"span":     name,
	})

	return span
}

func (s *Span) End() {
	s.EndTime = time.Now()
	s.Duration = s.EndTime.Sub(s.StartTime)

	if s.Status == "running" {
		s.Status = "ok"
	}

	observability.RecordTiming("span_duration", s.Duration, map[string]string{
		"trace_id": string(s.TraceID),
		"span":     s.Name,
		"status":   s.Status,
	})
}

func (s *Span) SetError(err error) {
	s.Status = "error"
	s.Error = err
	if s.Attributes == nil {
		s.Attributes = make(map[string]any)
	}
	s.Attributes["error"] = err.Error()

	observability.IncCounter("span_errors", map[string]string{
		"trace_id": string(s.TraceID),
		"span":     s.Name,
	})
}

func (s *Span) SetAttribute(key string, value any) {
	if s.Attributes == nil {
		s.Attributes = make(map[string]any)
	}
	s.Attributes[key] = value
}

func (s *Span) AddEvent(name string, attrs map[string]any) {
	event := SpanEvent{
		Name:      name,
		Timestamp: time.Now(),
		Attrs:     attrs,
	}
	s.Events = append(s.Events, event)
}

func (tc *TraceContext) AllSpans() []*Span {
	tc.mu <- struct{}{}
	defer func() { <-tc.mu }()
	return tc.spans
}

func (tc *TraceContext) TotalDuration() time.Duration {
	var total time.Duration
	for _, span := range tc.AllSpans() {
		if span.ParentID == "" {
			total += span.Duration
		}
	}
	return total
}

func (tc *TraceContext) ToJSON() string {
	data := map[string]any{
		"trace_id": tc.TraceID,
		"spans":    tc.AllSpans(),
		"duration": tc.TotalDuration().String(),
	}
	bytes, _ := json.MarshalIndent(data, "", "  ")
	return string(bytes)
}

func generateTraceID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func generateSpanID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano()&0xffff)
}
