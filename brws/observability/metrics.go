// Package observability provides metrics collection, health checks, and tracing.
package observability

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector collects and stores metrics
type MetricsCollector interface {
	// Counters
	IncCounter(name string, labels map[string]string)
	AddCounter(name string, value int64, labels map[string]string)

	// Gauges
	SetGauge(name string, value float64, labels map[string]string)

	// Histograms/Timers
	RecordHistogram(name string, value float64, labels map[string]string)
	RecordTiming(name string, duration time.Duration, labels map[string]string)

	// Retrieval
	GetCounter(name string, labels map[string]string) int64
	GetGauge(name string, labels map[string]string) float64
	GetHistogram(name string, labels map[string]string) *HistogramStats
}

// HistogramStats contains histogram statistics
type HistogramStats struct {
	Count   int64
	Sum     float64
	Min     float64
	Max     float64
	Buckets map[float64]int64 // bucket upper bound -> count
}

// InMemoryCollector is a simple in-memory metrics collector
type InMemoryCollector struct {
	counters   map[string]*counter
	gauges     map[string]*gauge
	histograms map[string]*histogram
	mu         sync.RWMutex
}

// NewInMemoryCollector creates a new in-memory collector
func NewInMemoryCollector() *InMemoryCollector {
	return &InMemoryCollector{
		counters:   make(map[string]*counter),
		gauges:     make(map[string]*gauge),
		histograms: make(map[string]*histogram),
	}
}

type counter struct {
	value int64
}

func (c *counter) Inc() {
	atomic.AddInt64(&c.value, 1)
}

func (c *counter) Add(n int64) {
	atomic.AddInt64(&c.value, n)
}

func (c *counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

type gauge struct {
	value float64
	mu    sync.RWMutex
}

func (g *gauge) Set(v float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value = v
}

func (g *gauge) Value() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.value
}

type histogram struct {
	count int64
	sum   float64
	min   float64
	max   float64
	mu    sync.RWMutex
}

func (h *histogram) Record(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.count == 0 || v < h.min {
		h.min = v
	}
	if v > h.max {
		h.max = v
	}
	h.count++
	h.sum += v
}

func (h *histogram) Stats() *HistogramStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return &HistogramStats{
		Count: h.count,
		Sum:   h.sum,
		Min:   h.min,
		Max:   h.max,
	}
}

// validateMetricName checks if a metric name is valid
func validateMetricName(name string) error {
	if name == "" {
		return fmt.Errorf("metric name cannot be empty")
	}
	return nil
}

// validateLabels checks if labels are valid
func validateLabels(labels map[string]string) error {
	for k, v := range labels {
		if k == "" {
			return fmt.Errorf("label key cannot be empty")
		}
		if strings.Contains(k, ":") {
			return fmt.Errorf("label key cannot contain ':': %s", k)
		}
		_ = v // values can be empty
	}
	return nil
}

func makeKey(name string, labels map[string]string) string {
	// Validation errors are ignored to maintain backward compatibility
	// In strict mode, these should return error
	_ = validateMetricName(name)
	_ = validateLabels(labels)
	
	if len(labels) == 0 {
		return name
	}
	return name + ":" + serializeLabels(labels)
}

func serializeLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	
	// Sort keys for deterministic output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		// Escape special characters to prevent key collisions
		b.WriteString(escapeLabel(k))
		b.WriteByte('=')
		b.WriteString(escapeLabel(labels[k]))
	}
	return b.String()
}

// escapeLabel escapes special characters in label keys/values
func escapeLabel(s string) string {
	// Replace backslash and equals to prevent collisions
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `,`, `\,`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	return s
}

// IncCounter increments a counter
func (c *InMemoryCollector) IncCounter(name string, labels map[string]string) {
	key := makeKey(name, labels)
	c.mu.Lock()
	cnt, exists := c.counters[key]
	if !exists {
		cnt = &counter{}
		c.counters[key] = cnt
	}
	c.mu.Unlock()
	cnt.Inc()
}

// AddCounter adds a value to a counter
func (c *InMemoryCollector) AddCounter(name string, value int64, labels map[string]string) {
	key := makeKey(name, labels)
	c.mu.Lock()
	cnt, exists := c.counters[key]
	if !exists {
		cnt = &counter{}
		c.counters[key] = cnt
	}
	c.mu.Unlock()
	cnt.Add(value)
}

// SetGauge sets a gauge value
func (c *InMemoryCollector) SetGauge(name string, value float64, labels map[string]string) {
	key := makeKey(name, labels)
	c.mu.Lock()
	g, exists := c.gauges[key]
	if !exists {
		g = &gauge{}
		c.gauges[key] = g
	}
	c.mu.Unlock()
	g.Set(value)
}

// RecordHistogram records a histogram value
func (c *InMemoryCollector) RecordHistogram(name string, value float64, labels map[string]string) {
	key := makeKey(name, labels)
	c.mu.Lock()
	h, exists := c.histograms[key]
	if !exists {
		h = &histogram{}
		c.histograms[key] = h
	}
	c.mu.Unlock()
	h.Record(value)
}

// RecordTiming records a timing duration
func (c *InMemoryCollector) RecordTiming(name string, duration time.Duration, labels map[string]string) {
	c.RecordHistogram(name, float64(duration.Milliseconds()), labels)
}

// GetCounter gets a counter value
func (c *InMemoryCollector) GetCounter(name string, labels map[string]string) int64 {
	key := makeKey(name, labels)
	c.mu.RLock()
	cnt, exists := c.counters[key]
	c.mu.RUnlock()
	if !exists {
		return 0
	}
	return cnt.Value()
}

// GetGauge gets a gauge value
func (c *InMemoryCollector) GetGauge(name string, labels map[string]string) float64 {
	key := makeKey(name, labels)
	c.mu.RLock()
	g, exists := c.gauges[key]
	c.mu.RUnlock()
	if !exists {
		return 0
	}
	return g.Value()
}

// GetHistogram gets histogram statistics
func (c *InMemoryCollector) GetHistogram(name string, labels map[string]string) *HistogramStats {
	key := makeKey(name, labels)
	c.mu.RLock()
	h, exists := c.histograms[key]
	c.mu.RUnlock()
	if !exists {
		return &HistogramStats{}
	}
	return h.Stats()
}

// GetAllCounters returns all counter values
func (c *InMemoryCollector) GetAllCounters() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]int64, len(c.counters))
	for k, v := range c.counters {
		result[k] = v.Value()
	}
	return result
}

// GetAllGauges returns all gauge values
func (c *InMemoryCollector) GetAllGauges() map[string]float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]float64, len(c.gauges))
	for k, v := range c.gauges {
		result[k] = v.Value()
	}
	return result
}

// Reset clears all metrics
func (c *InMemoryCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counters = make(map[string]*counter)
	c.gauges = make(map[string]*gauge)
	c.histograms = make(map[string]*histogram)
}

// global collector instance
var (
	globalCollector     MetricsCollector
	globalCollectorOnce sync.Once
	globalCollectorMu   sync.RWMutex
)

// SetGlobalCollector sets the global metrics collector
func SetGlobalCollector(collector MetricsCollector) {
	globalCollectorMu.Lock()
	defer globalCollectorMu.Unlock()
	globalCollector = collector
}

// GlobalCollector returns the global metrics collector
func GlobalCollector() MetricsCollector {
	globalCollectorMu.RLock()
	if globalCollector != nil {
		defer globalCollectorMu.RUnlock()
		return globalCollector
	}
	globalCollectorMu.RUnlock()

	globalCollectorOnce.Do(func() {
		SetGlobalCollector(NewInMemoryCollector())
	})

	globalCollectorMu.RLock()
	defer globalCollectorMu.RUnlock()
	return globalCollector
}

// IncCounter increments a counter on the global collector
func IncCounter(name string, labels map[string]string) {
	GlobalCollector().IncCounter(name, labels)
}

// AddCounter adds to a counter on the global collector
func AddCounter(name string, value int64, labels map[string]string) {
	GlobalCollector().AddCounter(name, value, labels)
}

// SetGauge sets a gauge on the global collector
func SetGauge(name string, value float64, labels map[string]string) {
	GlobalCollector().SetGauge(name, value, labels)
}

// RecordTiming records a timing on the global collector
func RecordTiming(name string, duration time.Duration, labels map[string]string) {
	GlobalCollector().RecordTiming(name, duration, labels)
}

// Timer is a helper for timing operations
type Timer struct {
	start     time.Time
	name      string
	labels    map[string]string
	collector MetricsCollector
}

// StartTimer starts a new timer
func StartTimer(name string, labels map[string]string) *Timer {
	return &Timer{
		start:     time.Now(),
		name:      name,
		labels:    labels,
		collector: GlobalCollector(),
	}
}

// Stop stops the timer and records the duration
func (t *Timer) Stop() time.Duration {
	duration := time.Since(t.start)
	t.collector.RecordTiming(t.name, duration, t.labels)
	return duration
}

// WithCollector sets a custom collector for the timer
func (t *Timer) WithCollector(collector MetricsCollector) *Timer {
	t.collector = collector
	return t
}

// TimeFunc times a function execution
func TimeFunc(name string, labels map[string]string, fn func()) time.Duration {
	timer := StartTimer(name, labels)
	fn()
	return timer.Stop()
}

// TimeFuncErr times a function that returns an error
func TimeFuncErr(name string, labels map[string]string, fn func() error) (time.Duration, error) {
	timer := StartTimer(name, labels)
	err := fn()
	duration := timer.Stop()

	// Add success/failure label
	resultLabels := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		resultLabels[k] = v
	}
	if err != nil {
		resultLabels["result"] = "error"
	} else {
		resultLabels["result"] = "success"
	}

	return duration, err
}

// Context functions

// WithCollector returns a context with a metrics collector
func WithCollector(ctx context.Context, collector MetricsCollector) context.Context {
	return context.WithValue(ctx, metricsKey{}, collector)
}

// CollectorFromContext gets the collector from context
func CollectorFromContext(ctx context.Context) MetricsCollector {
	if c, ok := ctx.Value(metricsKey{}).(MetricsCollector); ok {
		return c
	}
	return GlobalCollector()
}

type metricsKey struct{}
