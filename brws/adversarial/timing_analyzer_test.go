package adversarial

import (
	"testing"
)

func TestTimingAnalyzer_FixedIntervals(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	// Bot-like: perfectly uniform 100ms intervals
	seq := &RequestTimingSequence{
		Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
			{Timestamp: 100, ContentType: "text/css"},
			{Timestamp: 200, ContentType: "application/javascript"},
			{Timestamp: 300, ContentType: "image/png"},
			{Timestamp: 400, ContentType: "image/jpeg"},
		},
	}

	result := ta.Analyze(seq)
	if !result.Detected {
		t.Error("expected fixed intervals to be detected")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "fixed_intervals" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'fixed_intervals' indicator")
	}
}

func TestTimingAnalyzer_NaturalIntervals(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	// Human-like: variable intervals
	seq := &RequestTimingSequence{
		Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
			{Timestamp: 150, ContentType: "text/css"},
			{Timestamp: 420, ContentType: "application/javascript"},
			{Timestamp: 890, ContentType: "image/png"},
			{Timestamp: 1200, ContentType: "image/jpeg"},
		},
	}

	result := ta.Analyze(seq)
	for _, ind := range result.Indicators {
		if ind.Check == "fixed_intervals" {
			t.Error("natural intervals should not trigger fixed_intervals")
		}
	}
}

func TestTimingAnalyzer_WrongResourceOrder(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	// Bot-like: images loaded before CSS
	seq := &RequestTimingSequence{
		Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
			{Timestamp: 100, ContentType: "image/png"},
			{Timestamp: 200, ContentType: "image/jpeg"},
			{Timestamp: 300, ContentType: "text/css"},
			{Timestamp: 400, ContentType: "application/javascript"},
		},
	}

	result := ta.Analyze(seq)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "wrong_resource_order" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'wrong_resource_order' indicator when images load before CSS")
	}
}

func TestTimingAnalyzer_BrokenReferrerChain(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	// Bot-like: sub-resources missing referrer
	seq := &RequestTimingSequence{
		Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html", URL: "/page"},
			{Timestamp: 100, ContentType: "text/css", URL: "/style.css", Referrer: ""},
			{Timestamp: 200, ContentType: "application/javascript", URL: "/app.js", Referrer: ""},
			{Timestamp: 300, ContentType: "image/png", URL: "/logo.png", Referrer: ""},
		},
	}

	result := ta.Analyze(seq)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "broken_referrer_chain" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'broken_referrer_chain' indicator when sub-resources lack referrers")
	}
}

func TestTimingAnalyzer_TooFastGaps(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	// Bot-like: all gaps under 50ms
	seq := &RequestTimingSequence{
		Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
			{Timestamp: 10, ContentType: "text/css"},
			{Timestamp: 20, ContentType: "application/javascript"},
			{Timestamp: 30, ContentType: "image/png"},
			{Timestamp: 40, ContentType: "image/jpeg"},
		},
	}

	result := ta.Analyze(seq)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "too_fast_gaps" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'too_fast_gaps' indicator when all gaps < 50ms")
	}
}

func TestTimingAnalyzer_NilSequence(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	result := ta.Analyze(nil)
	if result.Detected {
		t.Error("nil sequence should not be detected")
	}
}

func TestTimingAnalyzer_SingleEntry(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	seq := &RequestTimingSequence{
		Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
		},
	}

	result := ta.Analyze(seq)
	if result.Detected {
		t.Error("single entry should not trigger detection")
	}
}
