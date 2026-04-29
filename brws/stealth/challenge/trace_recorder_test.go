package challenge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTraceRecorder_SessionLifecycle(t *testing.T) {
	dir := t.TempDir()
	tr := NewTraceRecorder(dir)

	// Start session
	session := tr.StartSession("ben", TraceEnvironment{
		UserAgent: "Chrome/134", Platform: "macOS", ScreenW: 2560, ScreenH: 1440,
	})
	if session.ID == "" {
		t.Fatal("session ID should not be empty")
	}
	if session.Operator != "ben" {
		t.Errorf("operator = %s, want ben", session.Operator)
	}

	// Start recording
	rec, err := tr.StartRecording(session.ID, "turnstile", "rotate", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ChallengeType != "turnstile" {
		t.Errorf("type = %s, want turnstile", rec.ChallengeType)
	}

	// Record events
	for i := range 10 {
		err := tr.RecordEvent(session.ID, rec.ID, CaptchaEvent{
			Type: "mousemove", ElapsedMs: int64(i * 100),
			X: float64(100 + i*20), Y: float64(200 + i*5),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Complete recording
	completed, err := tr.CompleteRecording(session.ID, rec.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !completed.Solved {
		t.Error("recording should be solved")
	}
	if completed.Metrics.TotalEvents != 10 {
		t.Errorf("events = %d, want 10", completed.Metrics.TotalEvents)
	}
	if completed.Metrics.MouseMoves != 10 {
		t.Errorf("mouse moves = %d, want 10", completed.Metrics.MouseMoves)
	}

	// End session (saves to disk)
	session, err = tr.EndSession(session.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Verify files exist
	sessDir := filepath.Join(dir, "traces", session.ID)
	if _, err := os.Stat(filepath.Join(sessDir, "session.json")); err != nil {
		t.Error("session.json should exist:", err)
	}
}

func TestTraceRecorder_BatchEvents(t *testing.T) {
	tr := NewTraceRecorder(t.TempDir())
	session := tr.StartSession("test", TraceEnvironment{})
	rec, _ := tr.StartRecording(session.ID, "recaptcha_v2", "image_grid", "")

	events := []CaptchaEvent{
		{Type: "mousemove", ElapsedMs: 100, X: 50, Y: 50},
		{Type: "click", ElapsedMs: 200, X: 100, Y: 100},
		{Type: "mousemove", ElapsedMs: 300, X: 150, Y: 150},
	}
	if err := tr.RecordEvents(session.ID, rec.ID, events); err != nil {
		t.Fatal(err)
	}

	completed, _ := tr.CompleteRecording(session.ID, rec.ID, true)
	if completed.Metrics.TotalEvents != 3 {
		t.Errorf("events = %d, want 3", completed.Metrics.TotalEvents)
	}
}

func TestTraceRecorder_ErrorCases(t *testing.T) {
	tr := NewTraceRecorder(t.TempDir())

	// Unknown session
	_, err := tr.StartRecording("nonexistent", "test", "test", "")
	if err == nil {
		t.Error("should error on unknown session")
	}

	err = tr.RecordEvent("nonexistent", "rec1", CaptchaEvent{})
	if err == nil {
		t.Error("should error on unknown session")
	}
}

func TestTraceRecorder_LoadSession(t *testing.T) {
	dir := t.TempDir()
	tr := NewTraceRecorder(dir)

	session := tr.StartSession("ben", TraceEnvironment{Platform: "macOS"})
	rec, _ := tr.StartRecording(session.ID, "turnstile", "checkbox", "")
	_ = tr.RecordEvent(session.ID, rec.ID, CaptchaEvent{Type: "click", ElapsedMs: 500, X: 100, Y: 100})
	_, _ = tr.CompleteRecording(session.ID, rec.ID, true)
	_, _ = tr.EndSession(session.ID)

	// Load in a fresh recorder
	tr2 := NewTraceRecorder(dir)
	loaded, err := tr2.LoadSession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Recordings) != 1 {
		t.Fatalf("loaded %d recordings, want 1", len(loaded.Recordings))
	}
	if len(loaded.Recordings[0].Events) != 1 {
		t.Errorf("loaded %d events, want 1", len(loaded.Recordings[0].Events))
	}
}

func TestTraceFingerprint(t *testing.T) {
	rec := &TraceRecording{
		ChallengeType:    "turnstile",
		ChallengeVariant: "rotate",
		Events: []CaptchaEvent{
			{Type: "mousemove", X: 100, Y: 200, ElapsedMs: 100},
			{Type: "click", X: 150, Y: 250, ElapsedMs: 200},
		},
	}
	fp := TraceFingerprint(rec)
	if len(fp) != 16 { // 8 bytes hex
		t.Errorf("fingerprint length = %d, want 16", len(fp))
	}

	// Same recording should produce same fingerprint
	fp2 := TraceFingerprint(rec)
	if fp != fp2 {
		t.Error("same recording should produce same fingerprint")
	}
}

func TestComputeRecordingMetrics(t *testing.T) {
	events := []CaptchaEvent{
		{Type: "mousemove", ElapsedMs: 0, X: 0, Y: 0},
		{Type: "mousemove", ElapsedMs: 100, X: 100, Y: 0},   // right
		{Type: "mousemove", ElapsedMs: 200, X: 50, Y: 0},    // left (direction change!)
		{Type: "mousemove", ElapsedMs: 800, X: 200, Y: 100}, // 600ms gap = hesitation
		{Type: "click", ElapsedMs: 900, X: 200, Y: 100},
	}
	m := computeRecordingMetrics(events)

	if m.MouseMoves != 4 {
		t.Errorf("mouse moves = %d, want 4", m.MouseMoves)
	}
	if m.Clicks != 1 {
		t.Errorf("clicks = %d, want 1", m.Clicks)
	}
	if m.Hesitations != 1 {
		t.Errorf("hesitations = %d, want 1", m.Hesitations)
	}
	if m.DirectionChanges < 1 {
		t.Errorf("direction changes = %d, want ≥1", m.DirectionChanges)
	}
}
