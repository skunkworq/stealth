package instrumentation

import (
	"os"
	"testing"
)

func TestLogger(t *testing.T) {
	// Test with default config
	log, err := NewLogger(&Config{
		LogLevel: "debug",
		Output:   os.Stderr,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	log.Debugw("debug message", "key", "value")
	log.Infow("info message", "key", "value")
	log.Warnw("warn message", "key", "value")
	log.Errorw("error message", "key", "value")

	_ = log.Flush()
}

func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		level     string
		wantPanic bool
	}{
		{"debug", false},
		{"info", false},
		{"warn", false},
		{"error", false},
		{"invalid", false}, // Should default to info
	}

	for _, tt := range tests {
		_, err := NewLogger(&Config{LogLevel: tt.level})
		if err != nil {
			t.Errorf("NewLogger(%q) error = %v", tt.level, err)
		}
	}
}

func TestDefaultLogger(t *testing.T) {
	log := GetDefault()
	if log == nil {
		t.Fatal("expected non-nil default logger")
	}

	// Should not panic
	log.Info("test message")
	_ = log.Flush()
}

func TestLoggerNamed(t *testing.T) {
	log := GetDefault()
	named := log.Named("test-component")
	if named == nil {
		t.Fatal("expected non-nil named logger")
	}
	named.Info("test from named logger")
}

func TestLoggerWith(t *testing.T) {
	log := GetDefault()
	withLog := log.With("custom-field", "custom-value")
	if withLog == nil {
		t.Fatal("expected non-nil logger with fields")
	}
	withLog.Info("test with fields")
}
