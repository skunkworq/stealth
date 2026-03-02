package log

import (
	"context"
	"testing"
)

func TestLevelParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", DebugLevel},
		{"info", InfoLevel},
		{"warn", WarnLevel},
		{"warning", WarnLevel},
		{"error", ErrorLevel},
		{"fatal", FatalLevel},
		{"unknown", InfoLevel}, // default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseLevel(tt.input)
			if got != tt.expected {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNopLogger(t *testing.T) {
	logger := NewNopLogger()

	// These should not panic
	logger.Debug("debug message", "key", "value")
	logger.Info("info message", "key", "value")
	logger.Warn("warn message", "key", "value")
	logger.Error("error message", "key", "value")

	child := logger.With("extra", "field")
	child.Info("child message")

	named := logger.Named("test")
	named.Info("named message")

	// Sync may fail when writing to stderr (expected)
	_ = logger.Sync()
}

func TestGlobalLogger(t *testing.T) {
	// Save original
	original := Global()

	// Set nop logger
	nop := NewNopLogger()
	SetGlobal(nop)

	// Verify it was set
	if Global() != nop {
		t.Error("Global() did not return set logger")
	}

	// Test package-level functions don't panic
	Debug("debug", "key", "value")
	Info("info", "key", "value")
	Warn("warn", "key", "value")
	Error("error", "key", "value")

	// Restore
	SetGlobal(original)
}

func TestContext(t *testing.T) {
	logger := NewNopLogger()

	ctx := IntoContext(context.Background(), logger)
	retrieved := FromContext(ctx)

	if retrieved != logger {
		t.Error("FromContext did not return stored logger")
	}

	// Test Ctx helper
	ctxLogger := Ctx(ctx)
	if ctxLogger != logger {
		t.Error("Ctx did not return stored logger")
	}

	// Test fallback to global
	emptyCtx := context.Background()
	if FromContext(emptyCtx) != Global() {
		t.Error("FromContext did not fallback to global")
	}
}

func TestSlogLogger(t *testing.T) {
	logger, err := NewSlogLogger(&SlogConfig{
		Level: InfoLevel,
		JSON:  false,
	})
	if err != nil {
		t.Fatalf("NewSlogLogger failed: %v", err)
	}

	logger.Info("test message", "key", "value")
	logger.With("extra", "field").Info("with message")
	logger.Named("test").Info("named message")
}

func TestZapLogger(t *testing.T) {
	logger, err := NewZapLogger(&ZapConfig{
		Level: InfoLevel,
		JSON:  false,
	})
	if err != nil {
		t.Fatalf("NewZapLogger failed: %v", err)
	}

	logger.Info("test message", "key", "value")
	logger.With("extra", "field").Info("with message")
	logger.Named("test").Info("named message")

	// Sync may fail when writing to stderr (expected behavior)
	_ = logger.Sync()
}

func TestNewFactory(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		backend string
	}{
		{"zap default", &Config{Level: "info", Backend: "zap"}, "zap"},
		{"slog backend", &Config{Level: "debug", Backend: "slog"}, "slog"},
		{"empty backend", &Config{Level: "warn", Backend: ""}, "zap"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.config)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// Test basic logging
			logger.Info("test message")
		})
	}
}
