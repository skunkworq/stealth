// Package log provides a unified logging interface for the stealth browser framework.
// It supports multiple backends (zap, slog) and provides structured logging capabilities.
package log

import (
	"context"
)

// Logger is the unified logging interface used throughout the codebase.
// Implementations must be safe for concurrent use.
type Logger interface {
	// Debug logs a debug message with optional key-value pairs
	Debug(msg string, keysAndValues ...interface{})

	// Info logs an info message with optional key-value pairs
	Info(msg string, keysAndValues ...interface{})

	// Warn logs a warning message with optional key-value pairs
	Warn(msg string, keysAndValues ...interface{})

	// Error logs an error message with optional key-value pairs
	Error(msg string, keysAndValues ...interface{})

	// Fatal logs a fatal message and exits
	Fatal(msg string, keysAndValues ...interface{})

	// With creates a child logger with additional fields
	With(keysAndValues ...interface{}) Logger

	// Named creates a named logger
	Named(name string) Logger

	// WithContext returns a logger with context metadata
	WithContext(ctx context.Context) Logger

	// Sync flushes any buffered log entries
	Sync() error
}

// Level represents log levels
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// String returns the string representation of a log level
func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	default:
		return "info"
	}
}

// ParseLevel parses a level string
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	default:
		return InfoLevel
	}
}

// Test comment
