package log

import (
	"sync"
)

// Config configures the global logger
type Config struct {
	Level      string
	JSON       bool
	Backend    string // "zap" or "slog"
	OutputPath string
}

var (
	globalLogger Logger
	globalOnce   sync.Once
	globalMu     sync.RWMutex
)

// New creates a new logger based on the configuration
func New(config *Config) (Logger, error) {
	if config == nil {
		config = &Config{Level: "info", Backend: "zap"}
	}

	level := ParseLevel(config.Level)

	switch config.Backend {
	case "slog":
		return NewSlogLogger(&SlogConfig{
			Level:      level,
			JSON:       config.JSON,
			OutputPath: config.OutputPath,
		})
	case "zap", "":
		return NewZapLogger(&ZapConfig{
			Level:      level,
			JSON:       config.JSON,
			OutputPath: config.OutputPath,
		})
	default:
		return NewZapLogger(&ZapConfig{
			Level:      level,
			JSON:       config.JSON,
			OutputPath: config.OutputPath,
		})
	}
}

// SetGlobal sets the global logger
func SetGlobal(logger Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = logger
}

// Global returns the global logger
func Global() Logger {
	globalMu.RLock()
	logger := globalLogger
	globalMu.RUnlock()

	if logger != nil {
		return logger
	}

	// Initialize default once
	globalOnce.Do(func() {
		newLogger, err := New(&Config{Level: "info"})
		if err != nil {
			// Fallback to no-op logger on init failure
			newLogger = NewNopLogger()
		}
		SetGlobal(newLogger)
	})

	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger
}

// Init initializes the global logger with config
func Init(config *Config) error {
	logger, err := New(config)
	if err != nil {
		return err
	}
	SetGlobal(logger)
	return nil
}

// Package-level convenience functions

// Debug logs at debug level using global logger
func Debug(msg string, keysAndValues ...interface{}) {
	Global().Debug(msg, keysAndValues...)
}

// Info logs at info level using global logger
func Info(msg string, keysAndValues ...interface{}) {
	Global().Info(msg, keysAndValues...)
}

// Warn logs at warn level using global logger
func Warn(msg string, keysAndValues ...interface{}) {
	Global().Warn(msg, keysAndValues...)
}

// Error logs at error level using global logger
func Error(msg string, keysAndValues ...interface{}) {
	Global().Error(msg, keysAndValues...)
}

// Fatal logs at fatal level using global logger
func Fatal(msg string, keysAndValues ...interface{}) {
	Global().Fatal(msg, keysAndValues...)
}

// With creates a child logger with fields using global logger
func With(keysAndValues ...interface{}) Logger {
	return Global().With(keysAndValues...)
}

// Named creates a named logger using global logger
func Named(name string) Logger {
	return Global().Named(name)
}
