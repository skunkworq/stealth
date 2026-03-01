// Package instrumentation provides structured logging, tracing, and hooks
// for the stealth browser engine.
package instrumentation

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config for the instrumentation system.
type Config struct {
	// LogLevel sets the minimum log level.
	// Options: debug, info, warn, error
	LogLevel string

	// Output is the log output writer (default: os.Stderr).
	Output *os.File

	// EnableJSONLogging enables JSON formatted logs.
	EnableJSONLogging bool
}

// Logger provides structured logging.
type Logger struct {
	*zap.SugaredLogger

	config *Config
}

// NewLogger creates a new structured logger.
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = &Config{LogLevel: "info"}
	}

	var level zapcore.Level

	switch config.LogLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if config.EnableJSONLogging {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	output := os.Stderr
	if config.Output != nil {
		output = config.Output
	}

	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(output),
		level,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	return &Logger{
		SugaredLogger: logger.Sugar(),
		config:        config,
	}, nil
}

// Flush flushes any buffered log entries.
func (l *Logger) Flush() error {
	return l.Sync()
}

// Default returns a package-level default logger.
func Default() *Logger {
	logger, _ := NewLogger(&Config{LogLevel: "info"})
	return logger
}

var (
	defaultLogger *Logger
	defaultOnce   sync.Once
)

// GetDefault returns the default logger.
func GetDefault() *Logger {
	if defaultLogger == nil {
		defaultLogger, _ = NewLogger(&Config{LogLevel: "info"})
	}
	return defaultLogger
}

// InitDefault initializes the default logger.
func InitDefault(config *Config) {
	defaultOnce.Do(func() {
		defaultLogger, _ = NewLogger(config)
	})
}

// Debug logs a debug message.
func Debug(msg string, args ...interface{}) {
	GetDefault().Debugw(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...interface{}) {
	GetDefault().Infow(msg, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...interface{}) {
	GetDefault().Warnw(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...interface{}) {
	GetDefault().Errorw(msg, args...)
}

// Fatal logs a fatal message.
func Fatal(msg string, args ...interface{}) {
	GetDefault().Fatalw(msg, args...)
}

// With creates a child logger with additional fields.
func With(fields ...interface{}) *Logger {
	return &Logger{
		SugaredLogger: GetDefault().With(fields...),
	}
}

// Named creates a named logger.
func Named(name string) *Logger {
	return &Logger{
		SugaredLogger: GetDefault().Named(name),
	}
}
