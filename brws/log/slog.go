package log

import (
	"context"
	"log/slog"
	"os"
)

// SlogLogger implements Logger using log/slog
type SlogLogger struct {
	logger *slog.Logger
	level  Level
}

// SlogConfig configures the slog logger
type SlogConfig struct {
	Level      Level
	JSON       bool
	OutputPath string
}

// NewSlogLogger creates a new slog-based logger
func NewSlogLogger(config *SlogConfig) (Logger, error) {
	if config == nil {
		config = &SlogConfig{Level: InfoLevel}
	}

	var level slog.Level
	switch config.Level {
	case DebugLevel:
		level = slog.LevelDebug
	case InfoLevel:
		level = slog.LevelInfo
	case WarnLevel:
		level = slog.LevelWarn
	case ErrorLevel:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if config.JSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return &SlogLogger{
		logger: slog.New(handler),
		level:  config.Level,
	}, nil
}

func (l *SlogLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debug(msg, keysAndValues...)
}

func (l *SlogLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

func (l *SlogLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warn(msg, keysAndValues...)
}

func (l *SlogLogger) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, keysAndValues...)
}

func (l *SlogLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, keysAndValues...)
	os.Exit(1)
}

func (l *SlogLogger) With(keysAndValues ...interface{}) Logger {
	return &SlogLogger{
		logger: l.logger.With(keysAndValues...),
		level:  l.level,
	}
}

func (l *SlogLogger) Named(name string) Logger {
	// slog doesn't have named loggers, use With
	return l.With("logger", name)
}

func (l *SlogLogger) WithContext(ctx context.Context) Logger {
	return l
}

func (l *SlogLogger) Sync() error {
	return nil
}
