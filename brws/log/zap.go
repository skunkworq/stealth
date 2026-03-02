//go:build !slog_only

package log

import (
	"context"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ZapLogger implements Logger using uber-go/zap
type ZapLogger struct {
	logger *zap.SugaredLogger
	level  Level
}

// ZapConfig configures the zap logger
type ZapConfig struct {
	Level      Level
	JSON       bool
	OutputPath string
}

// NewZapLogger creates a new zap-based logger
func NewZapLogger(config *ZapConfig) (Logger, error) {
	if config == nil {
		config = &ZapConfig{Level: InfoLevel}
	}

	level := toZapLevel(config.Level)

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
	if config.JSON {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	output := os.Stderr
	if config.OutputPath != "" && config.OutputPath != "stderr" {
		f, err := os.OpenFile(config.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		output = f
	}

	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(output),
		level,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	return &ZapLogger{
		logger: logger.Sugar(),
		level:  config.Level,
	}, nil
}

func (l *ZapLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debugw(msg, keysAndValues...)
}

func (l *ZapLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Infow(msg, keysAndValues...)
}

func (l *ZapLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warnw(msg, keysAndValues...)
}

func (l *ZapLogger) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Errorw(msg, keysAndValues...)
}

func (l *ZapLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.logger.Fatalw(msg, keysAndValues...)
}

func (l *ZapLogger) With(keysAndValues ...interface{}) Logger {
	return &ZapLogger{
		logger: l.logger.With(keysAndValues...),
		level:  l.level,
	}
}

func (l *ZapLogger) Named(name string) Logger {
	return &ZapLogger{
		logger: l.logger.Named(name),
		level:  l.level,
	}
}

func (l *ZapLogger) WithContext(ctx context.Context) Logger {
	// Extract context values if needed
	return l
}

func (l *ZapLogger) Sync() error {
	return l.logger.Sync()
}

func toZapLevel(level Level) zapcore.Level {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case FatalLevel:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}
