package log

import (
	"context"
)

// contextKey is the key type for storing logger in context
type contextKey struct{}

var loggerKey = &contextKey{}

// FromContext extracts a logger from the context
func FromContext(ctx context.Context) Logger {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}
	return Global()
}

// IntoContext stores a logger in the context
func IntoContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// Ctx logs using the logger from context
func Ctx(ctx context.Context) Logger {
	return FromContext(ctx)
}
