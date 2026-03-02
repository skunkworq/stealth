package log

import "context"

// NopLogger is a no-op logger for testing
type NopLogger struct{}

// NewNopLogger creates a no-op logger
func NewNopLogger() Logger {
	return &NopLogger{}
}

func (n *NopLogger) Debug(_ string, _ ...interface{}) {}
func (n *NopLogger) Info(_ string, _ ...interface{})  {}
func (n *NopLogger) Warn(_ string, _ ...interface{})  {}
func (n *NopLogger) Error(_ string, _ ...interface{}) {}
func (n *NopLogger) Fatal(_ string, _ ...interface{}) {}

func (n *NopLogger) With(_ ...interface{}) Logger {
	return n
}

func (n *NopLogger) Named(_ string) Logger {
	return n
}

func (n *NopLogger) WithContext(_ context.Context) Logger {
	return n
}

func (n *NopLogger) Sync() error {
	return nil
}
