package instrumentation

import (
	"context"
	"errors"
	"testing"
)

func TestHookRegistry_New(t *testing.T) {
	registry := NewHookRegistry()
	if registry == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestHookRegistry_Register(t *testing.T) {
	registry := NewHookRegistry()

	registry.Register("test-hook", func(ctx context.Context) error {
		return nil
	})

	hooks := registry.List()
	if len(hooks) != 1 || hooks[0] != "test-hook" {
		t.Errorf("expected ['test-hook'], got %v", hooks)
	}
}

func TestHookRegistry_Execute(t *testing.T) {
	registry := NewHookRegistry()
	ctx := context.Background()

	executed := false
	registry.Register("test-hook", func(ctx context.Context) error {
		executed = true
		return nil
	})

	err := registry.Execute(ctx, "test-hook")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !executed {
		t.Error("expected hook to be executed")
	}
}

func TestHookRegistry_Execute_MultipleHooks(t *testing.T) {
	registry := NewHookRegistry()
	ctx := context.Background()

	count := 0
	registry.Register("test-hook", func(ctx context.Context) error {
		count++
		return nil
	})
	registry.Register("test-hook", func(ctx context.Context) error {
		count++
		return nil
	})

	registry.Execute(ctx, "test-hook")

	if count != 2 {
		t.Errorf("expected 2 executions, got %d", count)
	}
}

func TestHookRegistry_Execute_NoSuchHook(t *testing.T) {
	registry := NewHookRegistry()
	ctx := context.Background()

	// Should not error
	err := registry.Execute(ctx, "nonexistent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHookRegistry_Execute_Error(t *testing.T) {
	registry := NewHookRegistry()
	ctx := context.Background()

	registry.Register("test-hook", func(ctx context.Context) error {
		return errors.New("hook error")
	})

	err := registry.Execute(ctx, "test-hook")
	if err == nil {
		t.Error("expected error from hook")
	}
}

func TestHookRegistry_Unregister(t *testing.T) {
	registry := NewHookRegistry()

	registry.Register("test-hook", func(ctx context.Context) error {
		return nil
	})

	registry.Unregister("test-hook")

	hooks := registry.List()
	if len(hooks) != 0 {
		t.Errorf("expected empty hooks list, got %v", hooks)
	}
}

func TestDefaultHookRegistry(t *testing.T) {
	registry := DefaultHookRegistry()
	if registry == nil {
		t.Fatal("expected non-nil registry")
	}

	hooks := registry.List()
	if len(hooks) != 18 {
		t.Errorf("expected 18 default hooks, got %d: %v", len(hooks), hooks)
	}
}

func TestHookNames(t *testing.T) {
	// Verify all hook names are defined
	if HookNames.OnBrowserStart == "" {
		t.Error("expected OnBrowserStart to be defined")
	}
	if HookNames.OnBrowserClose == "" {
		t.Error("expected OnBrowserClose to be defined")
	}
	if HookNames.OnRequestStart == "" {
		t.Error("expected OnRequestStart to be defined")
	}
	if HookNames.OnRequestEnd == "" {
		t.Error("expected OnRequestEnd to be defined")
	}
	if HookNames.OnStealthInject == "" {
		t.Error("expected OnStealthInject to be defined")
	}
	if HookNames.OnChallengeDetect == "" {
		t.Error("expected OnChallengeDetect to be defined")
	}
}
