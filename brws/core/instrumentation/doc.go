// Package instrumentation provides structured logging, tracing, FSM, and hooks
// for the stealth browser engine.
//
// # Logger
//
// Use the Logger for structured logging with support for contextual fields:
//
//	log := instrumentation.GetDefault()
//	log.Info("request started", "url", "https://example.com", "attempt", 1)
//
// # Tracing
//
// Use the Tracer for distributed tracing:
//
//	tracer := instrumentation.NewTracer()
//	ctx, span := tracer.StartSpan(ctx, "fetch", instrumentation.SpanKindRequest)
//	defer span.End()
//
// # FSM
//
// Use the FSM for state management:
//
//	fsm := instrumentation.NewRequestFSM()
//	err := fsm.Transition(ctx, instrumentation.RequestEvents.Start)
//
// # Hooks
//
// Use Hooks for extensibility:
//
//	registry := instrumentation.DefaultHookRegistry()
//	registry.Register(instrumentation.HookNames.OnRequestStart, func(ctx context.Context) error {
//	    // custom logic
//	    return nil
//	})
package instrumentation
