// Package detection analyzes HTTP requests for bot-detection signals across
// multiple fingerprinting vectors: TLS, HTTP/2, navigator properties, canvas,
// WebGL, audio, timing, behavioral biometrics, and Cloudflare-specific checks.
//
// # Primary entry point
//
// Use [StealthDetector] for all detection work. Create one with [NewStealthDetector]
// and call [StealthDetector.AnalyzeRequest] per request.
//
// # Result types
//
// [StealthDetection] — the top-level result returned by AnalyzeRequest.
// [DetectionVector]  — per-vector score and indicator list inside StealthDetection.
// [CheckReport]      — granular check record within a DetectionVector.
//
// # Supporting types
//
// [CloudflareSignal]    — Cloudflare-specific detection signal (Name, Score).
// [StealthBaseline]     — per-client baseline used for adaptive scoring.
// [DetectorConfig]      — feature flags controlling which vectors are active.
// [AdaptiveScorer]      — updates per-client baselines over time.
// [AdvancedDetection]   — cross-vector correlation checks.
// [IsomorphicAnalyzer]  — detects Node.js/headless environments.
// [BehavioralAnalyzer]  — mouse/keyboard/scroll timing analysis.
// [TimingAnalyzer]      — request-timing anomaly detection.
// [WebGLAnalyzer]       — WebGL renderer and parameter validation.
// [FontAnalyzer]        — available-font set analysis.
// [ScreenAnalyzer]      — screen geometry and DPI consistency checks.
// [PluginAnalyzer]      — navigator.plugins validation.
// [CloudflareDetector]  — Cloudflare cookie and challenge detection.
//
// # Internal implementation types
//
// The following types are implementation details of the above and are not
// part of the public API: audioAnalyzer, audioData, graphicsAnalyzer,
// navigatorAnalyzer. They are intentionally unexported.
package detection
