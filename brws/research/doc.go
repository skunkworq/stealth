// Package research contains out-of-band packages used for data collection,
// model training, and offline analysis. It is NOT part of the production
// library.
//
// # Sandboxing contract
//
// Nothing in the four production layers (brws/browser, brws/network,
// brws/stealth, brws/content, brws/crawl, brws/fingerprint, brws/core,
// brws/llm) may import from brws/research. This boundary is intentional:
// research packages are free to use heavy dependencies, external services,
// and experimental APIs that are not appropriate for production use.
//
// # Sub-packages
//
//   - research/bench        — fingerprint and SemanticTree benchmarks
//   - research/captcha      — CAPTCHA ML solver experiments and training data
//   - research/detection    — bot-detection signal analysis and trace lab
//   - research/evasion      — local emulators for Cloudflare and reCAPTCHA challenges
//   - research/fingerprint  — live capture harness and TLS/HTTP training data generation
//   - research/rl           — per-domain strategy storage and RL performance tracking
package research
