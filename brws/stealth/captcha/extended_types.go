// Package captcha provides CAPTCHA solving and generation capabilities.
// Extended provider types are split by provider:
//   - extended_types_recaptcha.go  — reCAPTCHA v2
//   - extended_types_hcaptcha.go   — hCaptcha
//   - extended_types_turnstile.go  — Cloudflare Turnstile
//   - extended_types_text.go       — distorted text CAPTCHA
//   - extended_types_audio.go      — audio CAPTCHA
//   - extended_types_behavioral.go — behavioral analysis
//   - extended_types_canvas.go     — canvas fingerprinting
//   - extended_types_webgl.go      — WebGL interactive CAPTCHA
//   - extended_types_service.go    — CaptchaService (manages all types)
package captcha
