// Package collect turns a URL into extract.SourceDocuments. A pluggable
// Renderer (stealth-browser or static HTTP) yields raw HTML; the Collector
// emits two views — cleaned visible text (text/plain) for the LLM/freetext
// path and raw markup (text/html) for the structured extractors (ld+json,
// og/social). All extracted values still pass extract.Validator, so the
// zero-hallucination guarantee holds. collect owns all HTML-awareness; the
// extract package stays free of any HTML dependency.
package collect
