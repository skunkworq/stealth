// Package extract is stealth's grounded verbatim extraction capability.
//
// A SourceDocument (text + provenance) flows through Extractors (deterministic
// regex / structured-data harvesters and a langextract-backed LLM extractor).
// Every Candidate they propose is funneled through the Validator, which emits a
// Field only when the value is present in the source text under the field's
// class normalisation (identifier/email/url/freetext). A value the LLM invents
// is dropped — the zero-hallucination guarantee. This package owns no API keys
// and no business logic; higher-order extraction (which fields to pursue,
// cross-source reasoning) lives in brandbrain.
package extract
