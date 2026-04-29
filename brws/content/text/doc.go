// Package langextract provides a Go-native port of the Python langextract API
// for model-driven structured extraction.
//
// The package is semantic-first:
//
//   - Extract returns a semantic result shape (SemanticResult), suitable for
//     downstream consumers in brws/semantic.
//   - ExtractRaw returns the low-level langextract-style result
//     (RawExtractionResult) for callers that need parser/alignment details.
//
// A minimal extraction flow:
//
//	raw, err := langextract.ExtractRaw(ctx, text,
//		langextract.WithPromptDescription("Extract people and organizations."),
//		langextract.WithExamples(langextract.ExampleData{
//			Text: "Alice is an engineer at Acme.",
//			Extractions: []langextract.Extraction{
//				{ExtractionClass: "person", ExtractionText: "Alice"},
//				{ExtractionClass: "organization", ExtractionText: "Acme"},
//			},
//		}),
//		langextract.WithModelConfig(langextract.ModelConfig{
//			ModelID:  "gemini-2.5-flash",
//			Provider: "gemini",
//			ProviderKwargs: map[string]any{
//				"api_key": "...",
//			},
//		}),
//	)
//
// Core behavior:
//
//   - Examples are required and used for prompt construction (few-shot).
//   - Input can be raw text or a URL. URL fetching is enabled by default and
//     can be disabled with WithFetchURLs(false).
//   - Outputs are parsed (JSON/YAML), resolved into extraction records, then
//     aligned back to source text spans.
//   - Multi-pass extraction is supported with WithExtractionPasses.
//
// Model/provider precedence:
//
//   - WithModel (pre-built extractor) has highest precedence.
//   - WithModelConfig / WithConfig is next.
//   - WithModelID + WithProvider/WithProviderHint + WithModelParams (or
//     WithLanguageModelParams) is the fallback path.
//
// Built-in providers:
//
//   - Gemini
//   - OpenAI
//   - Ollama
//
// Additional providers can be added with RegisterProvider and then selected by
// name through ModelConfig.Provider (or WithProviderHint/WithProvider).
//
// Prompt validation:
//
//   - WithPromptValidationLevel(PromptValidationOff|Warning|Error) controls
//     preflight validation of example alignments.
//   - WithPromptValidationStrict(true) treats non-exact matches as errors when
//     level is PromptValidationError.
package langextract
