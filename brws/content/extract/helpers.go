package extract

import "encoding/json"

// ParseResponse parses a raw model response into ordered extraction entries.
//
// This helper is useful when you already have model output text and only need
// langextract parsing/resolution behavior without running inference.
func ParseResponse(output string, opts ...Option) ([]Extraction, error) {
	options := defaultExtractOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	handler, params, err := FormatHandlerFromResolverParams(
		options.ResolverParams,
		options.FormatType,
		true,
	)
	if err != nil {
		return nil, err
	}
	resolver, _, suppressParseErrors, err := buildResolver(handler, params, options.Tokenizer)
	if err != nil {
		return nil, err
	}
	return resolver.Resolve(output, suppressParseErrors)
}

// ExtractRawToJSON marshals RawExtractionResult as JSON.
func ExtractRawToJSON(raw *RawExtractionResult) (string, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
