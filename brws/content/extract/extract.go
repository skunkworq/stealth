package extract

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Extract performs extraction and returns semantic-first output.
//
// This is the preferred entrypoint for most callers.
// It is equivalent to calling ExtractRaw and converting with ToSemantic.
func Extract(ctx context.Context, input string, opts ...Option) (SemanticResult, error) {
	raw, err := ExtractRaw(ctx, input, opts...)
	if err != nil {
		return SemanticResult{}, err
	}
	return ToSemantic(raw), nil
}

// ExtractRaw performs extraction and returns raw langextract-style output.
//
// Required:
//   - non-empty input text (or URL when URL fetching is enabled)
//   - at least one example via WithExamples
//
// Provider/model precedence:
//   - WithModel wins over all other provider settings.
//   - WithModelConfig/WithConfig wins over WithModelID/WithProvider* options.
//   - Otherwise provider/model is resolved from WithModelID and model/provider hints.
func ExtractRaw(ctx context.Context, input string, opts ...Option) (*RawExtractionResult, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("input text is empty")
	}

	options := defaultExtractOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.Tokenizer == nil {
		options.Tokenizer = DefaultTokenizer
	}
	if options.ExtractionPasses <= 0 {
		options.ExtractionPasses = 1
	}
	if options.BatchLength <= 0 {
		options.BatchLength = 1
	}
	if options.MaxCharBuffer <= 0 {
		options.MaxCharBuffer = defaultMaxCharBuffer
	}
	if len(options.Examples) == 0 {
		return nil, fmt.Errorf("examples are required for reliable extraction")
	}
	if options.PromptValidation != PromptValidationOff {
		report := ValidatePromptExamples(options.Examples, options.Tokenizer)
		if options.PromptValidation == PromptValidationError {
			if err := report.ErrorForMode(options.PromptValidationStrict); err != nil {
				return nil, err
			}
		}
	}

	text := input
	if options.FetchURLs && IsURL(input) {
		timeout := time.Duration(options.FetchTimeoutSeconds) * time.Second
		downloaded, err := DownloadTextFromURL(ctx, input, timeout)
		if err != nil {
			return nil, err
		}
		text = downloaded
	}

	model, providerName, modelID, err := resolveExtractor(ctx, options)
	if err != nil {
		return nil, err
	}
	model.SetFormatType(options.FormatType)
	if options.FenceOutput != nil {
		model.SetFenceOutput(*options.FenceOutput)
	}

	if options.UseSchemaConstraints {
		model.SetSchema(buildSchemaFromExamples(options.Examples))
	}

	formatHandler, remainingResolverParams, err := FormatHandlerFromResolverParams(
		options.ResolverParams,
		options.FormatType,
		model.RequiresFenceOutput(),
	)
	if err != nil {
		return nil, err
	}

	resolver, alignOptions, suppressParseErrors, err := buildResolver(formatHandler, remainingResolverParams, options.Tokenizer)
	if err != nil {
		return nil, err
	}

	template := PromptTemplateStructured{
		Description: options.PromptDescription,
		Examples:    append([]ExampleData{}, options.Examples...),
	}
	promptGen := newQAPromptGenerator(template, formatHandler)

	tokenized := options.Tokenizer.Tokenize(text)
	document := &Document{
		Text:              text,
		DocumentID:        "document-1",
		AdditionalContext: options.AdditionalContext,
		TokenizedText:     &tokenized,
	}

	inferOptions := map[string]any{}
	for k, v := range options.ModelParams {
		inferOptions[k] = v
	}
	if options.Temperature != nil {
		inferOptions["temperature"] = *options.Temperature
	}
	if options.MaxWorkers > 0 {
		maxWorkers := options.MaxWorkers
		if options.BatchLength > 0 && maxWorkers > options.BatchLength {
			maxWorkers = options.BatchLength
		}
		inferOptions["max_workers"] = maxWorkers
	}

	allPassExtractions := make([][]Extraction, 0, options.ExtractionPasses)
	for pass := 0; pass < options.ExtractionPasses; pass++ {
		promptBuilder := newContextAwarePromptBuilder(promptGen, options.ContextWindowChars)
		chunkIter, err := NewChunkIterator(tokenized, options.MaxCharBuffer, options.Tokenizer, document)
		if err != nil {
			return nil, err
		}
		batches, err := MakeBatchesOfTextChunk(chunkIter, options.BatchLength)
		if err != nil {
			return nil, err
		}

		passExtractions := make([]Extraction, 0)
		for _, batch := range batches {
			if len(batch) == 0 {
				continue
			}

			prompts := make([]string, 0, len(batch))
			for _, chunk := range batch {
				chunkText, err := chunk.ChunkText()
				if err != nil {
					return nil, err
				}
				prompt, err := promptBuilder.BuildPrompt(chunkText, chunk.DocumentID(), chunk.AdditionalContext())
				if err != nil {
					return nil, err
				}
				prompts = append(prompts, prompt)
			}

			scoredOutputs, err := model.Infer(ctx, prompts, inferOptions)
			if err != nil {
				return nil, err
			}
			if len(scoredOutputs) == 0 {
				return nil, &InferenceOutputError{newErr("extract", "no scored outputs from language model")}
			}

			limit := len(batch)
			if len(scoredOutputs) < limit {
				limit = len(scoredOutputs)
			}

			for i := 0; i < limit; i++ {
				if len(scoredOutputs[i]) == 0 {
					return nil, &InferenceOutputError{newErr("extract", "empty scored output entry")}
				}

				chunk := batch[i]
				chunkText, err := chunk.ChunkText()
				if err != nil {
					return nil, err
				}
				chunkChars, err := chunk.CharInterval()
				if err != nil {
					return nil, err
				}

				resolvedExtractions, err := resolver.Resolve(scoredOutputs[i][0].Output, suppressParseErrors)
				if err != nil {
					return nil, err
				}
				aligned := resolver.Align(
					resolvedExtractions,
					chunkText,
					chunk.TokenInterval.StartIndex,
					chunkChars.StartPos,
					alignOptions,
				)
				passExtractions = append(passExtractions, aligned...)
			}
		}

		allPassExtractions = append(allPassExtractions, passExtractions)
	}

	merged := mergeNonOverlappingExtractions(allPassExtractions)
	return &RawExtractionResult{
		DocumentID:      document.id(),
		Text:            text,
		Extractions:     merged,
		TokenizedText:   document.TokenizedText,
		DocumentCount:   1,
		PassesPerformed: options.ExtractionPasses,
		ModelID:         modelID,
		Provider:        providerName,
		Metadata: map[string]any{
			"format_type":  options.FormatType,
			"fence_output": model.RequiresFenceOutput(),
		},
	}, nil
}

func resolveExtractor(ctx context.Context, options extractOptions) (Extractor, string, string, error) {
	if options.Model != nil {
		modelID := options.ModelID
		if options.Config != nil && strings.TrimSpace(options.Config.ModelID) != "" {
			modelID = options.Config.ModelID
		}
		return options.Model, "custom", modelID, nil
	}

	cfg := ModelConfig{
		ModelID:        options.ModelID,
		Provider:       options.ProviderHint,
		ProviderClass:  "",
		ProviderKwargs: map[string]any{},
	}
	for k, v := range options.ModelParams {
		cfg.ProviderKwargs[k] = v
	}
	if options.Temperature != nil {
		if _, exists := cfg.ProviderKwargs["temperature"]; !exists {
			cfg.ProviderKwargs["temperature"] = *options.Temperature
		}
	}

	if options.Config != nil {
		cfg = ModelConfig{
			ModelID:        options.Config.ModelID,
			Provider:       options.Config.Provider,
			ProviderClass:  options.Config.ProviderClass,
			ProviderKwargs: map[string]any{},
		}
		for k, v := range options.Config.ProviderKwargs {
			cfg.ProviderKwargs[k] = v
		}
		// Runtime model params override config kwargs.
		for k, v := range options.ModelParams {
			cfg.ProviderKwargs[k] = v
		}
		if options.Temperature != nil {
			cfg.ProviderKwargs["temperature"] = *options.Temperature
		}
	}
	if strings.TrimSpace(cfg.ModelID) == "" {
		cfg.ModelID = defaultModelID
	}

	providerHint := firstNonEmpty(cfg.Provider, cfg.ProviderClass, options.ProviderHint)
	factory, providerName, err := resolveProviderFactory(cfg.ModelID, providerHint)
	if err != nil {
		return nil, "", "", err
	}

	model, err := factory(ctx, cfg)
	if err != nil {
		return nil, "", "", err
	}
	return model, providerName, cfg.ModelID, nil
}

func buildResolver(
	formatHandler *FormatHandler,
	resolverParams map[string]any,
	tokenizer Tokenizer,
) (*Resolver, AlignOptions, bool, error) {
	resolver := NewResolver(formatHandler)
	if v, ok := resolverParams["extraction_index_suffix"]; ok {
		if s, ok := v.(string); ok {
			resolver.ExtractionIndexSuffix = s
			delete(resolverParams, "extraction_index_suffix")
		} else {
			return nil, AlignOptions{}, false, fmt.Errorf("extraction_index_suffix must be a string")
		}
	}
	if v, ok := resolverParams["strict"]; ok {
		if b, ok := asBool(v); ok {
			resolver.Strict = b
			delete(resolverParams, "strict")
		}
	}

	alignOptions := DefaultAlignOptions()
	alignOptions.Tokenizer = tokenizer

	if v, ok := resolverParams["enable_fuzzy_alignment"]; ok {
		if b, ok := asBool(v); ok {
			alignOptions.EnableFuzzyAlignment = b
		}
		delete(resolverParams, "enable_fuzzy_alignment")
	}
	if v, ok := resolverParams["accept_match_lesser"]; ok {
		if b, ok := asBool(v); ok {
			alignOptions.AcceptMatchLesser = b
		}
		delete(resolverParams, "accept_match_lesser")
	}
	if v, ok := resolverParams["fuzzy_alignment_threshold"]; ok {
		switch t := v.(type) {
		case float64:
			alignOptions.FuzzyAlignmentThreshold = t
		case float32:
			alignOptions.FuzzyAlignmentThreshold = float64(t)
		case int:
			alignOptions.FuzzyAlignmentThreshold = float64(t)
		default:
			return nil, AlignOptions{}, false, fmt.Errorf("fuzzy_alignment_threshold must be numeric")
		}
		delete(resolverParams, "fuzzy_alignment_threshold")
	}

	suppressParseErrors := false
	if v, ok := resolverParams["suppress_parse_errors"]; ok {
		if b, ok := asBool(v); ok {
			suppressParseErrors = b
		}
		delete(resolverParams, "suppress_parse_errors")
	}

	if len(resolverParams) > 0 {
		unknown := make([]string, 0, len(resolverParams))
		for k := range resolverParams {
			unknown = append(unknown, k)
		}
		return nil, AlignOptions{}, false, fmt.Errorf("unknown key(s) in resolver_params: %s", strings.Join(unknown, ", "))
	}

	return resolver, alignOptions, suppressParseErrors, nil
}

func buildSchemaFromExamples(examples []ExampleData) map[string]any {
	classes := map[string]struct{}{}
	for _, ex := range examples {
		for _, e := range ex.Extractions {
			if strings.TrimSpace(e.ExtractionClass) != "" {
				classes[e.ExtractionClass] = struct{}{}
			}
		}
	}
	keys := make([]string, 0, len(classes))
	for k := range classes {
		keys = append(keys, k)
	}

	return map[string]any{
		"type":             "object",
		"wrapper_key":      ExtractionKey,
		"attribute_suffix": AttributeSuffix,
		"classes":          keys,
	}
}

func mergeNonOverlappingExtractions(allPassExtractions [][]Extraction) []Extraction {
	if len(allPassExtractions) == 0 {
		return nil
	}
	if len(allPassExtractions) == 1 {
		out := append([]Extraction{}, allPassExtractions[0]...)
		return out
	}

	merged := append([]Extraction{}, allPassExtractions[0]...)
	for passIdx := 1; passIdx < len(allPassExtractions); passIdx++ {
		for _, ext := range allPassExtractions[passIdx] {
			overlaps := false
			if ext.CharInterval != nil {
				for _, existing := range merged {
					if existing.CharInterval != nil && extractionsOverlap(ext, existing) {
						overlaps = true
						break
					}
				}
			}
			if !overlaps {
				merged = append(merged, ext)
			}
		}
	}
	return merged
}

func extractionsOverlap(a, b Extraction) bool {
	if a.CharInterval == nil || b.CharInterval == nil {
		return false
	}
	startA, endA := a.CharInterval.StartPos, a.CharInterval.EndPos
	startB, endB := b.CharInterval.StartPos, b.CharInterval.EndPos
	return startA < endB && startB < endA
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
