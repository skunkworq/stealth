package extract

import "context"

// FormatType denotes extraction output format.
type FormatType string

const (
	// FormatTypeJSON requests JSON-formatted model output and parsing.
	FormatTypeJSON FormatType = "json"
	// FormatTypeYAML requests YAML-formatted model output and parsing.
	FormatTypeYAML FormatType = "yaml"
)

// AlignmentStatus indicates how an extraction aligned to source text.
type AlignmentStatus string

const (
	// AlignmentExact means the extraction text matched source text exactly.
	AlignmentExact AlignmentStatus = "match_exact"
	// AlignmentGreater means alignment consumed a superset span.
	AlignmentGreater AlignmentStatus = "match_greater"
	// AlignmentLesser means alignment matched a subset/partial span.
	AlignmentLesser AlignmentStatus = "match_lesser"
	// AlignmentFuzzy means alignment succeeded via fuzzy token similarity.
	AlignmentFuzzy AlignmentStatus = "match_fuzzy"
)

// ExtractionKey is the default wrapper key used in prompt/model outputs.
const ExtractionKey = "extractions"

// AttributeSuffix is the suffix used for attribute fields in extraction outputs.
const AttributeSuffix = "_attributes"

// ScoredOutput is a single scored completion for a single prompt.
type ScoredOutput struct {
	Score  float64
	Output string
}

// CharInterval is a character span in source text.
type CharInterval struct {
	StartPos int
	EndPos   int
}

// TokenInterval is a token span in source tokenized text.
type TokenInterval struct {
	StartIndex int
	EndIndex   int
}

// Extraction represents a single semantic extraction.
type Extraction struct {
	ExtractionClass string
	ExtractionText  string
	CharInterval    *CharInterval
	TokenInterval   *TokenInterval
	Alignment       AlignmentStatus
	ExtractionIndex int
	GroupIndex      int
	Description     string
	Attributes      map[string]any
}

// CharStart returns the extraction character start offset, or -1 when unavailable.
func (e Extraction) CharStart() int {
	if e.CharInterval == nil {
		return -1
	}
	return e.CharInterval.StartPos
}

// CharEnd returns the extraction character end offset, or -1 when unavailable.
func (e Extraction) CharEnd() int {
	if e.CharInterval == nil {
		return -1
	}
	return e.CharInterval.EndPos
}

// TokenStart returns the extraction token start offset, or -1 when unavailable.
func (e Extraction) TokenStart() int {
	if e.TokenInterval == nil {
		return -1
	}
	return e.TokenInterval.StartIndex
}

// TokenEnd returns the extraction token end offset, or -1 when unavailable.
func (e Extraction) TokenEnd() int {
	if e.TokenInterval == nil {
		return -1
	}
	return e.TokenInterval.EndIndex
}

// Document is one unit of input text for extraction.
type Document struct {
	Text              string
	DocumentID        string
	AdditionalContext string
	TokenizedText     *TokenizedText
}

func (d Document) id() string {
	if d.DocumentID == "" {
		return "document-1"
	}
	return d.DocumentID
}

// ExampleData provides one few-shot training example.
type ExampleData struct {
	Text        string
	Extractions []Extraction
}

// RawExtractionResult is the raw package output.
type RawExtractionResult struct {
	DocumentID      string
	Text            string
	Extractions     []Extraction
	TokenizedText   *TokenizedText
	DocumentCount   int
	PassesPerformed int
	ModelID         string
	Provider        string
	Metadata        map[string]any
}

// Extractor defines the provider-facing interface.
type Extractor interface {
	Infer(ctx context.Context, prompts []string, options map[string]any) ([][]ScoredOutput, error)
	RequiresFenceOutput() bool
	SetFenceOutput(enabled bool)
	FormatType() FormatType
	SetFormatType(ft FormatType)
	SetSchema(schema any)
}

// ProviderFactory creates provider instances for model configuration.
type ProviderFactory func(ctx context.Context, cfg ModelConfig) (Extractor, error)

// ModelConfig contains configuration used to build a provider.
type ModelConfig struct {
	// ModelID is the model identifier used by the selected provider.
	ModelID string
	// Provider is the provider registry name (for example "gemini").
	Provider string
	// ProviderClass is an alternate explicit provider selector alias.
	ProviderClass string
	// ProviderKwargs contains provider-specific constructor parameters.
	ProviderKwargs map[string]any
}

// extractOptions drives both Extract and ExtractRaw.
type extractOptions struct {
	PromptDescription      string
	Examples               []ExampleData
	ModelID                string
	Config                 *ModelConfig
	Model                  Extractor
	FormatType             FormatType
	FenceOutput            *bool
	UseSchemaConstraints   bool
	MaxCharBuffer          int
	BatchLength            int
	MaxWorkers             int
	AdditionalContext      string
	ResolverParams         map[string]any
	ModelParams            map[string]any
	Temperature            *float64
	ContextWindowChars     *int
	ExtractionPasses       int
	ShowProgress           bool
	Debug                  bool
	FetchURLs              bool
	Tokenizer              Tokenizer
	PromptValidation       PromptValidationLevel
	PromptValidationStrict bool
	FetchTimeoutSeconds    int
	ProviderHint           string
}

// Option customizes extraction behavior.
type Option func(*extractOptions)

const (
	defaultModelID         = "gemini-2.5-flash"
	defaultPrompt          = "Extract the requested information from the text."
	defaultMaxCharBuffer   = 1000
	defaultBatchLength     = 10
	defaultMaxWorkers      = 10
	defaultExtractionPass  = 1
	defaultFetchURLs       = true
	defaultShowProgress    = false
	defaultSchema          = true
	defaultFetchTimeoutSec = 30
)

// PromptValidationLevel controls prompt-example validation.
type PromptValidationLevel int

const (
	// PromptValidationOff disables preflight example validation.
	PromptValidationOff PromptValidationLevel = iota
	// PromptValidationWarning keeps running even when validation finds issues.
	PromptValidationWarning
	// PromptValidationError fails extraction when validation finds disallowed issues.
	PromptValidationError
)

// Ensure option defaults include sane values.
func defaultExtractOptions() extractOptions {
	return extractOptions{
		PromptDescription:      defaultPrompt,
		ModelID:                defaultModelID,
		FormatType:             FormatTypeJSON,
		MaxCharBuffer:          defaultMaxCharBuffer,
		BatchLength:            defaultBatchLength,
		MaxWorkers:             defaultMaxWorkers,
		ResolverParams:         map[string]any{},
		ModelParams:            map[string]any{},
		ExtractionPasses:       defaultExtractionPass,
		ShowProgress:           defaultShowProgress,
		FetchURLs:              defaultFetchURLs,
		UseSchemaConstraints:   defaultSchema,
		Tokenizer:              DefaultTokenizer,
		PromptValidation:       PromptValidationWarning,
		PromptValidationStrict: false,
		FetchTimeoutSeconds:    defaultFetchTimeoutSec,
	}
}

// WithPromptDescription sets the prompt instructions for extraction.
func WithPromptDescription(desc string) Option {
	return func(o *extractOptions) { o.PromptDescription = desc }
}

// WithExamples sets few-shot examples.
func WithExamples(examples ...ExampleData) Option {
	return func(o *extractOptions) {
		o.Examples = append([]ExampleData{}, examples...)
	}
}

// WithModelID sets an explicit model id.
func WithModelID(modelID string) Option {
	return func(o *extractOptions) { o.ModelID = modelID }
}

// WithModelConfig sets explicit model config.
func WithModelConfig(cfg ModelConfig) Option {
	return func(o *extractOptions) {
		o.Config = &cfg
	}
}

// WithConfig is an alias for WithModelConfig.
func WithConfig(cfg ModelConfig) Option { return WithModelConfig(cfg) }

// WithModel sets explicit provider instance.
func WithModel(model Extractor) Option {
	return func(o *extractOptions) { o.Model = model }
}

// WithFormat sets output parsing format.
func WithFormat(format FormatType) Option {
	return func(o *extractOptions) { o.FormatType = format }
}

// WithFenceOutput forces fence behavior expected by the model output parser.
func WithFenceOutput(enabled bool) Option {
	return func(o *extractOptions) { o.FenceOutput = &enabled }
}

// WithMaxCharBuffer sets chunk size in characters.
func WithMaxCharBuffer(v int) Option {
	return func(o *extractOptions) { o.MaxCharBuffer = v }
}

// WithBatchLength sets inference batch size.
func WithBatchLength(v int) Option {
	return func(o *extractOptions) { o.BatchLength = v }
}

// WithMaxWorkers sets model concurrency hints.
//
// Effective workers are capped at batch length.
func WithMaxWorkers(v int) Option {
	return func(o *extractOptions) { o.MaxWorkers = v }
}

// WithAdditionalContext sets document-level extra context.
func WithAdditionalContext(v string) Option {
	return func(o *extractOptions) { o.AdditionalContext = v }
}

// WithResolverParams sets format and alignment resolver parameters.
//
// Common keys:
//   - "strict" (bool)
//   - "suppress_parse_errors" (bool)
//   - "extraction_index_suffix" (string)
//   - "enable_fuzzy_alignment" (bool)
//   - "accept_match_lesser" (bool)
//   - "fuzzy_alignment_threshold" (number)
//   - format handler keys such as "format_type", "fence_output",
//     "strict_fences", "require_extractions_key", "attribute_suffix"
func WithResolverParams(v map[string]any) Option {
	return func(o *extractOptions) {
		o.ResolverParams = map[string]any{}
		for key, val := range v {
			o.ResolverParams[key] = val
		}
	}
}

// WithResolverParameters is an alias for WithResolverParams.
func WithResolverParameters(v map[string]any) Option { return WithResolverParams(v) }

// WithModelParams sets provider-specific runtime parameters.
//
// These values are forwarded to provider inference calls and can override
// overlapping values from WithModelConfig(...).ProviderKwargs.
func WithModelParams(v map[string]any) Option {
	return func(o *extractOptions) {
		o.ModelParams = map[string]any{}
		for key, val := range v {
			o.ModelParams[key] = val
		}
	}
}

// WithLanguageModelParams is an alias for WithModelParams.
func WithLanguageModelParams(v map[string]any) Option { return WithModelParams(v) }

// WithAPIKey sets provider api_key in model parameters.
func WithAPIKey(v string) Option {
	return func(o *extractOptions) {
		if o.ModelParams == nil {
			o.ModelParams = map[string]any{}
		}
		o.ModelParams["api_key"] = v
	}
}

// WithModelURL sets model/base URL aliases in model parameters.
func WithModelURL(v string) Option {
	return func(o *extractOptions) {
		if o.ModelParams == nil {
			o.ModelParams = map[string]any{}
		}
		o.ModelParams["model_url"] = v
		o.ModelParams["base_url"] = v
	}
}

// WithTemperature sets temperature.
func WithTemperature(v float64) Option {
	return func(o *extractOptions) { o.Temperature = &v }
}

// WithContextWindowChars sets context carry-over for chunked extraction.
func WithContextWindowChars(v int) Option {
	return func(o *extractOptions) { o.ContextWindowChars = &v }
}

// WithExtractionPasses enables multi-pass extraction.
func WithExtractionPasses(v int) Option {
	return func(o *extractOptions) { o.ExtractionPasses = v }
}

// WithFetchURLs toggles URL fetch behavior when input is a URL string.
func WithFetchURLs(v bool) Option {
	return func(o *extractOptions) { o.FetchURLs = v }
}

// WithTokenizer sets the tokenizer implementation used for chunking and alignment.
func WithTokenizer(t Tokenizer) Option {
	return func(o *extractOptions) { o.Tokenizer = t }
}

// WithNoSchemaConstraints disables parser/schema constraints.
func WithNoSchemaConstraints() Option {
	return func(o *extractOptions) { o.UseSchemaConstraints = false }
}

// WithFetchTimeoutSeconds sets timeout used when downloading URLs.
func WithFetchTimeoutSeconds(v int) Option {
	return func(o *extractOptions) { o.FetchTimeoutSeconds = v }
}

// WithProviderHint forces the provider name.
func WithProviderHint(name string) Option {
	return func(o *extractOptions) { o.ProviderHint = name }
}

// WithProvider is an alias for WithProviderHint.
func WithProvider(name string) Option { return WithProviderHint(name) }

// WithShowProgress toggles progress display.
func WithShowProgress(v bool) Option {
	return func(o *extractOptions) { o.ShowProgress = v }
}

// WithDebug toggles debug behavior.
func WithDebug(v bool) Option {
	return func(o *extractOptions) { o.Debug = v }
}

// WithPromptValidationLevel sets prompt validation behavior.
func WithPromptValidationLevel(v PromptValidationLevel) Option {
	return func(o *extractOptions) { o.PromptValidation = v }
}

// WithPromptValidationStrict controls whether non-exact alignments fail in error mode.
func WithPromptValidationStrict(v bool) Option {
	return func(o *extractOptions) { o.PromptValidationStrict = v }
}

// WithUseSchemaConstraints toggles schema constraints.
func WithUseSchemaConstraints(v bool) Option {
	return func(o *extractOptions) { o.UseSchemaConstraints = v }
}
