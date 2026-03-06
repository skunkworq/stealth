package langextract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type goldenHandlerConfig struct {
	FormatType        string `json:"format_type"`
	UseWrapper        bool   `json:"use_wrapper"`
	WrapperKey        string `json:"wrapper_key"`
	UseFences         bool   `json:"use_fences"`
	StrictFences      bool   `json:"strict_fences"`
	AllowTopLevelList bool   `json:"allow_top_level_list"`
	AttributeSuffix   string `json:"attribute_suffix"`
}

type goldenResolverConfig struct {
	IndexSuffix string `json:"index_suffix"`
	Strict      bool   `json:"strict"`
}

type goldenExtractionExpected struct {
	Class      string         `json:"class"`
	Text       string         `json:"text"`
	Index      int            `json:"index"`
	Group      int            `json:"group"`
	Attributes map[string]any `json:"attributes,omitempty"`

	Alignment  string `json:"alignment,omitempty"`
	TokenStart int    `json:"token_start,omitempty"`
	TokenEnd   int    `json:"token_end,omitempty"`
	CharStart  int    `json:"char_start,omitempty"`
	CharEnd    int    `json:"char_end,omitempty"`
}

type parseResolveGoldenCase struct {
	Name                string                     `json:"name"`
	Handler             goldenHandlerConfig        `json:"handler"`
	Resolver            goldenResolverConfig       `json:"resolver"`
	Input               string                     `json:"input"`
	ExpectErrorContains string                     `json:"expect_error_contains,omitempty"`
	Expected            []goldenExtractionExpected `json:"expected,omitempty"`
}

type parseResolveGoldenFile struct {
	Cases []parseResolveGoldenCase `json:"cases"`
}

type alignmentOptionsFixture struct {
	EnableFuzzyAlignment    bool    `json:"enable_fuzzy_alignment"`
	FuzzyAlignmentThreshold float64 `json:"fuzzy_alignment_threshold"`
	AcceptMatchLesser       bool    `json:"accept_match_lesser"`
}

type alignmentGoldenCase struct {
	Name        string                     `json:"name"`
	SourceText  string                     `json:"source_text"`
	Options     alignmentOptionsFixture    `json:"options"`
	Extractions []goldenExtractionExpected `json:"extractions"`
	Expected    []goldenExtractionExpected `json:"expected"`
}

type alignmentGoldenFile struct {
	Cases []alignmentGoldenCase `json:"cases"`
}

type semanticRawFixture struct {
	DocumentID      string                  `json:"document_id"`
	Text            string                  `json:"text"`
	DocumentCount   int                     `json:"document_count"`
	PassesPerformed int                     `json:"passes_performed"`
	ModelID         string                  `json:"model_id"`
	Provider        string                  `json:"provider"`
	Metadata        map[string]any          `json:"metadata"`
	Extractions     []semanticRawExtraction `json:"extractions"`
}

type semanticRawExtraction struct {
	Class           string         `json:"class"`
	Text            string         `json:"text"`
	Description     string         `json:"description"`
	Attributes      map[string]any `json:"attributes"`
	Alignment       string         `json:"alignment"`
	ExtractionIndex int            `json:"extraction_index"`
	GroupIndex      int            `json:"group_index"`
	CharStart       int            `json:"char_start"`
	CharEnd         int            `json:"char_end"`
	TokenStart      int            `json:"token_start"`
	TokenEnd        int            `json:"token_end"`
}

type semanticGoldenCase struct {
	Name     string             `json:"name"`
	Raw      semanticRawFixture `json:"raw"`
	Expected any                `json:"expected"`
}

type semanticGoldenFile struct {
	Cases []semanticGoldenCase `json:"cases"`
}

func TestGoldenParseResolveContract(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("testdata", "golden", "parse_resolve_golden.json")
	var fixture parseResolveGoldenFile
	loadJSONFixture(t, fixturePath, &fixture)

	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			handler := buildGoldenHandler(t, tc.Handler)
			resolver := NewResolver(handler)
			resolver.ExtractionIndexSuffix = tc.Resolver.IndexSuffix
			resolver.Strict = tc.Resolver.Strict

			got, err := resolver.Resolve(tc.Input, false)
			if tc.ExpectErrorContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.ExpectErrorContains)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.ExpectErrorContains)) {
					t.Fatalf("expected error containing %q, got %q", tc.ExpectErrorContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve failed: %v", err)
			}

			if len(got) != len(tc.Expected) {
				t.Fatalf("expected %d extractions, got %d", len(tc.Expected), len(got))
			}
			for i := range tc.Expected {
				exp := tc.Expected[i]
				actual := got[i]
				if actual.ExtractionClass != exp.Class ||
					actual.ExtractionText != exp.Text ||
					actual.ExtractionIndex != exp.Index ||
					actual.GroupIndex != exp.Group {
					t.Fatalf("unexpected extraction[%d]: got=%+v expected=%+v", i, actual, exp)
				}
				if !jsonEqual(actual.Attributes, exp.Attributes) {
					t.Fatalf("unexpected attributes[%d]: got=%v expected=%v", i, actual.Attributes, exp.Attributes)
				}
			}
		})
	}
}

func TestGoldenAlignmentContract(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("testdata", "golden", "alignment_golden.json")
	var fixture alignmentGoldenFile
	loadJSONFixture(t, fixturePath, &fixture)

	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			extractions := make([]Extraction, 0, len(tc.Extractions))
			for _, ex := range tc.Extractions {
				extractions = append(extractions, Extraction{
					ExtractionClass: ex.Class,
					ExtractionText:  ex.Text,
				})
			}

			opts := DefaultAlignOptions()
			opts.EnableFuzzyAlignment = tc.Options.EnableFuzzyAlignment
			opts.FuzzyAlignmentThreshold = tc.Options.FuzzyAlignmentThreshold
			opts.AcceptMatchLesser = tc.Options.AcceptMatchLesser

			resolver := NewResolver(NewFormatHandler())
			got := resolver.Align(extractions, tc.SourceText, 0, 0, opts)
			if len(got) != len(tc.Expected) {
				t.Fatalf("expected %d aligned extractions, got %d", len(tc.Expected), len(got))
			}
			for i := range tc.Expected {
				exp := tc.Expected[i]
				actual := got[i]
				if actual.ExtractionClass != exp.Class || actual.ExtractionText != exp.Text {
					t.Fatalf("unexpected extraction[%d] class/text: got=%+v expected=%+v", i, actual, exp)
				}
				if string(actual.Alignment) != exp.Alignment {
					t.Fatalf("unexpected extraction[%d] alignment: got=%q expected=%q", i, actual.Alignment, exp.Alignment)
				}
				if actual.TokenInterval == nil || actual.CharInterval == nil {
					t.Fatalf("expected intervals for extraction[%d], got token=%v char=%v", i, actual.TokenInterval, actual.CharInterval)
				}
				if actual.TokenInterval.StartIndex != exp.TokenStart ||
					actual.TokenInterval.EndIndex != exp.TokenEnd ||
					actual.CharInterval.StartPos != exp.CharStart ||
					actual.CharInterval.EndPos != exp.CharEnd {
					t.Fatalf("unexpected extraction[%d] intervals: got token=%+v char=%+v expected token=[%d,%d] char=[%d,%d]",
						i,
						*actual.TokenInterval,
						*actual.CharInterval,
						exp.TokenStart, exp.TokenEnd, exp.CharStart, exp.CharEnd,
					)
				}
			}
		})
	}
}

func TestGoldenSemanticMappingContract(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("testdata", "golden", "semantic_mapping_golden.json")
	var fixture semanticGoldenFile
	loadJSONFixture(t, fixturePath, &fixture)

	for _, tc := range fixture.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			raw := &RawExtractionResult{
				DocumentID:      tc.Raw.DocumentID,
				Text:            tc.Raw.Text,
				DocumentCount:   tc.Raw.DocumentCount,
				PassesPerformed: tc.Raw.PassesPerformed,
				ModelID:         tc.Raw.ModelID,
				Provider:        tc.Raw.Provider,
				Metadata:        tc.Raw.Metadata,
				Extractions:     make([]Extraction, 0, len(tc.Raw.Extractions)),
			}
			for _, ex := range tc.Raw.Extractions {
				raw.Extractions = append(raw.Extractions, Extraction{
					ExtractionClass: ex.Class,
					ExtractionText:  ex.Text,
					Description:     ex.Description,
					Attributes:      ex.Attributes,
					Alignment:       AlignmentStatus(ex.Alignment),
					ExtractionIndex: ex.ExtractionIndex,
					GroupIndex:      ex.GroupIndex,
					CharInterval: &CharInterval{
						StartPos: ex.CharStart,
						EndPos:   ex.CharEnd,
					},
					TokenInterval: &TokenInterval{
						StartIndex: ex.TokenStart,
						EndIndex:   ex.TokenEnd,
					},
				})
			}

			got := ToSemantic(raw)
			var gotAny any = got
			if !jsonEqual(gotAny, tc.Expected) {
				gotJSON, _ := json.MarshalIndent(gotAny, "", "  ")
				expJSON, _ := json.MarshalIndent(tc.Expected, "", "  ")
				t.Fatalf("semantic mapping mismatch\ngot:\n%s\nexpected:\n%s", string(gotJSON), string(expJSON))
			}
		})
	}
}

func buildGoldenHandler(t *testing.T, cfg goldenHandlerConfig) *FormatHandler {
	t.Helper()

	ft, err := parseFormatType(cfg.FormatType)
	if err != nil {
		t.Fatalf("invalid format type %q: %v", cfg.FormatType, err)
	}
	handler := NewFormatHandler()
	handler.FormatType = ft
	handler.UseWrapper = cfg.UseWrapper
	handler.WrapperKey = cfg.WrapperKey
	handler.UseFences = cfg.UseFences
	handler.StrictFences = cfg.StrictFences
	handler.AllowTopLevelList = cfg.AllowTopLevelList
	if cfg.AttributeSuffix != "" {
		handler.AttributeSuffix = cfg.AttributeSuffix
	}
	return handler
}

func loadJSONFixture(t *testing.T, fixturePath string, out any) {
	t.Helper()
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", fixturePath, err)
	}
	if err := json.Unmarshal(content, out); err != nil {
		t.Fatalf("failed to unmarshal fixture %s: %v", fixturePath, err)
	}
}

func jsonEqual(a, b any) bool {
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	var an any
	var bn any
	if err := json.Unmarshal(aj, &an); err != nil {
		return false
	}
	if err := json.Unmarshal(bj, &bn); err != nil {
		return false
	}
	return deepEqualJSON(an, bn)
}

func deepEqualJSON(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}
