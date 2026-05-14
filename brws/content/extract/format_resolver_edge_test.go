package extract

import (
	"strings"
	"testing"
)

func TestFormatHandlerFromResolverParamsLegacyMapping(t *testing.T) {
	t.Parallel()

	handler, leftover, err := FormatHandlerFromResolverParams(
		map[string]any{
			"fence_output":                 false,
			"format_type":                  "yaml",
			"strict_fences":                true,
			"require_extractions_key":      false,
			"extraction_attributes_suffix": "__attrs",
			"unknown_key":                  42,
		},
		FormatTypeJSON,
		true,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler.FormatType != FormatTypeYAML {
		t.Fatalf("expected yaml format, got %q", handler.FormatType)
	}
	if handler.UseFences {
		t.Fatalf("expected fence_output=false")
	}
	if !handler.StrictFences {
		t.Fatalf("expected strict fences to be set")
	}
	if handler.UseWrapper {
		t.Fatalf("expected wrapper disabled")
	}
	if handler.WrapperKey != "" {
		t.Fatalf("expected empty wrapper key when wrapper disabled")
	}
	if handler.AttributeSuffix != "__attrs" {
		t.Fatalf("expected custom attribute suffix, got %q", handler.AttributeSuffix)
	}
	if len(leftover) != 1 || leftover["unknown_key"] != 42 {
		t.Fatalf("unexpected leftover params: %+v", leftover)
	}
}

func TestFormatHandlerFromResolverParamsExplicitHandler(t *testing.T) {
	t.Parallel()

	custom := NewFormatHandler()
	custom.FormatType = FormatTypeYAML
	custom.UseFences = false

	handler, leftover, err := FormatHandlerFromResolverParams(
		map[string]any{
			"format_handler":   custom,
			"fence_output":     true,
			"format_type":      "json",
			"strict_fences":    true,
			"attribute_suffix": "_ignored",
			"extra":            "keep",
		},
		FormatTypeJSON,
		true,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler != custom {
		t.Fatalf("expected explicit format handler to be returned unchanged")
	}
	if len(leftover) != 1 || leftover["extra"] != "keep" {
		t.Fatalf("unexpected leftover params: %+v", leftover)
	}
}

func TestFormatHandlerFromResolverParamsErrors(t *testing.T) {
	t.Parallel()

	_, _, err := FormatHandlerFromResolverParams(
		map[string]any{"format_handler": "not-a-handler"},
		FormatTypeJSON,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "format_handler must be *FormatHandler") {
		t.Fatalf("expected format_handler type error, got: %v", err)
	}

	_, _, err = FormatHandlerFromResolverParams(
		map[string]any{"format_type": "xml"},
		FormatTypeJSON,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported format_type") {
		t.Fatalf("expected unsupported format_type error, got: %v", err)
	}
}

func TestResolverStringToExtractionData(t *testing.T) {
	t.Parallel()

	resolver := NewResolver(NewFormatHandler())
	parsed, err := resolver.StringToExtractionData(`{"extractions":[{"person":"Alice"}]}`)
	if err != nil {
		t.Fatalf("expected parse success: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected one extraction map, got %d", len(parsed))
	}

	if _, err := resolver.StringToExtractionData(""); err == nil {
		t.Fatalf("expected empty input error")
	}
}

func TestNormalizeYAMLAndStringOrJSONHelpers(t *testing.T) {
	t.Parallel()

	normalized := normalizeYAML(map[any]any{
		1: map[any]any{"k": "v"},
	})
	out, ok := normalized.(map[string]any)
	if !ok {
		t.Fatalf("expected normalized map[string]any, got %T", normalized)
	}
	if _, ok := out["1"]; !ok {
		t.Fatalf("expected non-string key to be normalized to string")
	}

	jsonText := stringOrJSON(map[string]any{"a": 1})
	if !strings.Contains(jsonText, `"a":1`) {
		t.Fatalf("unexpected json text: %q", jsonText)
	}
}
