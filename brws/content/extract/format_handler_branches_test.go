package extract

import "testing"

func TestParseOutputOrderedBranchErrors(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseFences = false
	handler.UseWrapper = true
	handler.WrapperKey = ExtractionKey

	if _, err := handler.ParseOutputOrdered("", false); err == nil {
		t.Fatalf("expected empty input error")
	}

	if _, err := handler.ParseOutputOrdered(`{"foo":[]}`, false); err == nil {
		t.Fatalf("expected missing wrapper key error")
	}

	if _, err := handler.ParseOutputOrdered(`{"extractions":{"person":"Alice"}}`, false); err == nil {
		t.Fatalf("expected sequence/list error for wrapper value")
	}

	if _, err := handler.ParseOutputOrdered(`{"extractions":[1]}`, false); err == nil {
		t.Fatalf("expected item mapping type error")
	}

	if _, err := handler.ParseOutputOrdered(`{"extractions":[{"":"x"}]}`, false); err == nil {
		t.Fatalf("expected empty key validation error")
	}
}

func TestParseOutputOrderedTopLevelListModes(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseFences = false

	handler.UseWrapper = true
	handler.AllowTopLevelList = true
	if _, err := handler.ParseOutputOrdered(`[{"person":"Alice"}]`, true); err == nil {
		t.Fatalf("expected strict wrapper list rejection")
	}

	handler.UseWrapper = false
	handler.AllowTopLevelList = false
	if _, err := handler.ParseOutputOrdered(`[{"person":"Alice"}]`, false); err == nil {
		t.Fatalf("expected top-level list disallowed error")
	}
}

func TestParseOutputOrderedNilParsedBranches(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeYAML
	handler.UseFences = false

	handler.UseWrapper = true
	if _, err := handler.ParseOutputOrdered("null", false); err == nil {
		t.Fatalf("expected wrapper-required error for nil payload")
	}

	handler.UseWrapper = false
	if _, err := handler.ParseOutputOrdered("null", false); err == nil {
		t.Fatalf("expected list-or-dict error for nil payload without wrapper")
	}
}

func TestFormatHandlerExtractContentFenceBranches(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseFences = true

	handler.StrictFences = true
	if _, err := handler.extractContent("```json\n{}\n```\n```json\n{}\n```"); err == nil {
		t.Fatalf("expected strict multiple-fence error")
	}
	if _, err := handler.extractContent("{}"); err == nil {
		t.Fatalf("expected strict missing-fence error")
	}

	handler.StrictFences = false
	if _, err := handler.extractContent("```yaml\nx: 1\n```\n```yaml\ny: 2\n```"); err == nil {
		t.Fatalf("expected non-strict unsupported multi-fence language error")
	}
}

func TestParseJSONOrderedNumberAndTrailingTokenBranches(t *testing.T) {
	t.Parallel()

	if _, err := parseJSONOrdered(`{"n":9223372036854775807123}`); err != nil {
		t.Fatalf("expected large-number parse fallback to float, got err=%v", err)
	}

	if _, err := parseJSONOrdered(`{"a":1} {"b":2}`); err == nil {
		t.Fatalf("expected trailing token parse error")
	}
}

func TestAsBoolAndParseFormatTypeBranches(t *testing.T) {
	t.Parallel()

	if got, ok := asBool(true); !ok || !got {
		t.Fatalf("expected bool true parse")
	}
	if _, ok := asBool("true"); ok {
		t.Fatalf("expected non-bool to return ok=false")
	}

	if ft, err := parseFormatType(FormatTypeYAML); err != nil || ft != FormatTypeYAML {
		t.Fatalf("expected format type passthrough, got ft=%q err=%v", ft, err)
	}
	if _, err := parseFormatType(123); err == nil {
		t.Fatalf("expected unsupported format_type type error")
	}
}
