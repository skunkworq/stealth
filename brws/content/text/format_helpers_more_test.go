package langextract

import "testing"

func TestNormalizeYAMLAdditionalBranches(t *testing.T) {
	t.Parallel()

	in := map[string]any{
		"a": map[any]any{
			"b": []any{
				map[any]any{"c": 1},
			},
		},
	}
	out := normalizeYAML(in)
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any output, got %T", out)
	}
	a, ok := m["a"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map[string]any at key a")
	}
	items, ok := a["b"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected normalized list at key b, got %T", a["b"])
	}
	item0, ok := items[0].(map[string]any)
	if !ok || item0["c"] != 1 {
		t.Fatalf("expected normalized map item, got %v", items[0])
	}
	if got := normalizeYAML(123); got != 123 {
		t.Fatalf("expected scalar passthrough, got %v", got)
	}
}

func TestOrderedValueToMapValueBranches(t *testing.T) {
	t.Parallel()

	nested := newOrderedObject()
	nested.Index["y"] = 0
	nested.Pairs = append(nested.Pairs, orderedKV{Key: "y", Value: 2})

	root := newOrderedObject()
	root.Index["x"] = 0
	root.Pairs = append(root.Pairs, orderedKV{Key: "x", Value: nested})
	root.Index["list"] = 1
	root.Pairs = append(root.Pairs, orderedKV{Key: "list", Value: []any{nested, 3}})

	got := orderedValueToMapValue(root)
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map output from ordered object, got %T", got)
	}
	if xm, ok := m["x"].(map[string]any); !ok || xm["y"] != 2 {
		t.Fatalf("expected nested map conversion, got %v", m["x"])
	}
	list, ok := m["list"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("expected converted list, got %v", m["list"])
	}
	if item0, ok := list[0].(map[string]any); !ok || item0["y"] != 2 {
		t.Fatalf("expected list nested conversion, got %v", list[0])
	}
	if list[1] != 3 {
		t.Fatalf("expected scalar passthrough in list, got %v", list[1])
	}

	if got := orderedValueToMapValue("plain"); got != "plain" {
		t.Fatalf("expected scalar passthrough for non-collection, got %v", got)
	}
}

func TestParseYAMLOrderedEmptyAndInvalid(t *testing.T) {
	t.Parallel()

	got, err := parseYAMLOrdered("")
	if err != nil {
		t.Fatalf("expected empty yaml to parse as nil, got err=%v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty yaml, got %T", got)
	}

	if _, err := parseYAMLOrdered(": bad"); err == nil {
		t.Fatalf("expected invalid yaml error")
	}
}
