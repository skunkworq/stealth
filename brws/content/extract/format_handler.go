package extract

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	fenceRE    = regexp.MustCompile("(?s)```([A-Za-z0-9_+-]+)?(?:\\s*\\n)?(.*?)```")
	thinkTagRE = regexp.MustCompile("(?is)<think>[\\s\\S]*?</think>\\s*")
)

type orderedKV struct {
	Key   string
	Value any
}

type orderedObject struct {
	Pairs []orderedKV
	Index map[string]int
}

func newOrderedObject() orderedObject {
	return orderedObject{
		Pairs: []orderedKV{},
		Index: map[string]int{},
	}
}

func (o orderedObject) get(key string) (any, bool) {
	if idx, ok := o.Index[key]; ok && idx >= 0 && idx < len(o.Pairs) {
		return o.Pairs[idx].Value, true
	}
	return nil, false
}

func (o orderedObject) asMap() map[string]any {
	out := make(map[string]any, len(o.Pairs))
	for _, pair := range o.Pairs {
		out[pair.Key] = orderedValueToMapValue(pair.Value)
	}
	return out
}

// FormatHandler handles JSON/YAML rendering and parsing.
type FormatHandler struct {
	FormatType        FormatType
	UseWrapper        bool
	WrapperKey        string
	UseFences         bool
	AttributeSuffix   string
	StrictFences      bool
	AllowTopLevelList bool
}

// NewFormatHandler builds a handler with package defaults.
func NewFormatHandler() *FormatHandler {
	return &FormatHandler{
		FormatType:        FormatTypeJSON,
		UseWrapper:        true,
		WrapperKey:        ExtractionKey,
		UseFences:         true,
		AttributeSuffix:   AttributeSuffix,
		StrictFences:      false,
		AllowTopLevelList: true,
	}
}

// FormatExtractionExample formats prompt examples as JSON/YAML payload.
func (f *FormatHandler) FormatExtractionExample(extractions []Extraction) (string, error) {
	if f == nil {
		f = NewFormatHandler()
	}

	items := make([]map[string]any, 0, len(extractions))
	for _, ext := range extractions {
		item := map[string]any{
			ext.ExtractionClass: ext.ExtractionText,
		}
		item[ext.ExtractionClass+f.AttributeSuffix] = ext.Attributes
		if ext.Attributes == nil {
			item[ext.ExtractionClass+f.AttributeSuffix] = map[string]any{}
		}
		items = append(items, item)
	}

	var payload any = items
	if f.UseWrapper {
		key := f.WrapperKey
		if key == "" {
			key = ExtractionKey
		}
		payload = map[string]any{key: items}
	}

	var body string
	switch f.FormatType {
	case FormatTypeYAML:
		b, err := yaml.Marshal(payload)
		if err != nil {
			return "", err
		}
		body = string(b)
	default:
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
		body = string(b)
	}

	body = strings.TrimSpace(body)
	if !f.UseFences {
		return body, nil
	}
	return fmt.Sprintf("```%s\n%s\n```", string(f.FormatType), body), nil
}

// ParseOutput parses model output into extraction maps.
func (f *FormatHandler) ParseOutput(text string, strict bool) ([]map[string]any, error) {
	ordered, err := f.ParseOutputOrdered(text, strict)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(ordered))
	for _, item := range ordered {
		out = append(out, item.asMap())
	}
	return out, nil
}

// ParseOutputOrdered parses model output and preserves mapping key order.
func (f *FormatHandler) ParseOutputOrdered(text string, strict bool) ([]orderedObject, error) {
	if f == nil {
		f = NewFormatHandler()
	}
	if strings.TrimSpace(text) == "" {
		return nil, &FormatError{newErr("parse_output", "empty or invalid input string")}
	}

	content, err := f.extractContent(text)
	if err != nil {
		return nil, err
	}

	parsed, err := f.parseWithFallback(content, strict)
	if err != nil {
		return nil, &FormatError{newErr("parse_output", err.Error())}
	}

	if parsed == nil {
		if f.UseWrapper {
			return nil, &FormatError{newErr("parse_output", fmt.Sprintf("content must be a mapping with an %q key", f.wrapperKey()))}
		}
		return nil, &FormatError{newErr("parse_output", "content must be a list of extractions or a dict")}
	}

	requireWrapper := f.wrapperKey() != "" && (f.UseWrapper || strict)
	var items any

	switch v := parsed.(type) {
	case orderedObject:
		if requireWrapper {
			key := f.wrapperKey()
			payload, ok := v.get(key)
			if !ok {
				return nil, &FormatError{newErr("parse_output", fmt.Sprintf("content must contain an %q key", key))}
			}
			items = payload
		} else {
			key := f.wrapperKey()
			if payload, ok := v.get(ExtractionKey); ok {
				items = payload
			} else if key != "" {
				if payload, ok := v.get(key); ok {
					items = payload
				}
			}
			if items == nil {
				items = []any{v}
			}
		}
	case map[string]any:
		return f.ParseOutputOrdered(stringOrJSON(v), strict)
	case []any:
		if requireWrapper && (strict || !f.AllowTopLevelList) {
			return nil, &FormatError{newErr("parse_output", fmt.Sprintf("content must be a mapping with an %q key", f.wrapperKey()))}
		}
		if strict && f.UseWrapper {
			return nil, &FormatError{newErr("parse_output", "strict mode requires a wrapper object")}
		}
		if !f.AllowTopLevelList {
			return nil, &FormatError{newErr("parse_output", "top-level list is not allowed")}
		}
		items = v
	default:
		return nil, &FormatError{newErr("parse_output", fmt.Sprintf("expected list or dict, got %T", parsed))}
	}

	list, ok := items.([]any)
	if !ok {
		return nil, &FormatError{newErr("parse_output", "the extractions must be a sequence (list) of mappings")}
	}

	out := make([]orderedObject, 0, len(list))
	for _, it := range list {
		var orderedItem orderedObject
		switch m := it.(type) {
		case orderedObject:
			orderedItem = m
		case map[string]any:
			orderedItem = orderedObjectFromMap(m)
		default:
			return nil, &FormatError{newErr("parse_output", "each item in the sequence must be a mapping")}
		}
		for _, pair := range orderedItem.Pairs {
			k := pair.Key
			if strings.TrimSpace(k) == "" {
				return nil, &FormatError{newErr("parse_output", "all extraction keys must be strings")}
			}
		}
		out = append(out, orderedItem)
	}
	return out, nil
}

func (f *FormatHandler) wrapperKey() string {
	if !f.UseWrapper {
		return ""
	}
	if strings.TrimSpace(f.WrapperKey) != "" {
		return f.WrapperKey
	}
	return ExtractionKey
}

func (f *FormatHandler) parseWithFallback(content string, strict bool) (any, error) {
	parse := func(raw string) (any, error) {
		switch f.FormatType {
		case FormatTypeYAML:
			out, err := parseYAMLOrdered(raw)
			if err != nil {
				return nil, err
			}
			return out, nil
		default:
			out, err := parseJSONOrdered(raw)
			if err != nil {
				return nil, err
			}
			return out, nil
		}
	}

	parsed, err := parse(content)
	if err == nil {
		return parsed, nil
	}
	if strict {
		return nil, err
	}

	if thinkTagRE.MatchString(content) {
		stripped := strings.TrimSpace(thinkTagRE.ReplaceAllString(content, ""))
		return parse(stripped)
	}
	return nil, err
}

func (f *FormatHandler) extractContent(text string) (string, error) {
	text = strings.TrimSpace(text)
	if !f.UseFences {
		return text, nil
	}

	matches := fenceRE.FindAllStringSubmatch(text, -1)
	valid := make([][]string, 0, len(matches))
	for _, m := range matches {
		lang := strings.ToLower(strings.TrimSpace(m[1]))
		if f.validLanguageTag(lang) {
			valid = append(valid, m)
		}
	}

	if f.StrictFences {
		if len(valid) != 1 {
			if len(valid) == 0 {
				return "", &FormatError{newErr("extract_content", "input string does not contain valid fence markers")}
			}
			return "", &FormatError{newErr("extract_content", "multiple fenced blocks found; expected exactly one")}
		}
		return strings.TrimSpace(valid[0][2]), nil
	}

	if len(valid) == 1 {
		return strings.TrimSpace(valid[0][2]), nil
	}
	if len(valid) > 1 {
		return "", &FormatError{newErr("extract_content", "multiple fenced blocks found; expected exactly one")}
	}

	if len(matches) > 0 {
		if !f.StrictFences && len(matches) == 1 {
			return strings.TrimSpace(matches[0][2]), nil
		}
		return "", &FormatError{newErr("extract_content", fmt.Sprintf("no %s code block found", f.FormatType))}
	}

	return text, nil
}

func (f *FormatHandler) validLanguageTag(lang string) bool {
	if lang == "" {
		return true
	}
	switch f.FormatType {
	case FormatTypeYAML:
		return lang == "yaml" || lang == "yml"
	default:
		return lang == "json"
	}
}

func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, v := range t {
			m[fmt.Sprintf("%v", k)] = normalizeYAML(v)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, v := range t {
			m[k] = normalizeYAML(v)
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = normalizeYAML(t[i])
		}
		return out
	default:
		return t
	}
}

func parseJSONOrdered(raw string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	value, err := parseJSONOrderedValue(dec)
	if err != nil {
		return nil, err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected trailing token %v", tok)
	}
	return value, nil
}

func parseJSONOrderedValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := newOrderedObject()
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("json object key must be string")
				}
				value, err := parseJSONOrderedValue(dec)
				if err != nil {
					return nil, err
				}
				value = canonicalizeOrderedValue(value)
				obj.Index[key] = len(obj.Pairs)
				obj.Pairs = append(obj.Pairs, orderedKV{Key: key, Value: value})
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		case '[':
			out := make([]any, 0)
			for dec.More() {
				value, err := parseJSONOrderedValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, canonicalizeOrderedValue(value))
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			return out, nil
		default:
			return nil, fmt.Errorf("unsupported json delimiter %q", t)
		}
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			fv, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return nil, err
			}
			return fv, nil
		}
		iv, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			fv, ferr := strconv.ParseFloat(s, 64)
			if ferr != nil {
				return nil, err
			}
			return fv, nil
		}
		return int(iv), nil
	default:
		return t, nil
	}
}

func parseYAMLOrdered(raw string) (any, error) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &node); err != nil {
		return nil, err
	}
	if len(node.Content) == 0 {
		return nil, nil
	}
	return yamlNodeToOrdered(node.Content[0]), nil
}

func yamlNodeToOrdered(node *yaml.Node) any {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil
		}
		return yamlNodeToOrdered(node.Content[0])
	case yaml.MappingNode:
		obj := newOrderedObject()
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			key := keyNode.Value
			value := canonicalizeOrderedValue(yamlNodeToOrdered(valNode))
			obj.Index[key] = len(obj.Pairs)
			obj.Pairs = append(obj.Pairs, orderedKV{Key: key, Value: value})
		}
		return obj
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, c := range node.Content {
			out = append(out, canonicalizeOrderedValue(yamlNodeToOrdered(c)))
		}
		return out
	case yaml.ScalarNode:
		var out any
		if err := node.Decode(&out); err != nil {
			return node.Value
		}
		return out
	case yaml.AliasNode:
		return yamlNodeToOrdered(node.Alias)
	default:
		return nil
	}
}

func orderedObjectFromMap(m map[string]any) orderedObject {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	obj := newOrderedObject()
	for _, k := range keys {
		obj.Index[k] = len(obj.Pairs)
		obj.Pairs = append(obj.Pairs, orderedKV{
			Key:   k,
			Value: canonicalizeOrderedValue(m[k]),
		})
	}
	return obj
}

func canonicalizeOrderedValue(v any) any {
	switch t := v.(type) {
	case orderedObject:
		obj := newOrderedObject()
		for _, pair := range t.Pairs {
			obj.Index[pair.Key] = len(obj.Pairs)
			obj.Pairs = append(obj.Pairs, orderedKV{
				Key:   pair.Key,
				Value: canonicalizeOrderedValue(pair.Value),
			})
		}
		return obj
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = canonicalizeOrderedValue(t[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[k] = canonicalizeOrderedValue(v)
		}
		return out
	default:
		return t
	}
}

func orderedValueToMapValue(v any) any {
	switch t := v.(type) {
	case orderedObject:
		return t.asMap()
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = orderedValueToMapValue(t[i])
		}
		return out
	default:
		return t
	}
}

func stringOrJSON(v map[string]any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// FormatHandlerFromResolverParams builds a format handler from resolver params and returns leftover params.
func FormatHandlerFromResolverParams(
	resolverParams map[string]any,
	baseFormatType FormatType,
	baseUseFences bool,
) (*FormatHandler, map[string]any, error) {
	params := map[string]any{}
	for k, v := range resolverParams {
		params[k] = v
	}

	// Explicit handler takes precedence.
	if h, ok := params["format_handler"]; ok && h != nil {
		if fh, ok := h.(*FormatHandler); ok {
			delete(params, "format_handler")
			for _, key := range []string{
				"fence_output",
				"format_type",
				"strict_fences",
				"require_extractions_key",
				"extraction_attributes_suffix",
				"attribute_suffix",
			} {
				delete(params, key)
			}
			return fh, params, nil
		}
		return nil, nil, fmt.Errorf("format_handler must be *FormatHandler")
	}

	h := NewFormatHandler()
	h.FormatType = baseFormatType
	h.UseFences = baseUseFences

	if v, ok := params["fence_output"]; ok && v != nil {
		if b, ok := asBool(v); ok {
			h.UseFences = b
		}
		delete(params, "fence_output")
	}
	if v, ok := params["format_type"]; ok && v != nil {
		ft, err := parseFormatType(v)
		if err != nil {
			return nil, nil, err
		}
		h.FormatType = ft
		delete(params, "format_type")
	}
	if v, ok := params["strict_fences"]; ok && v != nil {
		if b, ok := asBool(v); ok {
			h.StrictFences = b
		}
		delete(params, "strict_fences")
	}
	if v, ok := params["require_extractions_key"]; ok && v != nil {
		if b, ok := asBool(v); ok {
			h.UseWrapper = b
			if !b {
				h.WrapperKey = ""
			}
		}
		delete(params, "require_extractions_key")
	}
	if v, ok := params["extraction_attributes_suffix"]; ok && v != nil {
		if s, ok := v.(string); ok && s != "" {
			h.AttributeSuffix = s
		}
		delete(params, "extraction_attributes_suffix")
	}
	if v, ok := params["attribute_suffix"]; ok && v != nil {
		if s, ok := v.(string); ok && s != "" {
			h.AttributeSuffix = s
		}
		delete(params, "attribute_suffix")
	}
	return h, params, nil
}

func parseFormatType(v any) (FormatType, error) {
	switch t := v.(type) {
	case FormatType:
		return t, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "json":
			return FormatTypeJSON, nil
		case "yaml", "yml":
			return FormatTypeYAML, nil
		default:
			return "", fmt.Errorf("unsupported format_type %q", t)
		}
	default:
		return "", fmt.Errorf("unsupported format_type value %T", v)
	}
}

func asBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	default:
		return false, false
	}
}
