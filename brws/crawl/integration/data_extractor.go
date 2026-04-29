package integration

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

type DataExtractor struct {
	navigator  *SemanticNavigator
	schemas    []*ExtractionSchema
	extractors []CustomExtractor
	mu         sync.RWMutex
}

type ExtractionSchema struct {
	Name       string
	URLPattern string
	Fields     []FieldSpec
	Lists      []ListSpec
	Tables     []TableSpec
	Confidence float32
}

type FieldSpec struct {
	Name      string
	Selector  string
	Type      string
	Required  bool
	Transform string
	Regex     string
	Default   string
}

type ListSpec struct {
	Name     string
	Selector string
	ItemSpec FieldSpec
	MinItems int
	MaxItems int
}

type TableSpec struct {
	Name        string
	Selector    string
	Headers     []string
	RowSelector string
}

type CustomExtractor func(*semantic.SemanticTree) (map[string]interface{}, error)

type ExtractionResult struct {
	URL         string
	SchemaName  string
	Data        map[string]interface{}
	Confidence  float32
	FieldsFound int
	ListsFound  int
	TablesFound int
	Error       error
}

func NewDataExtractor(nav *SemanticNavigator) *DataExtractor {
	return &DataExtractor{
		navigator:  nav,
		schemas:    make([]*ExtractionSchema, 0),
		extractors: make([]CustomExtractor, 0),
	}
}

func (e *DataExtractor) AddSchema(schema *ExtractionSchema) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.schemas = append(e.schemas, schema)
}

func (e *DataExtractor) AddCustomExtractor(extractor CustomExtractor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.extractors = append(e.extractors, extractor)
}

func (e *DataExtractor) Extract(ctx context.Context, url string) (*ExtractionResult, error) {
	tree, err := e.extractTree(ctx, url)
	if err != nil {
		return nil, err
	}

	result := &ExtractionResult{
		URL:  url,
		Data: make(map[string]interface{}),
	}

	schema := e.matchSchema(url)
	if schema != nil {
		result.SchemaName = schema.Name
		result.Data = e.extractBySchema(tree, schema)
		result.Confidence = schema.Confidence
		result.FieldsFound = len(schema.Fields)
		result.ListsFound = len(schema.Lists)
		result.TablesFound = len(schema.Tables)
	}

	for _, extractor := range e.extractors {
		extracted, err := extractor(tree)
		if err == nil {
			for k, v := range extracted {
				result.Data[k] = v
			}
		}
	}

	if len(result.Data) == 0 {
		result.Data = e.extractByHeuristics(tree)
		result.Confidence = 0.5
	}

	return result, nil
}

func (e *DataExtractor) extractTree(ctx context.Context, url string) (*semantic.SemanticTree, error) {
	navResult, err := e.navigator.NavigateWithIntent(ctx, url, "")
	if err != nil {
		return nil, err
	}
	return navResult.SemanticTree, nil
}

func (e *DataExtractor) matchSchema(url string) *ExtractionSchema {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, schema := range e.schemas {
		if schema.URLPattern != "" {
			matched, err := regexp.MatchString(schema.URLPattern, url)
			if err == nil && matched {
				return schema
			}
		}
	}
	return nil
}

func (e *DataExtractor) extractBySchema(tree *semantic.SemanticTree, schema *ExtractionSchema) map[string]interface{} {
	data := make(map[string]interface{})

	for _, field := range schema.Fields {
		value := e.extractField(tree, field)
		if value != "" || field.Default != "" {
			if value == "" && field.Default != "" {
				value = field.Default
			}
			data[field.Name] = value
		}
	}

	for _, listSpec := range schema.Lists {
		items := e.extractList(tree, listSpec)
		if len(items) >= listSpec.MinItems {
			data[listSpec.Name] = items
		}
	}

	for _, tableSpec := range schema.Tables {
		table := e.extractTable(tree, tableSpec)
		if table != nil {
			data[tableSpec.Name] = table
		}
	}

	return data
}

func (e *DataExtractor) extractField(tree *semantic.SemanticTree, spec FieldSpec) string {
	if spec.Selector != "" {
		node := tree.FindNode(spec.Selector)
		if node != nil {
			value := node.Summary
			return e.transformValue(value, spec)
		}
	}

	if spec.Regex != "" {
		re := regexp.MustCompile(spec.Regex)
		for _, node := range tree.AllNodes() {
			matches := re.FindStringSubmatch(node.Summary)
			if len(matches) > 1 {
				return e.transformValue(matches[1], spec)
			}
		}
	}

	return ""
}

func (e *DataExtractor) transformValue(value string, spec FieldSpec) string {
	switch spec.Transform {
	case "uppercase":
		return strings.ToUpper(value)
	case "lowercase":
		return strings.ToLower(value)
	case "trim":
		return strings.TrimSpace(value)
	case "number":
		re := regexp.MustCompile(`[\d.]+`)
		return re.FindString(value)
	case "email":
		re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
		match := re.FindString(value)
		return match
	case "url":
		re := regexp.MustCompile(`https?://[^\s]+`)
		match := re.FindString(value)
		return match
	default:
		return value
	}
}

func (e *DataExtractor) extractList(tree *semantic.SemanticTree, spec ListSpec) []interface{} {
	items := make([]interface{}, 0)

	if spec.Selector != "" {
		for _, node := range tree.AllNodes() {
			if spec.Selector != "" && !strings.Contains(node.DOMSelector, spec.Selector) {
				continue
			}
			if len(items) >= spec.MaxItems && spec.MaxItems > 0 {
				break
			}
			value := e.extractField(&semantic.SemanticTree{RootNodes: []semantic.SemanticNode{*node}}, spec.ItemSpec)
			if value != "" {
				items = append(items, value)
			}
		}
	}

	return items
}

func (e *DataExtractor) extractTable(tree *semantic.SemanticTree, spec TableSpec) [][]string {
	if spec.Selector == "" {
		return nil
	}

	var table [][]string

	node := tree.FindNode(spec.Selector)
	if node == nil {
		return nil
	}

	table = append(table, spec.Headers)

	return table
}

func (e *DataExtractor) extractByHeuristics(tree *semantic.SemanticTree) map[string]interface{} {
	data := make(map[string]interface{})

	data["title"] = tree.Title
	data["domain"] = tree.Domain

	links := make([]string, 0)
	for _, node := range tree.AllNodes() {
		for _, action := range node.Actions {
			if action.Type == semantic.ActionClick {
				if strings.HasPrefix(action.Selector, "a[href") ||
					strings.HasPrefix(action.Selector, "a[") {
					links = append(links, action.Description)
				}
			}
		}
	}
	if len(links) > 0 {
		data["links"] = links
	}

	forms := e.extractForms(tree)
	if len(forms) > 0 {
		data["forms"] = forms
	}

	images := e.extractImages(tree)
	if len(images) > 0 {
		data["images"] = images
	}

	headings := e.extractHeadings(tree)
	if len(headings) > 0 {
		data["headings"] = headings
	}

	return data
}

func (e *DataExtractor) extractForms(tree *semantic.SemanticTree) []map[string]string {
	forms := make([]map[string]string, 0)

	formRE := regexp.MustCompile(`(?i)(login|signup|register|signin|contact|search|form)`)

	for _, node := range tree.AllNodes() {
		for _, action := range node.Actions {
			if action.Type == semantic.ActionFill {
				if formRE.MatchString(action.Description) {
					forms = append(forms, map[string]string{
						"field":    action.Description,
						"selector": action.Selector,
					})
				}
			}
		}
	}

	return forms
}

func (e *DataExtractor) extractImages(tree *semantic.SemanticTree) []string {
	images := make([]string, 0)

	for _, node := range tree.AllNodes() {
		if strings.Contains(strings.ToLower(node.Summary), "image") ||
			strings.Contains(strings.ToLower(node.Summary), "photo") ||
			strings.Contains(strings.ToLower(node.Summary), "picture") {
			images = append(images, node.Summary)
		}
	}

	return images
}

func (e *DataExtractor) extractHeadings(tree *semantic.SemanticTree) []string {
	headings := make([]string, 0)

	for _, node := range tree.AllNodes() {
		summary := strings.ToLower(node.Summary)
		if strings.HasPrefix(summary, "h1") ||
			strings.HasPrefix(summary, "h2") ||
			strings.HasPrefix(summary, "h3") ||
			strings.Contains(summary, "heading") {
			headings = append(headings, node.Summary)
		}
	}

	return headings
}

func (e *DataExtractor) ExportJSON(result *ExtractionResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func (e *DataExtractor) BatchExtract(ctx context.Context, urls []string) ([]*ExtractionResult, error) {
	results := make([]*ExtractionResult, 0, len(urls))

	for _, url := range urls {
		result, err := e.Extract(ctx, url)
		if err != nil {
			results = append(results, &ExtractionResult{
				URL:   url,
				Error: err,
			})
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func ProductPageSchema() *ExtractionSchema {
	return &ExtractionSchema{
		Name:       "product",
		URLPattern: `.*(product|item|shop|buy|purchase).*`,
		Fields: []FieldSpec{
			{Name: "name", Selector: "[itemprop=name]", Type: "text"},
			{Name: "price", Selector: "[itemprop=price]", Type: "number", Regex: `[\d.,]+`},
			{Name: "currency", Selector: "[itemprop=priceCurrency]", Type: "text"},
			{Name: "description", Selector: "[itemprop=description]", Type: "text"},
			{Name: "availability", Selector: "[itemprop=availability]", Type: "text"},
			{Name: "brand", Selector: "[itemprop=brand]", Type: "text"},
			{Name: "sku", Selector: "[itemprop=sku]", Type: "text"},
		},
		Confidence: 0.8,
	}
}

func ArticlePageSchema() *ExtractionSchema {
	return &ExtractionSchema{
		Name:       "article",
		URLPattern: `.*(article|blog|post|news|story).*`,
		Fields: []FieldSpec{
			{Name: "headline", Selector: "[itemprop=headline]", Type: "text"},
			{Name: "author", Selector: "[itemprop=author]", Type: "text"},
			{Name: "datePublished", Selector: "[itemprop=datePublished]", Type: "text"},
			{Name: "description", Selector: "[itemprop=description]", Type: "text"},
			{Name: "image", Selector: "[itemprop=image]", Type: "url"},
		},
		Confidence: 0.8,
	}
}

func ContactPageSchema() *ExtractionSchema {
	return &ExtractionSchema{
		Name:       "contact",
		URLPattern: `.*(contact|about|us).*`,
		Fields: []FieldSpec{
			{Name: "email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Type: "email"},
			{Name: "phone", Regex: `\+?[\d\s\-\(\)]{10,}`, Type: "text"},
			{Name: "address", Regex: `[\d\s]+[A-Za-z]+.*`, Type: "text"},
		},
		Confidence: 0.6,
	}
}
