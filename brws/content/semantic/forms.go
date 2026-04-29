package semantic

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

type FormSchema struct {
	Action       string      `json:"action"`
	Method       string      `json:"method"`
	EncType      string      `json:"enctype,omitempty"`
	Fields       []FormField `json:"fields"`
	SubmitButton string      `json:"submit_button,omitempty"`
	HasCSRF      bool        `json:"has_csrf"`
}

type FormField struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Label        string   `json:"label,omitempty"`
	Required     bool     `json:"required"`
	Placeholder  string   `json:"placeholder,omitempty"`
	DefaultValue string   `json:"default_value,omitempty"`
	Options      []string `json:"options,omitempty"`
	MinLength    int      `json:"min_length,omitempty"`
	MaxLength    int      `json:"max_length,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
	Min          string   `json:"min,omitempty"`
	Max          string   `json:"max,omitempty"`
	Selector     string   `json:"selector"`
	Description  string   `json:"description,omitempty"`
}

func ExtractFormSchemas(htmlStr string) []FormSchema {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}
	return extractFormsFromDoc(doc)
}

func extractFormsFromDoc(n *html.Node) []FormSchema {
	var forms []FormSchema
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			form := parseFormElement(node)
			if form != nil {
				forms = append(forms, *form)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return forms
}

func parseFormElement(formNode *html.Node) *FormSchema {
	schema := &FormSchema{
		Method: "GET",
	}

	for _, attr := range formNode.Attr {
		switch attr.Key {
		case "action":
			schema.Action = attr.Val
		case "method":
			schema.Method = strings.ToUpper(attr.Val)
		case "enctype":
			schema.EncType = attr.Val
		}
	}

	labelFor := make(map[string]string)
	forEachElement(formNode, "label", func(label *html.Node) {
		forID := getAttr(label, "for")
		labelText := extractTextContent(label)
		if forID != "" && labelText != "" {
			labelFor[forID] = strings.TrimSpace(labelText)
		}
	})

	var submitText string
	hasExplicitSubmit := false

	forEachElement(formNode, "button", func(btn *html.Node) {
		btnType := getAttr(btn, "type")
		if btnType == "submit" || btnType == "" {
			hasExplicitSubmit = true
			submitText = extractTextContent(btn)
		}
	})

	forEachElement(formNode, "input", func(input *html.Node) {
		inputType := getAttr(input, "type")
		if inputType == "submit" {
			hasExplicitSubmit = true
			if submitText == "" {
				submitText = getAttr(input, "value")
				if submitText == "" {
					submitText = "Submit"
				}
			}
		}
	})

	if hasExplicitSubmit {
		schema.SubmitButton = strings.TrimSpace(submitText)
	}

	fieldIndex := 0
	forEachElement(formNode, "input", func(input *html.Node) {
		field := parseInputField(input, labelFor, fieldIndex)
		if field != nil && field.Name != "" {
			if strings.Contains(strings.ToLower(field.Name), "csrf") ||
				strings.Contains(strings.ToLower(field.Name), "token") ||
				strings.Contains(strings.ToLower(field.Name), "_token") {
				schema.HasCSRF = true
			}
			schema.Fields = append(schema.Fields, *field)
			fieldIndex++
		}
	})

	fieldIndex = 0
	forEachElement(formNode, "select", func(selectEl *html.Node) {
		field := parseSelectField(selectEl, labelFor, fieldIndex)
		if field != nil && field.Name != "" {
			schema.Fields = append(schema.Fields, *field)
			fieldIndex++
		}
	})

	fieldIndex = 0
	forEachElement(formNode, "textarea", func(ta *html.Node) {
		field := parseTextareaField(ta, labelFor, fieldIndex)
		if field != nil && field.Name != "" {
			schema.Fields = append(schema.Fields, *field)
			fieldIndex++
		}
	})

	return schema
}

func parseInputField(input *html.Node, labelFor map[string]string, index int) *FormField {
	inputType := getAttr(input, "type")
	if inputType == "" {
		inputType = "text"
	}
	if inputType == "submit" || inputType == "button" || inputType == "reset" || inputType == "image" {
		return nil
	}

	name := getAttr(input, "name")
	if name == "" {
		return nil
	}

	field := &FormField{
		Name:         name,
		Type:         inputType,
		Required:     hasAttr(input, "required"),
		Placeholder:  getAttr(input, "placeholder"),
		DefaultValue: getAttr(input, "value"),
		Pattern:      getAttr(input, "pattern"),
		Selector:     fmt.Sprintf("input[name='%s']", name),
	}

	if inputType == "number" || inputType == "range" {
		field.Min = getAttr(input, "min")
		field.Max = getAttr(input, "max")
	}

	maxLength := getAttr(input, "maxlength")
	minLength := getAttr(input, "minlength")
	if maxLength != "" {
		if _, err := fmt.Sscanf(maxLength, "%d", &field.MaxLength); err != nil {
			field.MaxLength = 0
		}
	}
	if minLength != "" {
		if _, err := fmt.Sscanf(minLength, "%d", &field.MinLength); err != nil {
			field.MinLength = 0
		}
	}

	inputID := getAttr(input, "id")
	if label, ok := labelFor[inputID]; ok {
		field.Label = label
	}

	if field.Label == "" && inputType != "hidden" {
		if field.Placeholder != "" {
			field.Label = strings.Split(field.Placeholder, "\n")[0]
		}
	}

	return field
}

func parseSelectField(selectEl *html.Node, labelFor map[string]string, index int) *FormField {
	name := getAttr(selectEl, "name")
	if name == "" {
		return nil
	}

	field := &FormField{
		Name:     name,
		Type:     "select",
		Required: hasAttr(selectEl, "required"),
		Selector: fmt.Sprintf("select[name='%s']", name),
	}

	forEachElement(selectEl, "option", func(opt *html.Node) {
		value := getAttr(opt, "value")
		text := extractTextContent(opt)
		if value != "" || text != "" {
			if value == "" {
				value = text
			}
			field.Options = append(field.Options, value)
		}
	})

	selectID := getAttr(selectEl, "id")
	if label, ok := labelFor[selectID]; ok {
		field.Label = label
	}

	return field
}

func parseTextareaField(ta *html.Node, labelFor map[string]string, index int) *FormField {
	name := getAttr(ta, "name")
	if name == "" {
		return nil
	}

	field := &FormField{
		Name:     name,
		Type:     "textarea",
		Required: hasAttr(ta, "required"),
		Selector: fmt.Sprintf("textarea[name='%s']", name),
	}

	maxLength := getAttr(ta, "maxlength")
	minLength := getAttr(ta, "minlength")
	if maxLength != "" {
		if _, err := fmt.Sscanf(maxLength, "%d", &field.MaxLength); err != nil {
			field.MaxLength = 0
		}
	}
	if minLength != "" {
		if _, err := fmt.Sscanf(minLength, "%d", &field.MinLength); err != nil {
			field.MinLength = 0
		}
	}

	defaultValue := extractTextContent(ta)
	if defaultValue != "" {
		field.DefaultValue = strings.TrimSpace(defaultValue)
	}

	placeholder := getAttr(ta, "placeholder")
	if placeholder != "" {
		field.Placeholder = placeholder
		if field.Label == "" {
			field.Label = placeholder
		}
	}

	taID := getAttr(ta, "id")
	if label, ok := labelFor[taID]; ok {
		field.Label = label
	}

	return field
}

func forEachElement(n *html.Node, tagName string, fn func(*html.Node)) {
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == tagName {
			fn(node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
}

func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, key string) bool {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return true
		}
	}
	return false
}

func (s *FormSchema) Describe() string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Form [%s %s]", s.Method, s.Action))
	lines = append(lines, fmt.Sprintf("  Fields: %d", len(s.Fields)))
	for _, f := range s.Fields {
		req := ""
		if f.Required {
			req = " [required]"
		}
		lines = append(lines, fmt.Sprintf("    %s (%s)%s", f.Name, f.Type, req))
	}
	return strings.Join(lines, "\n")
}
