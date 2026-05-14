package understand

import (
	"regexp"
	"strings"
)

type FieldType string

const (
	FieldTypeText     FieldType = "text"
	FieldTypePassword FieldType = "password"
	FieldTypeEmail    FieldType = "email"
	FieldTypeNumber   FieldType = "number"
	FieldTypeSearch   FieldType = "search"
	FieldTypeURL      FieldType = "url"
	FieldTypeTextarea FieldType = "textarea"
)

type Action struct {
	Type        ActionType `json:"type"`
	Selector    string     `json:"selector"`
	Description string     `json:"description,omitempty"`

	FillOptions *FillOptions `json:"fill_options,omitempty"`
	SelectOpts  *SelectOpts  `json:"select_options,omitempty"`
	ToggleState *bool        `json:"toggle_state,omitempty"`
}

type ActionType string

const (
	ActionClick  ActionType = "click"
	ActionFill   ActionType = "fill"
	ActionSelect ActionType = "select"
	ActionToggle ActionType = "toggle"
)

type FillOptions struct {
	FieldType FieldType `json:"field_type"`
}

type SelectOpts struct {
	Options []string `json:"options"`
}

func (a *Action) GetSelector() string { return a.Selector }

func (a *Action) GetDescription() string { return a.Description }

type InteractiveElement struct {
	Selector   string            `json:"selector"`
	Tag        string            `json:"tag"`
	Attrs      map[string]string `json:"attrs"`
	ActionType string            `json:"action_type"`
}

func extractInteractiveElements(htmlStr string) []InteractiveElement {
	var elements []InteractiveElement

	patterns := []struct {
		tag    string
		action string
		regex  *regexp.Regexp
	}{
		{"button", "click", regexp.MustCompile(`<button[^>]*>`)},
		{"a", "click", regexp.MustCompile(`<a[^>]*href="[^"]*"[^>]*>`)},
		{"input", "fill", regexp.MustCompile(`<input[^>]*>`)},
		{"select", "select", regexp.MustCompile(`<select[^>]*>`)},
		{"textarea", "fill", regexp.MustCompile(`<textarea[^>]*>`)},
	}

	for _, p := range patterns {
		matches := p.regex.FindAllStringIndex(htmlStr, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				elementHTML := htmlStr[match[0]:match[1]]
				attrs := parseAttributes(elementHTML)

				element := InteractiveElement{
					Tag:        p.tag,
					Attrs:      attrs,
					ActionType: p.action,
				}

				if id, ok := attrs["id"]; ok && id != "" {
					element.Selector = "#" + id
				} else if class, ok := attrs["class"]; ok && class != "" {
					classes := strings.Fields(class)
					if len(classes) > 0 {
						element.Selector = "." + classes[0]
					}
				} else {
					element.Selector = p.tag
				}

				elements = append(elements, element)
			}
		}
	}

	return elements
}

func matchInteractiveElements(_ string, elements []InteractiveElement) []InteractiveElement {
	return elements
}

func buildActionFromInteractive(el InteractiveElement, desc string) Action {
	switch el.ActionType {
	case "fill":
		fieldType := FieldTypeText
		switch el.Attrs["type"] {
		case "email":
			fieldType = FieldTypeEmail
		case "password":
			fieldType = FieldTypePassword
		case "number":
			fieldType = FieldTypeNumber
		case "search":
			fieldType = FieldTypeSearch
		case "url":
			fieldType = FieldTypeURL
		}
		return Action{
			Type:        ActionFill,
			Selector:    el.Selector,
			Description: desc,
			FillOptions: &FillOptions{FieldType: fieldType},
		}
	case "select":
		return Action{
			Type:        ActionSelect,
			Selector:    el.Selector,
			Description: desc,
			SelectOpts:  &SelectOpts{},
		}
	case "toggle":
		return Action{
			Type:        ActionToggle,
			Selector:    el.Selector,
			Description: desc,
			ToggleState: new(bool),
		}
	default:
		return Action{
			Type:        ActionClick,
			Selector:    el.Selector,
			Description: desc,
		}
	}
}

func parseAttributes(tagStr string) map[string]string {
	attrs := make(map[string]string)
	pattern := regexp.MustCompile(`(\w+)=["']([^"']*)["']`)
	matches := pattern.FindAllStringSubmatch(tagStr, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			attrs[match[1]] = match[2]
		}
	}
	return attrs
}
