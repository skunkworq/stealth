package semantic

import (
	"regexp"
	"strings"
)

// extractInteractiveElements extracts interactive elements from HTML string.
func extractInteractiveElements(htmlStr string) []InteractiveElement {
	var elements []InteractiveElement

	// Pattern to match interactive elements
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

				// Build selector
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

// matchInteractiveElements matches interactive elements to selectors.
func matchInteractiveElements(htmlStr string, elements []InteractiveElement) []InteractiveElement {
	// For now, return elements as-is
	// In a full implementation, this would match elements to their DOM positions
	return elements
}

// buildActionFromInteractive builds an Action from an interactive element.
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

// parseAttributes parses HTML attributes from a tag string.
func parseAttributes(tagStr string) map[string]string {
	attrs := make(map[string]string)

	// Match attribute="value" or attribute='value' patterns
	pattern := regexp.MustCompile(`(\w+)=["']([^"']*)["']`)
	matches := pattern.FindAllStringSubmatch(tagStr, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			attrs[match[1]] = match[2]
		}
	}

	return attrs
}
