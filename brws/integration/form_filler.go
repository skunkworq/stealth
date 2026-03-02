package integration

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/semantic"
	"github.com/stealth/brwslab/brws/stealth"
)

type SemanticFormFiller struct {
	client      *stealth.Client
	navigator   *SemanticNavigator
	typingDelay time.Duration
	mu          sync.Mutex
}

type FormField struct {
	Selector    string
	Type        string // text, email, password, etc.
	Label       string
	Value       string
	Required    bool
	Placeholder string
}

type FormSchema struct {
	Selector     string
	Action       string // "submit", "login", "search", etc.
	Fields       []FormField
	SubmitButton string
}

type FillOptions struct {
	HumanizeTyping bool
	TypingSpeedMin time.Duration
	TypingSpeedMax time.Duration
	FieldDelay     time.Duration // Delay between fields
}

var DefaultFillOptions = FillOptions{
	HumanizeTyping: true,
	TypingSpeedMin: 30 * time.Millisecond,
	TypingSpeedMax: 120 * time.Millisecond,
	FieldDelay:     200 * time.Millisecond,
}

type FormFillerOption func(*SemanticFormFiller)

func WithTypingDelay(delay time.Duration) FormFillerOption {
	return func(f *SemanticFormFiller) {
		f.typingDelay = delay
	}
}

func NewSemanticFormFiller(client *stealth.Client, nav *SemanticNavigator, opts ...FormFillerOption) *SemanticFormFiller {
	f := &SemanticFormFiller{
		client:      client,
		navigator:   nav,
		typingDelay: 50 * time.Millisecond,
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

func (f *SemanticFormFiller) FillForm(ctx context.Context, formSchema *FormSchema, values map[string]string, opts ...FillOptions) error {
	options := DefaultFillOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	for _, field := range formSchema.Fields {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		value, hasValue := values[field.Selector]
		if !hasValue && field.Required {
			value, hasValue = values[field.Label]
		}
		if !hasValue && field.Placeholder != "" {
			value, hasValue = values[field.Placeholder]
		}

		if !hasValue {
			if field.Required {
				return fmt.Errorf("missing value for required field: %s (%s)", field.Selector, field.Label)
			}
			continue
		}

		if err := f.fillField(ctx, field, value, options); err != nil {
			return fmt.Errorf("fill field %s: %w", field.Selector, err)
		}

		if options.FieldDelay > 0 {
			time.Sleep(f.jitterDelay(options.FieldDelay))
		}
	}

	return nil
}

func (f *SemanticFormFiller) fillField(ctx context.Context, field FormField, value string, opts FillOptions) error {
	if f.client == nil {
		return fmt.Errorf("no stealth client configured")
	}

	if opts.HumanizeTyping && (field.Type == "text" || field.Type == "email" || field.Type == "password" || field.Type == "search") {
		return f.typeHumanized(ctx, field.Selector, value, opts)
	}

	return f.client.ClickSelector(ctx, field.Selector)
}

func (f *SemanticFormFiller) typeHumanized(ctx context.Context, selector, value string, opts FillOptions) error {
	if err := f.client.ClickSelector(ctx, selector); err != nil {
		return err
	}

	time.Sleep(f.jitterDelay(50 * time.Millisecond))

	return nil
}

func (f *SemanticFormFiller) jitterDelay(base time.Duration) time.Duration {
	jitter := time.Duration(rand.Int63n(int64(base / 5)))
	return base + jitter
}

func (f *SemanticFormFiller) randomDelay(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	delta := max - min
	return min + time.Duration(rand.Int63n(int64(delta)))
}

func (f *SemanticFormFiller) SubmitForm(ctx context.Context, formSchema *FormSchema) error {
	if formSchema.SubmitButton != "" {
		return f.client.ClickSelector(ctx, formSchema.SubmitButton)
	}

	submitScript := fmt.Sprintf(`
		(function() {
			var form = document.querySelector("%s");
			if (form && form.tagName === "FORM") {
				var submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
				if (submitBtn) {
					submitBtn.click();
					return true;
				}
				form.submit();
				return true;
			}
			return false;
		})()
	`, formSchema.Selector)

	_ = submitScript
	return f.client.ClickSelector(ctx, formSchema.Selector+" button[type='submit']")
}

func (f *SemanticFormFiller) DetectForm(ctx context.Context, url string) (*FormSchema, error) {
	result, err := f.navigator.NavigateWithIntent(ctx, url, "form")
	if err != nil {
		return nil, err
	}

	tree := result.SemanticTree
	if tree == nil {
		return nil, fmt.Errorf("no semantic tree extracted")
	}

	forms := f.findFormsInTree(tree)
	if len(forms) == 0 {
		return nil, fmt.Errorf("no forms detected")
	}

	return forms[0], nil
}

func (f *SemanticFormFiller) findFormsInTree(tree *semantic.SemanticTree) []*FormSchema {
	var forms []*FormSchema

	for _, node := range tree.AllNodes() {
		for _, action := range node.Actions {
			if action.Type == semantic.ActionFill {
				form := f.extractFormFromNode(node, action)
				if form != nil {
					forms = append(forms, form)
				}
			}
		}
	}

	return forms
}

func (f *SemanticFormFiller) extractFormFromNode(node *semantic.SemanticNode, action semantic.Action) *FormSchema {
	form := &FormSchema{
		Selector: node.DOMSelector,
		Fields:   make([]FormField, 0),
	}

	if action.FillOptions != nil {
		field := FormField{
			Selector: action.Selector,
			Type:     string(action.FillOptions.FieldType),
		}
		form.Fields = append(form.Fields, field)
	}

	for _, child := range node.Children {
		for _, childAction := range child.Actions {
			if childAction.Type == semantic.ActionFill {
				field := FormField{
					Selector: childAction.Selector,
					Type:     "text",
				}
				if childAction.FillOptions != nil {
					field.Type = string(childAction.FillOptions.FieldType)
				}
				form.Fields = append(form.Fields, field)
			} else if childAction.Type == semantic.ActionClick {
				if strings.Contains(strings.ToLower(childAction.Description), "submit") ||
					strings.Contains(strings.ToLower(childAction.Description), "login") ||
					strings.Contains(strings.ToLower(childAction.Description), "search") {
					form.SubmitButton = childAction.Selector
				}
			}
		}
	}

	return form
}

func (f *SemanticFormFiller) Close() error {
	return nil
}
