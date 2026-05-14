package extract

import "strings"

// PromptTemplateStructured defines extraction instructions and few-shot examples.
type PromptTemplateStructured struct {
	Description string
	Examples    []ExampleData
}

// QAPromptGenerator renders QA prompts.
type QAPromptGenerator struct {
	Template        PromptTemplateStructured
	FormatHandler   *FormatHandler
	ExamplesHeading string
	QuestionPrefix  string
	AnswerPrefix    string
}

func newQAPromptGenerator(template PromptTemplateStructured, handler *FormatHandler) *QAPromptGenerator {
	return &QAPromptGenerator{
		Template:        template,
		FormatHandler:   handler,
		ExamplesHeading: "Examples",
		QuestionPrefix:  "Q: ",
		AnswerPrefix:    "A: ",
	}
}

// FormatExampleAsText renders one few-shot example into Q/A prompt form.
func (q *QAPromptGenerator) FormatExampleAsText(example ExampleData) (string, error) {
	answer, err := q.FormatHandler.FormatExtractionExample(example.Extractions)
	if err != nil {
		return "", err
	}

	lines := []string{
		q.QuestionPrefix + example.Text,
		q.AnswerPrefix + answer,
		"",
	}
	return strings.Join(lines, "\n"), nil
}

// Render renders the full prompt for a question/chunk.
func (q *QAPromptGenerator) Render(question, additionalContext string) (string, error) {
	lines := []string{q.Template.Description, ""}
	if strings.TrimSpace(additionalContext) != "" {
		lines = append(lines, additionalContext, "")
	}

	if len(q.Template.Examples) > 0 {
		lines = append(lines, q.ExamplesHeading)
		for _, ex := range q.Template.Examples {
			formatted, err := q.FormatExampleAsText(ex)
			if err != nil {
				return "", err
			}
			lines = append(lines, formatted)
		}
	}

	lines = append(lines, q.QuestionPrefix+question, q.AnswerPrefix)
	return strings.Join(lines, "\n"), nil
}

// PromptBuilder builds prompts for chunks.
type PromptBuilder struct {
	generator *QAPromptGenerator
}

func newPromptBuilder(generator *QAPromptGenerator) *PromptBuilder {
	return &PromptBuilder{generator: generator}
}

// BuildPrompt builds a prompt for one chunk.
func (p *PromptBuilder) BuildPrompt(chunkText, documentID, additionalContext string) (string, error) {
	_ = documentID
	return p.generator.Render(chunkText, additionalContext)
}

// ContextAwarePromptBuilder injects previous chunk context for each document.
type ContextAwarePromptBuilder struct {
	*PromptBuilder
	contextWindowChars int
	prevChunkByDocID   map[string]string
}

func newContextAwarePromptBuilder(generator *QAPromptGenerator, contextWindowChars *int) *ContextAwarePromptBuilder {
	window := 0
	if contextWindowChars != nil && *contextWindowChars > 0 {
		window = *contextWindowChars
	}
	return &ContextAwarePromptBuilder{
		PromptBuilder:      newPromptBuilder(generator),
		contextWindowChars: window,
		prevChunkByDocID:   map[string]string{},
	}
}

// BuildPrompt builds a prompt and optionally injects previous-chunk context.
func (c *ContextAwarePromptBuilder) BuildPrompt(chunkText, documentID, additionalContext string) (string, error) {
	effectiveContext := c.buildEffectiveContext(documentID, additionalContext)
	prompt, err := c.generator.Render(chunkText, effectiveContext)
	if err != nil {
		return "", err
	}
	c.updateState(documentID, chunkText)
	return prompt, nil
}

func (c *ContextAwarePromptBuilder) buildEffectiveContext(documentID, additionalContext string) string {
	parts := make([]string, 0, 2)

	if c.contextWindowChars > 0 {
		if prev, ok := c.prevChunkByDocID[documentID]; ok {
			window := prev
			if len(window) > c.contextWindowChars {
				window = window[len(window)-c.contextWindowChars:]
			}
			parts = append(parts, "[Previous text]: ..."+window)
		}
	}

	if strings.TrimSpace(additionalContext) != "" {
		parts = append(parts, additionalContext)
	}

	return strings.Join(parts, "\n\n")
}

func (c *ContextAwarePromptBuilder) updateState(documentID, chunkText string) {
	if c.contextWindowChars > 0 {
		c.prevChunkByDocID[documentID] = chunkText
	}
}
