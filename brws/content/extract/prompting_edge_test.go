package extract

import (
	"strings"
	"testing"
)

func TestPromptBuilderBuildPromptIncludesContext(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	generator := newQAPromptGenerator(PromptTemplateStructured{
		Description: "Extract people.",
	}, handler)
	builder := newPromptBuilder(generator)

	prompt, err := builder.BuildPrompt("Alice works at Acme.", "doc-1", "Use concise labels.")
	if err != nil {
		t.Fatalf("build prompt failed: %v", err)
	}
	if !strings.Contains(prompt, "Extract people.") {
		t.Fatalf("expected prompt description in output")
	}
	if !strings.Contains(prompt, "Use concise labels.") {
		t.Fatalf("expected additional context in output")
	}
	if !strings.Contains(prompt, "Q: Alice works at Acme.") {
		t.Fatalf("expected question line in output")
	}
}

func TestContextAwarePromptBuilderUsesPerDocumentHistory(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	generator := newQAPromptGenerator(PromptTemplateStructured{
		Description: "Extract entities.",
	}, handler)
	window := 10
	builder := newContextAwarePromptBuilder(generator, &window)

	first, err := builder.BuildPrompt("Alice joined Acme.", "doc-a", "")
	if err != nil {
		t.Fatalf("first build failed: %v", err)
	}
	if strings.Contains(first, "[Previous text]:") {
		t.Fatalf("did not expect previous text in first prompt")
	}

	second, err := builder.BuildPrompt("She leads backend.", "doc-a", "Focus on organizations.")
	if err != nil {
		t.Fatalf("second build failed: %v", err)
	}
	if !strings.Contains(second, "[Previous text]: ...") {
		t.Fatalf("expected previous context prefix in second prompt")
	}
	if !strings.Contains(second, "Focus on organizations.") {
		t.Fatalf("expected additional context in second prompt")
	}
	if !strings.Contains(second, "Acme.") {
		t.Fatalf("expected previous chunk content in second prompt")
	}

	otherDoc, err := builder.BuildPrompt("Bob moved teams.", "doc-b", "")
	if err != nil {
		t.Fatalf("other doc build failed: %v", err)
	}
	if strings.Contains(otherDoc, "[Previous text]:") {
		t.Fatalf("did not expect doc-a history to leak into doc-b prompt")
	}
}
