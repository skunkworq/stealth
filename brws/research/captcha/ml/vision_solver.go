package captchaml

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

// SolvePromptTemplate is the base instruction template passed to the vision LLM.
// Callers should augment it with challenge-specific context before passing to Solve.
const SolvePromptTemplate = `Output ONLY a JSON array of instructions to solve the CAPTCHA shown. No explanation, no markdown, no prose.

Instruction types:
  {"action":"click",  "x":<float>, "y":<float>, "description":"<why>"}
  {"action":"type",   "selector":"<css>", "value":"<text>"}
  {"action":"submit"}

Rules:
- Coordinates are relative to the top-left of the image provided.
- For image grids: click the centre of every matching cell, then submit.
- For text/math CAPTCHAs: type the answer into the input, then submit.
- For checkboxes: click the checkbox centre.
- End with {"action":"submit"} when a verify/submit button is present.
- If unsolvable output: []`

// VisionSolver is a stateless, context-free LLM solver for visual CAPTCHAs.
// It receives a pre-extracted captcha image and a caller-supplied prompt, and
// returns structured instructions relative to the image coordinates.
// The caller is responsible for extracting the captcha region and augmenting
// the prompt with any challenge-specific context.
type VisionSolver struct {
	LLM completions.LLM
}

// Instruction is one step the caller should perform to solve the CAPTCHA.
type Instruction struct {
	Action      string  `json:"action"`             // "click", "type", "submit"
	X           float64 `json:"x,omitempty"`        // image-relative, for click
	Y           float64 `json:"y,omitempty"`        // image-relative, for click
	Selector    string  `json:"selector,omitempty"` // for type
	Value       string  `json:"value,omitempty"`    // for type
	Description string  `json:"description,omitempty"`
}

// Solve sends captchaImage to the vision LLM with prompt and returns the
// instruction list. prompt should be built from SolvePromptTemplate augmented
// with any challenge-specific context the caller knows (challenge type, any
// visible label text, etc.). Returns an empty slice if the LLM signals it
// cannot determine the answer.
func (s *VisionSolver) Solve(ctx context.Context, captchaImage []byte, prompt string) ([]Instruction, error) {
	reply, err := s.LLM.AskAboutImageData(ctx, captchaImage, "image/png", prompt)
	if err != nil {
		return nil, fmt.Errorf("vision llm: %w", err)
	}

	reply = stripJSONFences(reply)

	var instructions []Instruction
	if err := json.Unmarshal([]byte(reply), &instructions); err != nil {
		return nil, fmt.Errorf("parse captcha instructions: %w (raw: %.300s)", err, reply)
	}
	return instructions, nil
}

func stripJSONFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if idx := strings.Index(s, "\n"); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
