package scrapegraph

import (
	"context"
	"fmt"
	"strings"

	"github.com/skunkworq/stealth/brws/content/extract"
)

// ExtractorNode replaces ParseNode + GenerateAnswerNode with a single call to
// content/extract. It provides built-in chunking, schema validation, and
// configurable LLM providers — useful when raw extraction fidelity matters more
// than speed.
type ExtractorNode struct {
	Base    baseNode
	Options []extract.Option
}

// NewExtractorNode creates an ExtractorNode. Pass any extract.Option values to
// control the model, prompt description, format, etc.
func NewExtractorNode(input, output string, nodeConfig map[string]interface{}, opts ...extract.Option) *ExtractorNode {
	return &ExtractorNode{
		Base: baseNode{
			nodeName:   "ExtractorNode",
			nodeType:   "node",
			inputExpr:  input,
			output:     []string{output},
			minInputs:  1,
			nodeConfig: nodeConfig,
		},
		Options: opts,
	}
}

func (n *ExtractorNode) Name() string      { return n.Base.nodeName }
func (n *ExtractorNode) NodeType() string  { return n.Base.nodeType }
func (n *ExtractorNode) InputExpr() string { return n.Base.inputExpr }
func (n *ExtractorNode) Outputs() []string { return n.Base.output }
func (n *ExtractorNode) MinInputs() int    { return n.Base.minInputs }

func (n *ExtractorNode) Execute(ctx context.Context, state State) (State, string, error) {
	keys, err := ParseInputKeys(state, n.Base.inputExpr)
	if err != nil {
		return state, "", fmt.Errorf("parse input: %w", err)
	}

	userPrompt, _ := state[StateKeyUserPrompt].(string)

	var content string
	if len(keys) > 0 {
		switch v := state[keys[0]].(type) {
		case []Document:
			var parts []string
			for _, d := range v {
				parts = append(parts, d.PageContent)
			}
			content = strings.Join(parts, "\n")
		case []string:
			content = strings.Join(v, "\n")
		case string:
			content = v
		default:
			content = fmt.Sprintf("%v", v)
		}
	}

	opts := append([]extract.Option{extract.WithPromptDescription(userPrompt)}, n.Options...)
	result, err := extract.Extract(ctx, content, opts...)
	if err != nil {
		return state, "", fmt.Errorf("extract: %w", err)
	}

	out := state.Clone()
	out[n.Base.output[0]] = result
	return out, "", nil
}
