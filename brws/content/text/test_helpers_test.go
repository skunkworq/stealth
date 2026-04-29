package langextract

import (
	"context"
	"sync"
)

type fakeExtractor struct {
	mu sync.Mutex

	outputs      []string
	calls        [][]string
	fenceOutput  bool
	formatType   FormatType
	lastSchema   any
	defaultScore float64
}

func newFakeExtractor(outputs ...string) *fakeExtractor {
	return &fakeExtractor{
		outputs:      append([]string{}, outputs...),
		formatType:   FormatTypeJSON,
		defaultScore: 1.0,
	}
}

func (f *fakeExtractor) Infer(_ context.Context, prompts []string, _ map[string]any) ([][]ScoredOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, append([]string{}, prompts...))

	out := make([][]ScoredOutput, 0, len(prompts))
	for i := range prompts {
		body := `{"extractions":[]}`
		if len(f.outputs) > 0 {
			body = f.outputs[i%len(f.outputs)]
		}
		out = append(out, []ScoredOutput{{
			Score:  f.defaultScore,
			Output: body,
		}})
	}
	return out, nil
}

func (f *fakeExtractor) RequiresFenceOutput() bool { return f.fenceOutput }

func (f *fakeExtractor) SetFenceOutput(enabled bool) { f.fenceOutput = enabled }

func (f *fakeExtractor) FormatType() FormatType { return f.formatType }

func (f *fakeExtractor) SetFormatType(ft FormatType) { f.formatType = ft }

func (f *fakeExtractor) SetSchema(schema any) { f.lastSchema = schema }

func (f *fakeExtractor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}
