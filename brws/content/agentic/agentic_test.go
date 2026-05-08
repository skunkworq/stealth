package agentic

import (
	"context"
	"testing"
)

func TestParseInputKeys(t *testing.T) {
	state := State{
		"user_prompt":     "find prices",
		"parsed_doc":      []string{"chunk1"},
		"doc":             []Document{{PageContent: "html"}},
		"url":             "https://example.com",
	}

	cases := []struct {
		expr string
		want int
	}{
		{"url | local_dir", 1},
		{"user_prompt & (relevant_chunks | parsed_doc | doc)", 2},
		{"doc", 1},
		{"missing | url", 1},
		{"user_prompt & doc", 2},
	}

	for _, c := range cases {
		keys, err := ParseInputKeys(state, c.expr)
		if err != nil {
			t.Fatalf("expr %q: unexpected error: %v", c.expr, err)
		}
		if len(keys) != c.want {
			t.Fatalf("expr %q: want %d keys, got %d (%v)", c.expr, c.want, len(keys), keys)
		}
	}
}

func TestBaseGraphExecution(t *testing.T) {
	// Build a simple graph: A -> B -> C
	nodeA := &testNode{name: "A", out: []string{"x"}, fn: func(s State) State {
		s["x"] = 1
		return s
	}}
	nodeB := &testNode{name: "B", inExpr: "x", out: []string{"y"}, fn: func(s State) State {
		s["y"] = s["x"].(int) * 2
		return s
	}}
	nodeC := &testNode{name: "C", inExpr: "y", out: []string{"z"}, fn: func(s State) State {
		s["z"] = s["y"].(int) + 3
		return s
	}}

	graph, err := NewBaseGraph(
		[]Node{nodeA, nodeB, nodeC},
		[][2]string{{"A", "B"}, {"B", "C"}},
		nodeA,
		"TestGraph",
	)
	if err != nil {
		t.Fatal(err)
	}

	state, info, err := graph.Execute(context.Background(), State{})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if len(info) != 3 {
		t.Fatalf("expected 3 execution infos, got %d", len(info))
	}
	if state["z"] != 5 {
		t.Fatalf("expected z=5, got %v", state["z"])
	}
}

func TestConditionalNode(t *testing.T) {
	nodeA := &testNode{name: "A", out: []string{"answer"}, fn: func(s State) State {
		s["answer"] = "NA"
		return s
	}}
	cond := NewConditionalNode("answer", "answer",
		map[string]interface{}{"key_name": "answer", "condition": `not answer or answer=="NA"`},
		"Retry", "Done",
	)
	retry := &testNode{name: "Retry", inExpr: "answer", out: []string{"answer"}, fn: func(s State) State {
		s["answer"] = "recovered"
		return s
	}}
	done := &testNode{name: "Done", inExpr: "answer", out: []string{"final"}, fn: func(s State) State {
		s["final"] = s["answer"]
		return s
	}}

	graph, err := NewBaseGraph(
		[]Node{nodeA, cond, retry, done},
		[][2]string{{"A", "ConditionalNode"}, {"ConditionalNode", "Retry"}, {"ConditionalNode", "Done"}},
		nodeA,
		"CondGraph",
	)
	if err != nil {
		t.Fatal(err)
	}

	state, _, err := graph.Execute(context.Background(), State{})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if state["answer"] != "recovered" {
		t.Fatalf("expected answer=recovered, got %v", state["answer"])
	}
}

func TestSplitText(t *testing.T) {
	text := "Hello world. This is a test. Another sentence here."
	chunks := splitText(text, 20)
	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}
	joined := ""
	for _, c := range chunks {
		joined += c
	}
	if joined != text {
		t.Fatalf("round-trip failed: %q", joined)
	}
}

// testNode is a simple Node implementation for unit tests.
type testNode struct {
	name   string
	inExpr string
	out    []string
	fn     func(State) State
}

func (n *testNode) Name() string      { return n.name }
func (n *testNode) NodeType() string  { return "node" }
func (n *testNode) InputExpr() string { return n.inExpr }
func (n *testNode) Outputs() []string { return n.out }
func (n *testNode) MinInputs() int    { return 0 }
func (n *testNode) Execute(ctx context.Context, state State) (State, string, error) {
	return n.fn(state.Clone()), "", nil
}
