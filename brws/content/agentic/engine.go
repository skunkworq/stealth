// Package agentic provides a directed-graph execution engine for LLM-centric
// web scraping. It is modeled after the ScrapeGraphAI architecture and operates
// independently from the browser-agent system in brws/content/agent.
package agentic

import (
	"context"
	"fmt"
	"time"
	"unicode"
)

// State is the shared mutable dictionary that flows through the graph.
type State map[string]interface{}

// Clone returns a shallow copy of the state.
func (s State) Clone() State {
	out := make(State, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// Node is the processing unit in the graph.
type Node interface {
	Name() string
	NodeType() string // "node" or "conditional_node"
	InputExpr() string
	Outputs() []string
	MinInputs() int
	// Execute runs the node. For conditional nodes the second return value is
	// the name of the next node to jump to; for regular nodes it is empty.
	Execute(ctx context.Context, state State) (State, string, error)
}

// ExecutionInfo tracks per-node telemetry.
type ExecutionInfo struct {
	NodeName           string        `json:"node_name"`
	TotalTokens        int           `json:"total_tokens"`
	PromptTokens       int           `json:"prompt_tokens"`
	CompletionTokens   int           `json:"completion_tokens"`
	SuccessfulRequests int           `json:"successful_requests"`
	TotalCostUSD       float64       `json:"total_cost_usd"`
	ExecTime           time.Duration `json:"exec_time"`
}

// BaseGraph is the execution engine that drives nodes in a loop.
type BaseGraph struct {
	Nodes      []Node
	Edges      map[string][]string // from -> tos
	EntryPoint string
	GraphName  string
}

// NewBaseGraph builds a graph from nodes and edges.
// Edges are given as pairs: (from, to). For conditional nodes the first edge
// is the "true" branch and the second is the "false" branch.
func NewBaseGraph(nodes []Node, edges [][2]string, entryPoint Node, graphName string) (*BaseGraph, error) {
	if entryPoint == nil {
		return nil, fmt.Errorf("entry point cannot be nil")
	}
	g := &BaseGraph{
		Nodes:      nodes,
		Edges:      make(map[string][]string, len(edges)),
		EntryPoint: entryPoint.Name(),
		GraphName:  graphName,
	}
	for _, e := range edges {
		g.Edges[e[0]] = append(g.Edges[e[0]], e[1])
	}
	// Validate conditional nodes have exactly 2 outgoing edges.
	for _, n := range nodes {
		if n.NodeType() == "conditional_node" {
			outs := g.Edges[n.Name()]
			if len(outs) != 2 {
				return nil, fmt.Errorf("conditional node %q must have exactly 2 outgoing edges, got %d", n.Name(), len(outs))
			}
		}
	}
	return g, nil
}

// Execute runs the graph until there is no next node.
func (g *BaseGraph) Execute(ctx context.Context, initialState State) (State, []ExecutionInfo, error) {
	current := g.EntryPoint
	state := initialState.Clone()
	var execInfo []ExecutionInfo

	for current != "" {
		node := g.getNode(current)
		if node == nil {
			return state, execInfo, fmt.Errorf("node %q not found", current)
		}

		start := time.Now()
		resultState, condNext, err := node.Execute(ctx, state)
		elapsed := time.Since(start)

		if err != nil {
			return state, execInfo, fmt.Errorf("node %q failed: %w", node.Name(), err)
		}

		// Merge result state back.
		for k, v := range resultState {
			state[k] = v
		}

		execInfo = append(execInfo, ExecutionInfo{
			NodeName: node.Name(),
			ExecTime: elapsed,
		})

		// Route to next node.
		if node.NodeType() == "conditional_node" {
			// condNext is the node name to jump to; empty string means terminate.
			current = condNext
		} else {
			nexts := g.Edges[node.Name()]
			if len(nexts) == 0 {
				current = ""
			} else if len(nexts) == 1 {
				current = nexts[0]
			} else {
				// Non-conditional nodes with multiple outgoing edges is unusual;
				// default to first.
				current = nexts[0]
			}
		}
	}

	return state, execInfo, nil
}

func (g *BaseGraph) getNode(name string) Node {
	for _, n := range g.Nodes {
		if n.Name() == name {
			return n
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Input expression parser
// ---------------------------------------------------------------------------

// ParseInputKeys evaluates a boolean expression against state keys and returns
// the list of matching keys. Supported operators: & (AND), | (OR), parentheses.
func ParseInputKeys(state State, expression string) ([]string, error) {
	p := &exprParser{
		tokens: tokenizeExpr(expression),
		state:  state,
	}
	return p.parseExpr()
}

// exprParser implements a tiny recursive-descent parser for the input grammar.
type exprParser struct {
	tokens []string
	pos    int
	state  State
}

func (p *exprParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *exprParser) consume() string {
	tok := p.peek()
	p.pos++
	return tok
}

func (p *exprParser) parseExpr() ([]string, error) {
	// expr = term { '|' term }
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for p.peek() == "|" {
		p.consume() // '|'
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		// OR: if left is empty, try right.
		if len(left) > 0 {
			return left, nil
		}
		left = right
	}
	return left, nil
}

func (p *exprParser) parseTerm() ([]string, error) {
	// term = factor { '&' factor }
	left, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	for p.peek() == "&" {
		p.consume() // '&'
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		// AND: merge keys; if either side is empty the whole term is empty.
		if len(left) == 0 || len(right) == 0 {
			return nil, nil
		}
		left = mergeKeys(left, right)
	}
	return left, nil
}

func (p *exprParser) parseFactor() ([]string, error) {
	tok := p.peek()
	if tok == "" {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	if tok == "(" {
		p.consume() // '('
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.consume() // ')'
		return inner, nil
	}
	if tok == ")" || tok == "&" || tok == "|" {
		return nil, fmt.Errorf("unexpected token %q", tok)
	}
	p.consume() // identifier
	if _, ok := p.state[tok]; ok {
		return []string{tok}, nil
	}
	return nil, nil
}

func tokenizeExpr(expr string) []string {
	var tokens []string
	runes := []rune(expr)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if unicode.IsSpace(c) {
			continue
		}
		if c == '(' || c == ')' || c == '&' || c == '|' {
			tokens = append(tokens, string(c))
			continue
		}
		// identifier
		start := i
		for i < len(runes) && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_') {
			i++
		}
		tokens = append(tokens, string(runes[start:i]))
		i-- // compensate for loop increment
	}
	return tokens
}

func mergeKeys(a, b []string) []string {
	m := make(map[string]struct{}, len(a)+len(b))
	for _, k := range a {
		m[k] = struct{}{}
	}
	for _, k := range b {
		m[k] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
