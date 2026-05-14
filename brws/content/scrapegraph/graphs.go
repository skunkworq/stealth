package scrapegraph

import (
	"context"
	"fmt"
	"sync"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
	"github.com/skunkworq/stealth/brws/stealth"
)

// ---------------------------------------------------------------------------
// Pipeline (AbstractGraph equivalent)
// ---------------------------------------------------------------------------

// Pipeline is the scaffolding that assembles nodes into a concrete graph.
type Pipeline struct {
	Prompt     string
	Source     string
	Config     map[string]interface{}
	Schema     interface{}
	LLM        LLM
	Graph      *BaseGraph
	InputKey   string // "url" or "local_dir"
	ModelToken int

	// Engine optionally sets the fetch engine for all FetchNodes in the graph.
	// Takes precedence over the default native engine.
	// StealthClient takes precedence over Engine when both are set.
	Engine engine.Engine

	// StealthClient optionally provides challenge-aware fetching.
	// Takes precedence over Engine.
	StealthClient *stealth.Adaptive
}

// NewPipeline creates the common scaffolding.
func NewPipeline(prompt, source string, config map[string]interface{}, schema interface{}, llm LLM) (*Pipeline, error) {
	if llm == nil {
		var err error
		llm, err = NewLLMFromEnv()
		if err != nil {
			return nil, err
		}
	}
	inputKey := "url"
	if source != "" && !(len(source) > 4 && (source[:4] == "http" || source[:5] == "https")) {
		inputKey = "local_dir"
	}
	model := "openai/gpt-4o"
	if m, ok := config["model"].(string); ok && m != "" {
		model = m
	}
	return &Pipeline{
		Prompt:     prompt,
		Source:     source,
		Config:     config,
		Schema:     schema,
		LLM:        llm,
		InputKey:   inputKey,
		ModelToken: LookupTokenLimit(model),
	}, nil
}

// Run executes the underlying graph with the initial state.
func (p *Pipeline) Run(ctx context.Context) (State, []ExecutionInfo, error) {
	if p.Graph == nil {
		return nil, nil, fmt.Errorf("graph not built")
	}
	state := State{
		"user_prompt": p.Prompt,
		p.InputKey:    p.Source,
	}
	return p.Graph.Execute(ctx, state)
}

// ---------------------------------------------------------------------------
// SmartScraperGraph
// ---------------------------------------------------------------------------

// SmartScraperGraph is the flagship scraper: Fetch -> Parse -> GenerateAnswer.
// Optional reasoning and re-attempt nodes can be enabled via config flags.
type SmartScraperGraph struct {
	Pipeline
}

// NewSmartScraperGraphWithEngine builds a SmartScraperGraph using the given engine for fetching.
func NewSmartScraperGraphWithEngine(prompt, source string, config map[string]interface{}, schema interface{}, llm LLM, eng engine.Engine) (*SmartScraperGraph, error) {
	ss, err := NewSmartScraperGraph(prompt, source, config, schema, llm)
	if err != nil {
		return nil, err
	}
	ss.Engine = eng
	graph, err := ss.buildGraph()
	if err != nil {
		return nil, err
	}
	ss.Graph = graph
	return ss, nil
}

// NewSmartScraperGraphWithStealth builds a SmartScraperGraph with a stealth client.
func NewSmartScraperGraphWithStealth(prompt, source string, config map[string]interface{}, schema interface{}, llm LLM, client *stealth.Adaptive) (*SmartScraperGraph, error) {
	ss, err := NewSmartScraperGraph(prompt, source, config, schema, llm)
	if err != nil {
		return nil, err
	}
	ss.StealthClient = client
	graph, err := ss.buildGraph()
	if err != nil {
		return nil, err
	}
	ss.Graph = graph
	return ss, nil
}

// NewSmartScraperGraph builds a SmartScraperGraph pipeline.
func NewSmartScraperGraph(prompt, source string, config map[string]interface{}, schema interface{}, llm LLM) (*SmartScraperGraph, error) {
	pipe, err := NewPipeline(prompt, source, config, schema, llm)
	if err != nil {
		return nil, err
	}
	ss := &SmartScraperGraph{Pipeline: *pipe}
	graph, err := ss.buildGraph()
	if err != nil {
		return nil, err
	}
	ss.Graph = graph
	return ss, nil
}

func (ss *SmartScraperGraph) buildGraph() (*BaseGraph, error) {
	cfg := ss.Config
	llm := ss.LLM
	schema := ss.Schema

	// Core nodes
	fetch := NewFetchNode("url | local_dir", "doc", cfg)
	if ss.StealthClient != nil {
		fetch.StealthClient = ss.StealthClient
	} else if ss.Engine != nil {
		fetch.Engine = ss.Engine
	}
	parse := NewParseNode("doc", "parsed_doc", ss.ModelToken, cfg)
	gen := NewGenerateAnswerNode(
		"user_prompt & (relevant_chunks | parsed_doc | doc)",
		"answer",
		llm,
		map[string]interface{}{
			"schema":          schema,
			"additional_info": cfg["additional_info"],
		},
	)

	// Optional reasoning node
	var reasoning *ReasoningNode
	if cfg["reasoning"] == true {
		reasoning = NewReasoningNode(
			"user_prompt & (relevant_chunks | parsed_doc | doc)",
			"reasoning",
			llm,
			map[string]interface{}{"schema": schema},
		)
	}

	// Optional re-attempt conditional
	var cond *ConditionalNode
	var regen *GenerateAnswerNode
	if cfg["reattempt"] == true {
		cond = NewConditionalNode(
			"answer",
			"answer",
			map[string]interface{}{
				"key_name":  "answer",
				"condition": `not answer or answer=="NA"`,
			},
			"RegenNode",
			"", // false branch -> terminate
		)
		regen = NewGenerateAnswerNode(
			"user_prompt & answer",
			"answer",
			llm,
			map[string]interface{}{
				"schema":          schema,
				"additional_info": "The previous extraction failed or returned NA. Try a different strategy.",
			},
		)
		regen.Base.nodeName = "RegenNode"
	}

	htmlMode := cfg["html_mode"] == true
	reasoningEnabled := cfg["reasoning"] == true
	reattemptEnabled := cfg["reattempt"] == true

	var nodes []Node
	var edges [][2]string

	// Strategy pattern: assemble nodes and edges based on flags.
	switch {
	case !htmlMode && !reasoningEnabled && !reattemptEnabled:
		// Default: Fetch -> Parse -> GenerateAnswer
		nodes = []Node{fetch, parse, gen}
		edges = [][2]string{{fetch.Name(), parse.Name()}, {parse.Name(), gen.Name()}}
	case htmlMode && !reasoningEnabled && !reattemptEnabled:
		// Fast path: Fetch -> GenerateAnswer (skip parse)
		nodes = []Node{fetch, gen}
		edges = [][2]string{{fetch.Name(), gen.Name()}}
	case !htmlMode && reasoningEnabled && !reattemptEnabled:
		// Fetch -> Parse -> Reasoning -> GenerateAnswer
		nodes = []Node{fetch, parse, reasoning, gen}
		edges = [][2]string{
			{fetch.Name(), parse.Name()},
			{parse.Name(), reasoning.Name()},
			{reasoning.Name(), gen.Name()},
		}
	case htmlMode && reasoningEnabled && !reattemptEnabled:
		// Fetch -> Reasoning -> GenerateAnswer
		nodes = []Node{fetch, reasoning, gen}
		edges = [][2]string{
			{fetch.Name(), reasoning.Name()},
			{reasoning.Name(), gen.Name()},
		}
	case !htmlMode && !reasoningEnabled && reattemptEnabled:
		// Fetch -> Parse -> GenerateAnswer -> Conditional -> Regen
		nodes = []Node{fetch, parse, gen, cond, regen}
		edges = [][2]string{
			{fetch.Name(), parse.Name()},
			{parse.Name(), gen.Name()},
			{gen.Name(), cond.Name()},
			{cond.Name(), regen.Name()}, // true branch
			// cond false branch terminates (empty string target)
		}
	case !htmlMode && reasoningEnabled && reattemptEnabled:
		// Fetch -> Parse -> Reasoning -> GenerateAnswer -> Conditional -> Regen
		nodes = []Node{fetch, parse, reasoning, gen, cond, regen}
		edges = [][2]string{
			{fetch.Name(), parse.Name()},
			{parse.Name(), reasoning.Name()},
			{reasoning.Name(), gen.Name()},
			{gen.Name(), cond.Name()},
			{cond.Name(), regen.Name()},
		}
	case htmlMode && reasoningEnabled && reattemptEnabled:
		// Fetch -> Reasoning -> GenerateAnswer -> Conditional -> Regen
		nodes = []Node{fetch, reasoning, gen, cond, regen}
		edges = [][2]string{
			{fetch.Name(), reasoning.Name()},
			{reasoning.Name(), gen.Name()},
			{gen.Name(), cond.Name()},
			{cond.Name(), regen.Name()},
		}
	case htmlMode && !reasoningEnabled && reattemptEnabled:
		// Fetch -> GenerateAnswer -> Conditional -> Regen
		nodes = []Node{fetch, gen, cond, regen}
		edges = [][2]string{
			{fetch.Name(), gen.Name()},
			{gen.Name(), cond.Name()},
			{cond.Name(), regen.Name()},
		}
	default:
		return nil, fmt.Errorf("unsupported graph configuration")
	}

	return NewBaseGraph(nodes, edges, fetch, "SmartScraperGraph")
}

// ---------------------------------------------------------------------------
// SearchGraph
// ---------------------------------------------------------------------------

// SearchGraph autonomously searches the web and scrapes top results.
type SearchGraph struct {
	Pipeline
}

// NewSearchGraph builds a SearchGraph pipeline.
func NewSearchGraph(prompt string, config map[string]interface{}, schema interface{}, llm LLM) (*SearchGraph, error) {
	pipe, err := NewPipeline(prompt, "", config, schema, llm)
	if err != nil {
		return nil, err
	}
	sg := &SearchGraph{Pipeline: *pipe}
	graph, err := sg.buildGraph()
	if err != nil {
		return nil, err
	}
	sg.Graph = graph
	return sg, nil
}

// NewSearchGraphWithEngine builds a SearchGraph using the given engine for fetching.
func NewSearchGraphWithEngine(prompt string, config map[string]interface{}, schema interface{}, llm LLM, eng engine.Engine) (*SearchGraph, error) {
	sg, err := NewSearchGraph(prompt, config, schema, llm)
	if err != nil {
		return nil, err
	}
	sg.Engine = eng
	graph, err := sg.buildGraph()
	if err != nil {
		return nil, err
	}
	sg.Graph = graph
	return sg, nil
}

// NewSearchGraphWithStealth builds a SearchGraph with a stealth client.
func NewSearchGraphWithStealth(prompt string, config map[string]interface{}, schema interface{}, llm LLM, client *stealth.Adaptive) (*SearchGraph, error) {
	sg, err := NewSearchGraph(prompt, config, schema, llm)
	if err != nil {
		return nil, err
	}
	sg.StealthClient = client
	// Rebuild the graph with the stealth client injected into the iterator
	graph, err := sg.buildGraph()
	if err != nil {
		return nil, err
	}
	sg.Graph = graph
	return sg, nil
}

func (sg *SearchGraph) buildGraph() (*BaseGraph, error) {
	cfg := sg.Config
	llm := sg.LLM
	schema := sg.Schema

	search := NewSearchInternetNode("user_prompt", "urls", llm, cfg)

	// GraphIteratorNode equivalent: for each URL, run a SmartScraperGraph.
	// In the Go implementation we model this as a single node that iterates.
	iterate := &GraphIteratorNode{
		Base: baseNode{
			nodeName:   "GraphIteratorNode",
			nodeType:   "node",
			inputExpr:  "user_prompt & urls",
			output:     []string{"results"},
			minInputs:  2,
			nodeConfig: cfg,
		},
		LLM:           llm,
		Schema:        schema,
		Engine:        sg.Engine,
		StealthClient: sg.StealthClient,
	}

	merge := NewMergeAnswersNode("user_prompt & results", "answer", llm,
		map[string]interface{}{"schema": schema},
	)

	nodes := []Node{search, iterate, merge}
	edges := [][2]string{
		{search.Name(), iterate.Name()},
		{iterate.Name(), merge.Name()},
	}

	return NewBaseGraph(nodes, edges, search, "SearchGraph")
}

// ---------------------------------------------------------------------------
// GraphIteratorNode
// ---------------------------------------------------------------------------

// GraphIteratorNode runs a scraper for each URL with semaphore-controlled
// concurrency.
type GraphIteratorNode struct {
	Base          baseNode
	LLM           LLM
	Schema        interface{}
	BatchSize     int
	Engine        engine.Engine
	StealthClient *stealth.Adaptive
}

func (n *GraphIteratorNode) Name() string      { return n.Base.nodeName }
func (n *GraphIteratorNode) NodeType() string  { return n.Base.nodeType }
func (n *GraphIteratorNode) InputExpr() string { return n.Base.inputExpr }
func (n *GraphIteratorNode) Outputs() []string { return n.Base.output }
func (n *GraphIteratorNode) MinInputs() int    { return n.Base.minInputs }

func (n *GraphIteratorNode) Execute(ctx context.Context, state State) (State, string, error) {
	userPrompt, _ := state["user_prompt"].(string)
	urls, ok := state["urls"].([]string)
	if !ok || len(urls) == 0 {
		return state, "", fmt.Errorf("graph iterator requires urls")
	}

	batch := n.BatchSize
	if batch <= 0 {
		batch = 4
	}

	results := make([]interface{}, len(urls))
	sem := make(chan struct{}, batch)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var graph *SmartScraperGraph
			var err error
			if n.StealthClient != nil {
				graph, err = NewSmartScraperGraphWithStealth(userPrompt, url, n.Base.nodeConfig, n.Schema, n.LLM, n.StealthClient)
			} else if n.Engine != nil {
				graph, err = NewSmartScraperGraphWithEngine(userPrompt, url, n.Base.nodeConfig, n.Schema, n.LLM, n.Engine)
			} else {
				graph, err = NewSmartScraperGraph(userPrompt, url, n.Base.nodeConfig, n.Schema, n.LLM)
			}
			if err != nil {
				return
			}
			out, _, err := graph.Run(ctx)
			if err != nil {
				return
			}
			ans := out["answer"]
			mu.Lock()
			results[idx] = ans
			mu.Unlock()
		}(i, u)
	}
	wg.Wait()

	out := state.Clone()
	out[n.Base.output[0]] = results
	return out, "", nil
}
