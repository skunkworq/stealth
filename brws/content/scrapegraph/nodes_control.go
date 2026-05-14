package scrapegraph

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// ConditionalNode
// ---------------------------------------------------------------------------

// ConditionalNode branches execution based on a runtime condition.
type ConditionalNode struct {
	Base         baseNode
	KeyName      string
	Condition    string
	TrueNodeName string
	FalseNodeName string
}

// NewConditionalNode creates a conditional branching node.
// The edges slice in the graph must supply exactly two outgoing edges:
// index 0 = true branch, index 1 = false branch.
func NewConditionalNode(input, output string, nodeConfig map[string]interface{}, trueNode, falseNode string) *ConditionalNode {
	key, _ := nodeConfig["key_name"].(string)
	cond, _ := nodeConfig["condition"].(string)
	return &ConditionalNode{
		Base: baseNode{
			nodeName:   "ConditionalNode",
			nodeType:   "conditional_node",
			inputExpr:  input,
			output:     []string{output},
			minInputs:  1,
			nodeConfig: nodeConfig,
		},
		KeyName:       key,
		Condition:     cond,
		TrueNodeName:  trueNode,
		FalseNodeName: falseNode,
	}
}

func (n *ConditionalNode) Name() string      { return n.Base.nodeName }
func (n *ConditionalNode) NodeType() string  { return n.Base.nodeType }
func (n *ConditionalNode) InputExpr() string { return n.Base.inputExpr }
func (n *ConditionalNode) Outputs() []string { return n.Base.output }
func (n *ConditionalNode) MinInputs() int    { return n.Base.minInputs }

func (n *ConditionalNode) Execute(ctx context.Context, state State) (State, string, error) {
	var result bool
	if n.Condition != "" {
		var err error
		result, err = evalCondition(state, n.Condition)
		if err != nil {
			return state, "", fmt.Errorf("condition evaluation: %w", err)
		}
	} else {
		v, ok := state[n.KeyName]
		result = ok && v != nil && v != ""
	}

	if result {
		return state, n.TrueNodeName, nil
	}
	return state, n.FalseNodeName, nil
}

// evalCondition parses a tiny boolean expression language and evaluates it
// against the state map. Supported: not, and, or, ==, !=, parentheses.
func evalCondition(state State, expr string) (bool, error) {
	// Normalize Python-like operators to Go-like.
	normalized := strings.ToLower(expr)
	normalized = strings.ReplaceAll(normalized, "not ", "!")
	normalized = strings.ReplaceAll(normalized, " and ", " && ")
	normalized = strings.ReplaceAll(normalized, " or ", " || ")
	normalized = strings.ReplaceAll(normalized, "==", "==")
	normalized = strings.ReplaceAll(normalized, "!=", "!=")

	fset := token.NewFileSet()
	node, err := parser.ParseExprFrom(fset, "", normalized, 0)
	if err != nil {
		return false, fmt.Errorf("parse condition %q: %w", expr, err)
	}

	return evalAST(node, state)
}

func evalAST(node ast.Expr, state State) (bool, error) {
	switch n := node.(type) {
	case *ast.BinaryExpr:
		left, err := evalAST(n.X, state)
		if err != nil {
			return false, err
		}
		right, err := evalAST(n.Y, state)
		if err != nil {
			return false, err
		}
		switch n.Op {
		case token.LAND:
			return left && right, nil
		case token.LOR:
			return left || right, nil
		case token.EQL:
			// String equality only for our mini-language.
			ls, err := evalString(n.X, state)
			if err != nil {
				return false, err
			}
			rs, err := evalString(n.Y, state)
			if err != nil {
				return false, err
			}
			return ls == rs, nil
		case token.NEQ:
			ls, err := evalString(n.X, state)
			if err != nil {
				return false, err
			}
			rs, err := evalString(n.Y, state)
			if err != nil {
				return false, err
			}
			return ls != rs, nil
		default:
			return false, fmt.Errorf("unsupported operator %v", n.Op)
		}
	case *ast.UnaryExpr:
		if n.Op == token.NOT {
			val, err := evalAST(n.X, state)
			if err != nil {
				return false, err
			}
			return !val, nil
		}
		return false, fmt.Errorf("unsupported unary operator %v", n.Op)
	case *ast.BasicLit:
		if n.Kind == token.STRING {
			s, err := strconv.Unquote(n.Value)
			if err != nil {
				return false, err
			}
			return s != "", nil
		}
		return false, fmt.Errorf("unsupported literal %v", n.Kind)
	case *ast.Ident:
		// Lookup in state
		v, ok := state[n.Name]
		if !ok {
			return false, nil // missing key == falsy
		}
		switch val := v.(type) {
		case bool:
			return val, nil
		case string:
			return val != "" && val != "NA", nil
		case nil:
			return false, nil
		default:
			return true, nil
		}
	case *ast.ParenExpr:
		return evalAST(n.X, state)
	default:
		return false, fmt.Errorf("unsupported expression type %T", node)
	}
}

func evalString(node ast.Expr, state State) (string, error) {
	switch n := node.(type) {
	case *ast.BasicLit:
		if n.Kind == token.STRING {
			return strconv.Unquote(n.Value)
		}
		return n.Value, nil
	case *ast.Ident:
		v, ok := state[n.Name]
		if !ok {
			return "", nil
		}
		if s, ok := v.(string); ok {
			return s, nil
		}
		return fmt.Sprintf("%v", v), nil
	default:
		return "", fmt.Errorf("cannot evaluate %T as string", node)
	}
}
