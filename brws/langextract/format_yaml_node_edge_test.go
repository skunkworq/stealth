package langextract

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestYAMLNodeToOrderedEdgeKinds(t *testing.T) {
	t.Parallel()

	if got := yamlNodeToOrdered(nil); got != nil {
		t.Fatalf("expected nil for nil node, got %T", got)
	}

	emptyDoc := &yaml.Node{Kind: yaml.DocumentNode}
	if got := yamlNodeToOrdered(emptyDoc); got != nil {
		t.Fatalf("expected nil for empty document node, got %T", got)
	}

	scalar := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "42"}
	alias := &yaml.Node{Kind: yaml.AliasNode, Alias: scalar}
	if got := yamlNodeToOrdered(alias); got != 42 {
		t.Fatalf("expected alias scalar decode to 42, got %v (%T)", got, got)
	}

	oddMapping := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "dangling_key"},
		},
	}
	got := yamlNodeToOrdered(oddMapping)
	obj, ok := got.(orderedObject)
	if !ok {
		t.Fatalf("expected orderedObject for mapping node, got %T", got)
	}
	if len(obj.Pairs) != 0 {
		t.Fatalf("expected dangling mapping key to be ignored, got %+v", obj.Pairs)
	}

	unknown := &yaml.Node{Kind: 999}
	if got := yamlNodeToOrdered(unknown); got != nil {
		t.Fatalf("expected nil for unsupported node kind, got %T", got)
	}
}
