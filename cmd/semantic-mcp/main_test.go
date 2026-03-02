package main

import (
	"testing"

	"github.com/stealth/brwslab/brws/semantic"
	"github.com/stealth/brwslab/brws/semantic/index"
)

func TestMCPServerInit(t *testing.T) {
	tools := &Tools{
		config: nil,
		cache:  nil,
		index:  index.NewHNSWIndex(1536),
	}

	if tools == nil {
		t.Error("Failed to create tools")
	}
}

func TestFetchTreeInvalidURL(t *testing.T) {
	tools := &Tools{
		config: &semantic.PipelineConfig{},
		cache:  nil,
		index:  nil,
	}

	_, err := tools.fetchTree(nil, "not-a-valid-url")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}
