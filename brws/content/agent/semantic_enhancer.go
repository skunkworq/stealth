// Package interact — Semantic Enhancement Layer
//
// Bridges the brws/content/understand package into the agent observation loop,
// enriching PageSnapshots with structured metadata, semantic trees,
// and optional vision-based image descriptions.
package agent

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/brws/content/understand"
)

// SemanticEnhancer enriches PageSnapshots with semantic package features.
type SemanticEnhancer struct {
	// Feature toggles
	EnableTree     bool // Build semantic tree from DOM (no LLM required)
	EnableTreeLLM  bool // Use LLM for richer tree summaries (requires OPENROUTER_API_KEY)
	EnableMeta     bool // Extract page meta (title, description, OG, Twitter)
	EnableImages   bool // Extract image references
	EnableSocial   bool // Extract social media links
	EnableColors   bool // Extract color palette
	EnableFonts    bool // Extract font information
	DescribeImages bool // Describe images via vision API (requires OPENROUTER_API_KEY)

	// Optional pipeline config for LLM features.
	// If nil and EnableTreeLLM is true, the enhancer attempts to build
	// a config from the OPENROUTER_API_KEY environment variable.
	PipelineConfig *understand.PipelineConfig
}

// DefaultSemanticEnhancer returns an enhancer with all features off.
// Callers must explicitly enable the features they want.
func DefaultSemanticEnhancer() *SemanticEnhancer {
	return &SemanticEnhancer{}
}

// Enhance enriches a PageSnapshot using the page HTML.
// Errors from individual features are swallowed so that a partial
// enhancement never breaks the observation loop.
func (se *SemanticEnhancer) Enhance(ctx context.Context, snap *PageSnapshot, htmlStr, url string) error {
	if snap == nil || htmlStr == "" {
		return nil
	}

	// Parse the DOM once if any head-extract feature is enabled.
	var doc *html.Node
	if se.needsParsedDoc() {
		d, err := html.Parse(strings.NewReader(htmlStr))
		if err == nil {
			doc = d
		}
	}

	// Semantic tree (works without LLM; falls back to tag + raw text summaries).
	if se.EnableTree || se.EnableTreeLLM {
		if err := se.enhanceTree(ctx, snap, htmlStr, url); err != nil {
			// Non-fatal: tree enhancement is best-effort.
			_ = err
		}
	}

	if doc != nil {
		if se.EnableMeta {
			meta := understand.ExtractPageMeta(doc, url)
			snap.Meta = &meta
		}
		if se.EnableImages {
			snap.Images = understand.ExtractImagesFromDoc(doc, url)
		}
		if se.EnableSocial {
			social := understand.ExtractSocialLinks(doc)
			snap.Social = &social
		}
		if se.EnableColors {
			snap.Colors = understand.ExtractColors(doc)
		}
		if se.EnableFonts {
			snap.Fonts = understand.ExtractFonts(doc)
		}
	}

	// Vision-based image descriptions (requires LLM / OpenRouter).
	if se.DescribeImages && len(snap.Images) > 0 {
		se.describeImages(ctx, snap)
	}

	return nil
}

func (se *SemanticEnhancer) needsParsedDoc() bool {
	return se.EnableMeta || se.EnableImages || se.EnableSocial || se.EnableColors || se.EnableFonts
}

func (se *SemanticEnhancer) enhanceTree(ctx context.Context, snap *PageSnapshot, htmlStr, url string) error {
	config := se.PipelineConfig
	if config == nil {
		config = &understand.PipelineConfig{
			MaxChunks: 50,
		}
		// Attempt to load LLM config from env if LLM-enhanced tree is requested.
		if se.EnableTreeLLM {
			if envConfig, err := understand.NewConfigFromEnv(); err == nil {
				config = envConfig
			}
		}
	}

	tree, _, err := understand.HTMLToSemanticTreeCached(ctx, htmlStr, url, config)
	if err != nil {
		return fmt.Errorf("semantic tree: %w", err)
	}
	snap.SemanticTree = tree
	return nil
}

func (se *SemanticEnhancer) describeImages(ctx context.Context, snap *PageSnapshot) {
	llm := se.PipelineConfig.LLMClient
	if llm == nil {
		return
	}

	for i := range snap.Images {
		img := &snap.Images[i]
		if img.URL == "" || strings.HasPrefix(img.URL, "data:") {
			continue
		}
		desc, err := llm.DescribeImage(ctx, img.URL)
		if err == nil && desc != "" {
			img.Description = desc
		}
	}
}
