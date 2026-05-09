package stealth

import (
	"github.com/skunkworq/stealth/brws/content/semantic"
)

// NewSemanticExtractor creates a semantic extractor that uses this stealth
// client's engine for fetching. This enables challenge-aware semantic
// extraction — anti-bot pages are automatically solved before the semantic
// tree is built.
func (c *Client) NewSemanticExtractor(config *semantic.PipelineConfig) *semantic.SemanticExtractor {
	return semantic.NewSemanticExtractorWithEngine(config, c.activeEngine())
}
