package stealth

import (
	"github.com/skunkworq/stealth/brws/content/understand"
)

// NewSemanticExtractor creates a semantic extractor that uses this stealth
// client's engine for fetching. This enables challenge-aware semantic
// extraction — anti-bot pages are automatically solved before the semantic
// tree is built.
func (c *Adaptive) NewSemanticExtractor(config *understand.PipelineConfig) *understand.SemanticExtractor {
	return understand.NewSemanticExtractorWithEngine(config, c.activeEngine())
}
