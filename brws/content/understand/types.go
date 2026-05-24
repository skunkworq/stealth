package understand

import coretypes "github.com/skunkworq/stealth/brws/core/types"

// Type aliases — the canonical definitions live in brws/core/types so that
// lower-layer packages (e.g. brws/stealth) can reference them without
// creating an upward import into content/understand.
type (
	PageMeta         = coretypes.PageMeta
	SocialLinks      = coretypes.SocialLinks
	Link             = coretypes.Link
	ColorInfo        = coretypes.ColorInfo
	FontInfo         = coretypes.FontInfo
	ImageWithContext = coretypes.ImageWithContext
)
