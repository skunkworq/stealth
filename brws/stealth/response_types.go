package stealth

import "github.com/skunkworq/stealth/brws/content/semantic"

// Type aliases so existing code that constructs stealth.PageMeta{…} etc. continues to compile.
type (
	PageMeta         = semantic.PageMeta
	SocialLinks      = semantic.SocialLinks
	Link             = semantic.Link
	ColorInfo        = semantic.ColorInfo
	FontInfo         = semantic.FontInfo
	ImageWithContext = semantic.ImageWithContext
)
