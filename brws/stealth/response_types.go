package stealth

import "github.com/skunkworq/stealth/brws/content/understand"

// Type aliases so existing code that constructs stealth.PageMeta{…} etc. continues to compile.
type (
	PageMeta         = understand.PageMeta
	SocialLinks      = understand.SocialLinks
	Link             = understand.Link
	ColorInfo        = understand.ColorInfo
	FontInfo         = understand.FontInfo
	ImageWithContext = understand.ImageWithContext
)
