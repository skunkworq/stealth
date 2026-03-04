package semantic

// PageMeta contains metadata extracted from an HTML page.
type PageMeta struct {
	Title        string            `json:"title,omitempty"`
	Description  string            `json:"description,omitempty"`
	Author       string            `json:"author,omitempty"`
	Publisher    string            `json:"publisher,omitempty"`
	CanonicalURL string            `json:"canonical_url,omitempty"`
	Language     string            `json:"language,omitempty"`
	Keywords     []string          `json:"keywords,omitempty"`
	OG           map[string]string `json:"og,omitempty"`
	TwitterCard  map[string]string `json:"twitter_card,omitempty"`
}

// SocialLinks contains social media profile URLs found on a page.
type SocialLinks struct {
	LinkedIn  string `json:"linkedin,omitempty"`
	Twitter   string `json:"twitter,omitempty"`
	Instagram string `json:"instagram,omitempty"`
	Facebook  string `json:"facebook,omitempty"`
	YouTube   string `json:"youtube,omitempty"`
	GitHub    string `json:"github,omitempty"`
	TikTok    string `json:"tiktok,omitempty"`
	Pinterest string `json:"pinterest,omitempty"`
	Discord   string `json:"discord,omitempty"`
}

// Link represents an anchor link found on a page.
type Link struct {
	URL        string `json:"url"`
	Text       string `json:"text,omitempty"`
	IsExternal bool   `json:"is_external"`
	IsNofollow bool   `json:"is_nofollow,omitempty"`
}

// ColorInfo represents a color found on a page.
type ColorInfo struct {
	Hex    string `json:"hex"`
	Source string `json:"source,omitempty"` // "meta" or "css"
}

// FontInfo represents a font found on a page.
type FontInfo struct {
	Family   string   `json:"family"`
	Variants []string `json:"variants,omitempty"`
	Source   string   `json:"source,omitempty"` // "google-fonts" or "css"
}
