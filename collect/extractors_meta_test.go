package collect

import (
	"context"
	"testing"

	"github.com/skunkworq/stealth/extract"
)

func TestMetaExtractorSocialAndLogo(t *testing.T) {
	raw := `<html><head>
	<meta property="og:image" content="https://acme.com.au/logo.png">
	</head><body>
	<a href="https://facebook.com/acmeplumbing">fb</a>
	<a href="https://instagram.com/acmeplumbing">ig</a>
	</body></html>`
	doc := &extract.SourceDocument{Ref: "https://acme.com.au/", ContentType: "text/html", Text: raw}
	cands, err := MetaExtractor{}.Extract(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[extract.FieldKey]string{}
	for _, c := range cands {
		got[c.Key] = c.Value
	}
	if got[extract.KeySocialFB] == "" {
		t.Error("facebook not extracted")
	}
	if got[extract.KeySocialIG] == "" {
		t.Error("instagram not extracted")
	}
	if got[extract.KeyLogoURL] != "https://acme.com.au/logo.png" {
		t.Errorf("logo %q", got[extract.KeyLogoURL])
	}
}
