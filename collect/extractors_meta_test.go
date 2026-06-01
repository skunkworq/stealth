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

func TestMetaExtractorFiltersPlatformSocials(t *testing.T) {
	junk := &extract.SourceDocument{Ref: "r", ContentType: "text/html",
		Text: `<html><body><a href="https://www.facebook.com/wix">x</a>
		<a href="https://www.instagram.com/squarespace">y</a>
		<a href="https://www.facebook.com/sharer/sharer.php?u=x">z</a></body></html>`}
	for _, c := range mustExtract(t, junk) {
		if c.Key == extract.KeySocialFB || c.Key == extract.KeySocialIG {
			t.Errorf("platform/share social should be filtered: %s", c.Value)
		}
	}
	real := &extract.SourceDocument{Ref: "r", ContentType: "text/html",
		Text: `<html><body><a href="https://www.facebook.com/acmeplumbing">fb</a></body></html>`}
	var got bool
	for _, c := range mustExtract(t, real) {
		if c.Key == extract.KeySocialFB {
			got = true
		}
	}
	if !got {
		t.Error("a real facebook profile must still be extracted")
	}
}

func mustExtract(t *testing.T, doc *extract.SourceDocument) []extract.Candidate {
	t.Helper()
	cs, err := MetaExtractor{}.Extract(contextTODO(), doc)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func contextTODO() context.Context { return context.Background() }
