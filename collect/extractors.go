package collect

import (
	"context"
	"encoding/json"
	"strings"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/extract"
)

// LdJSONExtractor harvests schema.org fields from <script type=application/ld+json>
// blocks. Each emitted value is the literal JSON string (verbatim in doc.Text),
// so the Validator confirms it. Runs only on raw-HTML documents.
type LdJSONExtractor struct{}

func (LdJSONExtractor) Name() string { return "ld_json" }

func (LdJSONExtractor) Extract(_ context.Context, doc *extract.SourceDocument) ([]extract.Candidate, error) {
	if doc == nil || doc.ContentType != "text/html" {
		return nil, nil
	}
	node, err := html.Parse(strings.NewReader(doc.Text))
	if err != nil {
		return nil, nil
	}
	var out []extract.Candidate
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" &&
			attrVal(n, "type") == "application/ld+json" && n.FirstChild != nil {
			out = append(out, candidatesFromLdJSON(n.FirstChild.Data)...)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(node)
	return out, nil
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func candidatesFromLdJSON(raw string) []extract.Candidate {
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &v); err != nil {
		return nil
	}
	var out []extract.Candidate
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			str := func(k string) string {
				s, _ := t[k].(string)
				return strings.TrimSpace(s)
			}
			emit := func(val string, fk extract.FieldKey, conf float64) {
				if val != "" {
					out = append(out, extract.Candidate{Key: fk, Value: val, Method: extract.MethodLdJSON, Conf: conf})
				}
			}
			emit(str("telephone"), extract.KeyPhone, 0.95)
			emit(str("email"), extract.KeyEmail, 0.95)
			emit(str("url"), extract.KeyWebsite, 0.8)
			if ln := str("legalName"); ln != "" {
				emit(ln, extract.KeyLegalName, 0.8)
			} else {
				emit(str("name"), extract.KeyLegalName, 0.7)
			}
			switch lg := t["logo"].(type) {
			case string:
				emit(strings.TrimSpace(lg), extract.KeyLogoURL, 0.8)
			case map[string]any:
				if u, ok := lg["url"].(string); ok {
					emit(strings.TrimSpace(u), extract.KeyLogoURL, 0.8)
				}
			}
			if addr, ok := t["address"].(map[string]any); ok {
				if s, ok := addr["streetAddress"].(string); ok {
					emit(strings.TrimSpace(s), extract.KeyAddress, 0.85)
				}
			} else if s, ok := t["address"].(string); ok {
				emit(strings.TrimSpace(s), extract.KeyAddress, 0.85)
			}
			for _, val := range t {
				walk(val) // recurse into @graph / nested objects
			}
		}
	}
	walk(v)
	return out
}
