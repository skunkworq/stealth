package collect

import (
	"strings"
	"testing"
)

func TestVisibleTextStripsScriptStyleAndKeepsText(t *testing.T) {
	raw := `<html><head><title>T</title><style>.x{}</style></head>
	<body><script>var a=1;</script><h1>Acme Plumbing</h1><p>Call 0412 345 678</p>
	<div>bob@acme.com.au</div></body></html>`
	got := visibleText(raw)
	if strings.Contains(got, "var a=1") || strings.Contains(got, ".x{}") {
		t.Fatalf("script/style leaked: %q", got)
	}
	if !strings.Contains(got, "Acme Plumbing") || !strings.Contains(got, "0412 345 678") || !strings.Contains(got, "bob@acme.com.au") {
		t.Fatalf("visible text missing content: %q", got)
	}
}
