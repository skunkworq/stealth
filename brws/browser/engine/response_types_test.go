package engine_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

func makeResp(body string) *engine.Response {
	return &engine.Response{
		Status: 200,
		Body:   []byte(body),
	}
}

func TestNewTextResponse(t *testing.T) {
	resp := makeResp("hello world")
	tr := engine.NewTextResponse(resp)
	if tr.Text != "hello world" {
		t.Errorf("Text = %q, want %q", tr.Text, "hello world")
	}
	if tr.Response != resp {
		t.Error("Response pointer not preserved")
	}
}

func TestTextResponse_JSON(t *testing.T) {
	tr := engine.NewTextResponse(makeResp(`{"key":"value"}`))
	m, err := tr.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	if m["key"] != "value" {
		t.Errorf("key = %v, want %q", m["key"], "value")
	}
}

func TestTextResponse_JSON_invalid(t *testing.T) {
	tr := engine.NewTextResponse(makeResp("not json"))
	_, err := tr.JSON()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestTextResponse_JSONP(t *testing.T) {
	body := `{"user":{"name":"alice","age":30}}`
	tr := engine.NewTextResponse(makeResp(body))

	name, err := tr.JSONP("user.name")
	if err != nil {
		t.Fatalf("JSONP error: %v", err)
	}
	if name != "alice" {
		t.Errorf("JSONP user.name = %v, want alice", name)
	}

	age, err := tr.JSONP("user.age")
	if err != nil {
		t.Fatalf("JSONP error: %v", err)
	}
	if age != float64(30) {
		t.Errorf("JSONP user.age = %v, want 30", age)
	}
}

func TestTextResponse_JSONP_emptySegment(t *testing.T) {
	body := `{"a":"b"}`
	tr := engine.NewTextResponse(makeResp(body))
	v, err := tr.JSONP(".a")
	if err != nil {
		t.Fatalf("JSONP error: %v", err)
	}
	if v != "b" {
		t.Errorf("JSONP .a = %v, want b", v)
	}
}

func TestTextResponse_JSONP_nonObject(t *testing.T) {
	body := `{"a":"scalar"}`
	tr := engine.NewTextResponse(makeResp(body))
	_, err := tr.JSONP("a.b")
	if err == nil {
		t.Error("expected error when traversing non-object")
	}
}

func TestNewHTMLResponse(t *testing.T) {
	html := `<html><head><title>Test Page</title></head><body><h1>Hello</h1></body></html>`
	resp := makeResp(html)
	hr := engine.NewHTMLResponse(resp)
	if hr == nil {
		t.Fatal("NewHTMLResponse returned nil")
	}
}

func TestHTMLResponse_GetTitle(t *testing.T) {
	html := `<html><head><title>My Title</title></head><body></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	title := hr.GetTitle()
	if title != "My Title" {
		t.Errorf("GetTitle = %q, want %q", title, "My Title")
	}
}

func TestHTMLResponse_GetTitle_empty(t *testing.T) {
	html := `<html><body></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	title := hr.GetTitle()
	if title != "" {
		t.Errorf("GetTitle = %q, want empty", title)
	}
}

func TestHTMLResponse_GetLinks(t *testing.T) {
	html := `<html><body><a href="https://example.com">Link 1</a><a href="/page">Link 2</a></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	links := hr.GetLinks()
	if len(links) != 2 {
		t.Fatalf("GetLinks len = %d, want 2", len(links))
	}
	if links[0] != "https://example.com" {
		t.Errorf("links[0] = %q, want %q", links[0], "https://example.com")
	}
}

func TestHTMLResponse_GetImages(t *testing.T) {
	html := `<html><body><img src="/img1.png"><img src="/img2.jpg"></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	imgs := hr.GetImages()
	if len(imgs) != 2 {
		t.Fatalf("GetImages len = %d, want 2", len(imgs))
	}
}

func TestHTMLResponse_GetMeta(t *testing.T) {
	html := `<html><head>
		<meta name="description" content="A test page">
		<meta property="og:title" content="OG Title">
	</head><body></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	meta := hr.GetMeta()
	if meta["description"] != "A test page" {
		t.Errorf("meta[description] = %q, want %q", meta["description"], "A test page")
	}
	if meta["og:title"] != "OG Title" {
		t.Errorf("meta[og:title] = %q, want %q", meta["og:title"], "OG Title")
	}
}

func TestHTMLResponse_CSS(t *testing.T) {
	html := `<html><body><div>one</div><div>two</div><p>para</p></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	divs := hr.CSS("div")
	if len(divs) != 2 {
		t.Fatalf("CSS(div) len = %d, want 2", len(divs))
	}
	ps := hr.CSS("p")
	if len(ps) != 1 {
		t.Fatalf("CSS(p) len = %d, want 1", len(ps))
	}
}

func TestHTMLResponse_XPath(t *testing.T) {
	html := `<html><body><a href="http://a.com">link A</a><a>no href</a></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	links := hr.XPath(".//a[@href]")
	if len(links) != 1 {
		t.Fatalf("XPath .//a[@href] len = %d, want 1", len(links))
	}
	if links[0].Attr("href") != "http://a.com" {
		t.Errorf("href = %q, want %q", links[0].Attr("href"), "http://a.com")
	}
}

func TestHTMLResponse_GetForms(t *testing.T) {
	html := `<html><body>
		<form action="/submit" method="post">
			<input name="email" type="email" required>
			<input name="password" type="password">
			<button type="submit">Submit</button>
		</form>
	</body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	forms := hr.GetForms()
	if len(forms) != 1 {
		t.Fatalf("GetForms len = %d, want 1", len(forms))
	}
	f := forms[0]
	if f.Action != "/submit" {
		t.Errorf("form.Action = %q, want /submit", f.Action)
	}
	if f.Method != "post" {
		t.Errorf("form.Method = %q, want post", f.Method)
	}
	if len(f.Fields) != 2 {
		t.Fatalf("form.Fields len = %d, want 2", len(f.Fields))
	}
	if f.Fields[0].Name != "email" {
		t.Errorf("field[0].Name = %q, want email", f.Fields[0].Name)
	}
}

func TestHTMLResponse_GetForms_defaultMethod(t *testing.T) {
	html := `<html><body><form><input name="q"></form></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	forms := hr.GetForms()
	if len(forms) != 1 {
		t.Fatalf("forms len = %d, want 1", len(forms))
	}
	if forms[0].Method != "get" {
		t.Errorf("default method = %q, want get", forms[0].Method)
	}
}

func TestMatchesHTMLSelector(t *testing.T) {
	html := `<html><body><a href="x">link</a></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	as := hr.CSS("a")
	if len(as) != 1 {
		t.Fatalf("CSS(a) len = %d, want 1", len(as))
	}
	if as[0].Text() != "link" {
		t.Errorf("text = %q, want %q", as[0].Text(), "link")
	}
	if as[0].Attr("href") != "x" {
		t.Errorf("href = %q, want x", as[0].Attr("href"))
	}
}

func TestHTMLElement_AllAttr(t *testing.T) {
	html := `<html><body><a href="x" id="mylink" class="nav">link</a></body></html>`
	hr := engine.NewHTMLResponse(makeResp(html))
	as := hr.CSS("a")
	if len(as) == 0 {
		t.Fatal("no anchors found")
	}
	attrs := as[0].AllAttr()
	if attrs["href"] != "x" {
		t.Errorf("href attr = %q, want x", attrs["href"])
	}
	if attrs["id"] != "mylink" {
		t.Errorf("id attr = %q, want mylink", attrs["id"])
	}
}

func TestHTMLResponse_emptyBody(t *testing.T) {
	hr := engine.NewHTMLResponse(makeResp(""))
	if hr.GetTitle() != "" {
		t.Error("expected empty title for empty body")
	}
	if len(hr.GetLinks()) != 0 {
		t.Error("expected no links for empty body")
	}
}
