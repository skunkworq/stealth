package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPRendererFetches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body>hi</body></html>`))
	}))
	defer srv.Close()
	r := HTTPRenderer{Client: srv.Client()}
	page, err := r.Render(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(page.HTML) != `<html><body>hi</body></html>` {
		t.Errorf("html: %q", page.HTML)
	}
	if page.FinalURL == "" {
		t.Error("final url empty")
	}
}

func TestHTTPRendererNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	r := HTTPRenderer{Client: srv.Client()}
	if _, err := r.Render(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error on 404")
	}
}
