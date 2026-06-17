package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/skunkworq/stealth/internal/dropshipprapp"
)

func main() {
	service, err := dropshipprapp.NewService()
	if err != nil {
		log.Fatalf("dropshippr api: %v", err)
	}

	addr := strings.TrimSpace(os.Getenv("DROPSHIPPR_APP_ADDR"))
	if addr == "" {
		addr = "127.0.0.1:3228"
	}
	origin := strings.TrimSpace(os.Getenv("DROPSHIPPR_APP_CORS_ORIGIN"))
	if origin == "" {
		origin = "http://localhost:3218"
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("/", dropshipprapp.NewHandler(service))

	log.Printf("dropshippr api listening on http://%s", addr)
	if err := http.ListenAndServe(addr, dropshipprapp.WithCORS(mux, origin)); err != nil {
		log.Fatalf("dropshippr api: %v", err)
	}
}
