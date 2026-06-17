// dropshippr-server is the production Connect-Go backend mirroring the TS
// Next.js handler at dropshippr/src/app/api/connect. Reads from the shared
// Neon Postgres catalog. Listens on :3228 by default (matching the
// DEFAULT_API_BASE_URL the frontend client uses).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/skunkworq/stealth/internal/dropshipprserver"
	"github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1/appv1connect"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}
	addr := os.Getenv("DROPSHIPPR_SERVER_ADDR")
	if addr == "" {
		addr = ":3228"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		log.Fatalf("parse DATABASE_URL: %v", err)
	}
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		log.Fatalf("connect Neon: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping Neon: %v", err)
	}

	srv := dropshipprserver.New(pool)
	mux := http.NewServeMux()
	path, handler := appv1connect.NewDropshipprServiceHandler(srv)
	mux.Handle(path, handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	fmt.Printf("dropshippr-server listening on %s (mounted %s)\n", addr, path)
	server := &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
