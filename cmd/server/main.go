package main

import (
	"log/slog"
	"os"

	"github.com/skunkworq/stealth/server"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := server.DefaultConfig()
	if addr := os.Getenv("SERVER_ADDR"); addr != "" {
		cfg.Addr = addr
	}
	if llm := os.Getenv("DEFAULT_LLM"); llm != "" {
		cfg.DefaultLLM = llm
	}
	if model := os.Getenv("DEFAULT_MODEL"); model != "" {
		cfg.DefaultModel = model
	}

	srv := server.NewServer(cfg, server.DefaultLLMProvider)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}
