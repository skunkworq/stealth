package main

import (
	"context"
	"fmt"
	"log"

	"github.com/skunkworq/stealth/brws/engine"
	"github.com/skunkworq/stealth/brws/engine/native"
)

func main() {
	fmt.Println("Querying local labd server with brws/native StealthTLS=true Engine...")

	// 1. Initialize native engine with TLS spoofing
	eng, err := native.New(engine.Options{
		StealthTLS: true,
	})
	if err != nil {
		log.Fatalf("Failed to create native engine: %v", err)
	}

	// 2. Fetch using native engine wrapper
	res, err := eng.Do(context.Background(), &engine.Request{
		Method: "GET",
		URL:    "https://localhost:8443",
	})
	
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body := res.Body

	fmt.Printf("\n--- JA3 Fingerprint Response ---\n")
	fmt.Printf("Status: %d\n", res.Status)
	fmt.Printf("Body length: %d\n", len(body))
}
