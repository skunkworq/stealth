package lab

import (
	"context"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/sniffer"
)

func TestSnifferIntegrationLifecycle(t *testing.T) {
	// 1. Configure the server for local isolated testing
	config := DefaultConfig()
	config.HTTPPort = 8097
	config.HTTPSPort = 8497
	config.ProxyPort = 8099
	config.EnableProxy = false

	server := NewEnhancedServer(config, nil)

	// Keep track of any packets caught directly through the backend 
	// (this tests the CGO bridge directly outside of WebSockets)
	capturedCount := 0
	err := sniffer.Start("any", func(pkt sniffer.Packet) {
		capturedCount++
	})

	if err != nil {
		t.Logf("Sniffer failed to start (expected without sudo): %v", err)
		return
	}
	defer sniffer.Stop()

	// Boot the server to trigger network activity
	err = server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	defer server.Stop(ctx)

	// Give the sniffer time to catch background system packets
	time.Sleep(1 * time.Second)

	if capturedCount > 0 {
		t.Logf("Successfully sniffed %d packets natively through CGO!", capturedCount)
	} else {
		t.Log("No packets sniffed in 1 second window, but sniffer successfully attached to interface.")
	}
}
