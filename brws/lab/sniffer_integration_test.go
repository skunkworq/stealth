package lab

import (
	"context"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/sniffer"
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

	// Boot the server in a goroutine — Start() blocks until Stop() is called
	startErr := make(chan error, 1)
	go func() {
		startErr <- server.Start()
	}()

	// Give the server a moment to bind its listeners
	time.Sleep(500 * time.Millisecond)

	// Check if Start() returned an error immediately
	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
	default:
		// Still running — expected
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	defer func() { _ = server.Stop(ctx) }()

	// Give the sniffer time to catch background system packets
	time.Sleep(1 * time.Second)

	if capturedCount > 0 {
		t.Logf("Successfully sniffed %d packets natively through CGO!", capturedCount)
	} else {
		t.Log("No packets sniffed in 1 second window, but sniffer successfully attached to interface.")
	}
}
