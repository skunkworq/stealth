package sniffer

import (
	"testing"
)

func TestStartStop(t *testing.T) {
	err := Start("lo0", func(_ Packet) {})
	if err != nil {
		t.Logf("Start failed (expected without root or if missing device): %v", err)
	} else {
		_ = Start("any", func(_ Packet) {})
	}
	Stop()
}
