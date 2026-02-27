package sniffer

import (
	"testing"
)

func TestStartStop(t *testing.T) {
	err := Start("lo0", func(p Packet) {})
	if err != nil {
		t.Logf("Start failed (expected without root or if missing device): %v", err)
	} else {
		Start("any", func(p Packet) {})
	}
	Stop()
}
