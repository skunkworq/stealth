package tlsfprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type HTTP2Fingerprint struct {
	Settings          map[uint16]uint32
	SettingsOrder     []uint16
	PseudoHeaders     []string
	HeaderOrder       []string
	EnablePush        bool
	InitialWindowSize uint32
	MaxFrameSize      uint32
	MaxConcurrent     uint32
	JA3H2             string
	JA3H2Fingerprint  string
}

func CalculateHTTP2Fingerprint(settings map[uint16]uint32, pseudoHeaders []string) string {
	var parts []string

	order := []uint16{1, 3, 4, 5, 6, 7}
	for _, id := range order {
		if v, ok := settings[id]; ok {
			parts = append(parts, fmt.Sprintf("%d:%d", id, v))
		}
	}

	parts = append(parts, fmt.Sprintf("ps:%s", strings.Join(pseudoHeaders, ",")))

	return strings.Join(parts, ";")
}

func CalculateJA3H2(settings map[uint16]uint32, pseudoHeaders []string) string {
	var settingsParts []string

	order := []uint16{1, 2, 3, 4, 5, 6, 7}
	for _, id := range order {
		if v, ok := settings[id]; ok {
			settingsParts = append(settingsParts, fmt.Sprintf("%d:%d", id, v))
		}
	}

	settingsStr := strings.Join(settingsParts, ",")

	var pseudoStr string
	if len(pseudoHeaders) > 0 {
		sorted := make([]string, len(pseudoHeaders))
		copy(sorted, pseudoHeaders)
		sort.Strings(sorted)
		pseudoStr = strings.Join(sorted, ",")
	}

	combined := fmt.Sprintf("%s-%s", settingsStr, pseudoStr)
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])[:32]
}

type HTTP2Signature struct {
	Name              string
	Version           string
	Platform          string
	Settings          map[uint16]uint32
	SettingsOrder     []uint16
	PseudoHeaders     []string
	HeaderOrder       []string
	EnablePush        bool
	InitialWindowSize uint32
	MaxFrameSize      uint32
	MaxConcurrent     uint32
	UserAgent         string
	JA3H2             string
}

var HTTP2Signatures = map[string]*HTTP2Signature{
	"chrome-120-windows": {
		Name:              "Chrome 120 Windows",
		Version:           "120.0.6099.129",
		Platform:          "Windows",
		Settings:          map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":path", ":authority", ":scheme"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 65535,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		JA3H2:             "",
	},
	"chrome-120-macos": {
		Name:              "Chrome 120 macOS",
		Version:           "120.0.6099.129",
		Platform:          "macOS",
		Settings:          map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":path", ":authority", ":scheme"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 65535,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		JA3H2:             "",
	},
	"chrome-120-android": {
		Name:              "Chrome 120 Android",
		Version:           "120.0.6099.210",
		Platform:          "Android",
		Settings:          map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":path", ":authority", ":scheme"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 65535,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		JA3H2:             "",
	},
	"firefox-120-windows": {
		Name:              "Firefox 120 Windows",
		Version:           "120.0",
		Platform:          "Windows",
		Settings:          map[uint16]uint32{1: 131072, 3: 200, 4: 65792, 5: 100, 6: 16, 7: 30},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":scheme", ":authority", ":path"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "host", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 131072,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		JA3H2:             "",
	},
	"firefox-120-macos": {
		Name:              "Firefox 120 macOS",
		Version:           "120.0",
		Platform:          "macOS",
		Settings:          map[uint16]uint32{1: 131072, 3: 200, 4: 65792, 5: 100, 6: 16, 7: 30},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":scheme", ":authority", ":path"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "host", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 131072,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		JA3H2:             "",
	},
	"safari-17-macos": {
		Name:              "Safari 17 macOS",
		Version:           "17.1",
		Platform:          "macOS",
		Settings:          map[uint16]uint32{1: 65536, 3: 100, 4: 1048576, 5: 100, 6: 16, 7: 100},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":path", ":scheme", ":authority"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 65536,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		JA3H2:             "",
	},
	"edge-120-windows": {
		Name:              "Edge 120 Windows",
		Version:           "120.0.2210.120",
		Platform:          "Windows",
		Settings:          map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":path", ":authority", ":scheme"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language", "cache-control", "content-type", "user-agent"},
		EnablePush:        false,
		InitialWindowSize: 65535,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		JA3H2:             "",
	},
}

func DetectBrowserFromHTTP2(settings map[uint16]uint32, pseudoHeaders []string) string {
	fingerprint := CalculateJA3H2(settings, pseudoHeaders)

	for _, sig := range HTTP2Signatures {
		if sig.JA3H2 == fingerprint {
			return sig.Name
		}
	}

	if settings[1] >= 131072 {
		return "firefox"
	}
	if settings[4] >= 1000000 {
		return "chrome"
	}
	if settings[4] >= 100000 {
		return "safari"
	}

	return "unknown"
}

type HTTP2Analyzer struct {
	observations []HTTP2Observation
}

type HTTP2Observation struct {
	Timestamp         int64
	Settings          map[uint16]uint32
	SettingsOrder     []uint16
	PseudoHeaders     []string
	HeaderOrder       []string
	FrameSize         uint32
	WindowSize        uint32
	ConnectionPreface string
	JA3H2             string
	DetectedBrowser   string
}

func NewHTTP2Analyzer() *HTTP2Analyzer {
	return &HTTP2Analyzer{
		observations: make([]HTTP2Observation, 0),
	}
}

func (a *HTTP2Analyzer) Record(settings map[uint16]uint32, pseudoHeaders []string, windowSize uint32, frameSize uint32) HTTP2Observation {
	obs := HTTP2Observation{
		Settings:        settings,
		SettingsOrder:   []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:   pseudoHeaders,
		WindowSize:      windowSize,
		FrameSize:       frameSize,
		JA3H2:           CalculateJA3H2(settings, pseudoHeaders),
		DetectedBrowser: DetectBrowserFromHTTP2(settings, pseudoHeaders),
	}
	a.observations = append(a.observations, obs)
	return obs
}

func (a *HTTP2Analyzer) GetObservations() []HTTP2Observation {
	return a.observations
}

func (a *HTTP2Analyzer) GetUniqueFingerprints() map[string]bool {
	unique := make(map[string]bool)
	for _, obs := range a.observations {
		unique[obs.JA3H2] = true
	}
	return unique
}

func (a *HTTP2Analyzer) GetBrowserDistribution() map[string]int {
	dist := make(map[string]int)
	for _, obs := range a.observations {
		dist[obs.DetectedBrowser]++
	}
	return dist
}

type HTTP2Permutator struct {
	randomize bool
	seed      int64
}

func NewHTTP2Permutator(randomize bool, seed int64) *HTTP2Permutator {
	return &HTTP2Permutator{
		randomize: randomize,
		seed:      seed,
	}
}

func (p *HTTP2Permutator) PermuteSettings(settings map[uint16]uint32) map[uint16]uint32 {
	if !p.randomize {
		return settings
	}

	result := make(map[uint16]uint32)
	for k, v := range settings {
		result[k] = v
	}

	return result
}

func (p *HTTP2Permutator) PermuteHeaderOrder(headers []string) []string {
	if !p.randomize || len(headers) <= 1 {
		return headers
	}

	perm := make([]string, len(headers))
	copy(perm, headers)

	for i := len(perm) - 1; i > 0; i-- {
		j := int64(i+1) * p.seed % int64(i+1)
		perm[i], perm[j] = perm[j], perm[i]
	}

	return perm
}
