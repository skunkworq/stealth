package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TrainedProfile is a browser profile derived from real Chrome training captures.
type TrainedProfile struct {
	browserProfile

	// HeaderOrder is the exact header ordering from real Chrome navigation requests.
	HeaderOrder []string
	// SubresourceHeaderOrder is the ordering for XHR/fetch requests.
	SubresourceHeaderOrder []string
	// SourceSession identifies which training session produced this profile.
	SourceSession string
}

// headerPatterns mirrors the JSON structure in header_patterns.json.
type headerPatterns struct {
	NavigationHeaderOrder  []string          `json:"navigation_header_order"`
	SubresourceHeaderOrder []string          `json:"subresource_header_order"`
	CommonHeaders          map[string]string `json:"common_headers"`
	HeaderFrequency        map[string]int    `json:"header_frequency"`
}

// LoadTrainingProfiles reads header_patterns.json files from a training data
// directory and returns browser profiles derived from real captures.
// The directory should contain session subdirectories (e.g., session-001/).
func LoadTrainingProfiles(trainingDir string) ([]TrainedProfile, error) {
	entries, err := os.ReadDir(trainingDir)
	if err != nil {
		return nil, fmt.Errorf("read training dir: %w", err)
	}

	var profiles []TrainedProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		patternsPath := filepath.Join(trainingDir, entry.Name(), "header_patterns.json")
		p, err := loadHeaderPatterns(patternsPath)
		if err != nil {
			continue // skip sessions without header patterns
		}

		profile, err := profileFromPatterns(p, entry.Name())
		if err != nil {
			continue
		}
		profiles = append(profiles, profile)
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("no training profiles found in %s", trainingDir)
	}
	return profiles, nil
}

func loadHeaderPatterns(path string) (*headerPatterns, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p headerPatterns
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func profileFromPatterns(p *headerPatterns, sessionName string) (TrainedProfile, error) {
	ua := extractHeader(p.CommonHeaders, "user-agent")
	if ua == "" {
		return TrainedProfile{}, fmt.Errorf("no user-agent in training data")
	}

	secCHUA := extractHeader(p.CommonHeaders, "sec-ch-ua")
	secCHUAPlatform := extractHeader(p.CommonHeaders, "sec-ch-ua-platform")
	acceptLang := extractHeader(p.CommonHeaders, "accept-language")

	name, version := parseBrowserFromUA(ua)
	platform := parsePlatformFromUA(ua)

	return TrainedProfile{
		browserProfile: browserProfile{
			Name:            name,
			Version:         version,
			Platform:        platform,
			UserAgent:       ua,
			SecCHUA:         secCHUA,
			SecCHUAPlatform: secCHUAPlatform,
			AcceptLang:      acceptLang,
			ViewportWidth:   1920,
			ViewportHeight:  1080,
			TLSFingerprint:  fmt.Sprintf("%s_%s", name, version),
		},
		HeaderOrder:            p.NavigationHeaderOrder,
		SubresourceHeaderOrder: p.SubresourceHeaderOrder,
		SourceSession:          sessionName,
	}, nil
}

// extractHeader does a case-insensitive header lookup.
func extractHeader(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	// Try title case
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// parseBrowserFromUA extracts browser name and version from a User-Agent string.
func parseBrowserFromUA(ua string) (name, version string) {
	// Check for Edge first (contains Chrome in UA)
	if idx := strings.Index(ua, "Edg/"); idx >= 0 {
		v := ua[idx+4:]
		if dot := strings.Index(v, "."); dot > 0 {
			return "edge", v[:dot]
		}
		return "edge", "120"
	}
	// Chrome
	if idx := strings.Index(ua, "Chrome/"); idx >= 0 {
		v := ua[idx+7:]
		if dot := strings.Index(v, "."); dot > 0 {
			return "chrome", v[:dot]
		}
		return "chrome", "120"
	}
	// Firefox
	if idx := strings.Index(ua, "Firefox/"); idx >= 0 {
		v := ua[idx+8:]
		if dot := strings.Index(v, "."); dot > 0 {
			return "firefox", v[:dot]
		}
		return "firefox", "120"
	}
	return "chrome", "120"
}

// parsePlatformFromUA extracts platform from a User-Agent string.
func parsePlatformFromUA(ua string) string {
	switch {
	case strings.Contains(ua, "Windows"):
		return "windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		return "macos"
	case strings.Contains(ua, "Linux"):
		return "linux"
	default:
		return "windows"
	}
}

// MergeTrainedProfiles adds trained profiles to the static profile table,
// giving them priority by prepending. Returns the number of profiles added.
func MergeTrainedProfiles(trained []TrainedProfile) int {
	// Deduplicate by browser+version+platform
	existing := make(map[string]bool)
	for _, p := range profileTable {
		existing[p.Name+"-"+p.Version+"-"+p.Platform] = true
	}

	var newProfiles []browserProfile
	for _, tp := range trained {
		key := tp.Name + "-" + tp.Version + "-" + tp.Platform
		if existing[key] {
			// Update existing profile with trained data (newer version wins)
			for i, p := range profileTable {
				if p.Name+"-"+p.Version+"-"+p.Platform == key {
					profileTable[i] = tp.browserProfile
					break
				}
			}
			continue
		}
		newProfiles = append(newProfiles, tp.browserProfile)
		existing[key] = true
	}

	if len(newProfiles) > 0 {
		// Prepend trained profiles for higher priority
		profileTable = append(newProfiles, profileTable...)
	}
	return len(newProfiles)
}

// TrainedProfileSummary returns a human-readable summary of loaded trained profiles.
func TrainedProfileSummary(profiles []TrainedProfile) string {
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].SourceSession < profiles[j].SourceSession
	})
	var sb strings.Builder
	for _, p := range profiles {
		fmt.Fprintf(&sb, "  %s/%s/%s (from %s, %d nav headers)\n",
			p.Name, p.Version, p.Platform, p.SourceSession, len(p.HeaderOrder))
	}
	return sb.String()
}
