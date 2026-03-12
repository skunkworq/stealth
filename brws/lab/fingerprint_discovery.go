package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BrowserProfile defines a browser configuration for fingerprint discovery.
type BrowserProfile struct {
	Name      string `json:"name"`
	Engine    string `json:"engine"`
	Headless  bool   `json:"headless"`
	Incognito bool   `json:"incognito"`
}

// DiscoveryConfig configures automated fingerprint discovery.
type DiscoveryConfig struct {
	Profiles   []BrowserProfile `json:"profiles"`
	TargetURLs []string         `json:"target_urls"`
	OutputDir  string           `json:"output_dir"`
	Headless   bool             `json:"headless"`
}

// DiscoveryResult holds the result of a single fingerprint capture.
type DiscoveryResult struct {
	Profile    BrowserProfile `json:"profile"`
	TargetURL  string         `json:"target_url"`
	CaptureID  string         `json:"capture_id"`
	Timestamp  time.Time      `json:"timestamp"`
	OutputFile string         `json:"output_file"`
	Error      string         `json:"error,omitempty"`
}

// DefaultDiscoveryConfig returns a default discovery configuration.
func DefaultDiscoveryConfig(outputDir string) *DiscoveryConfig {
	return &DiscoveryConfig{
		Profiles: []BrowserProfile{
			{Name: "chrome-default", Engine: "chromium", Headless: false},
			{Name: "chrome-headless", Engine: "chromium", Headless: true},
		},
		TargetURLs: []string{
			"/capture/json",
		},
		OutputDir: outputDir,
		Headless:  false,
	}
}

// DiscoverFingerprints launches real browsers through the MITM proxy,
// captures their fingerprints, and saves as baseline BrowserSignature JSONs.
func (s *EnhancedServer) DiscoverFingerprints(ctx context.Context, cfg *DiscoveryConfig) ([]DiscoveryResult, error) {
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	results := make([]DiscoveryResult, 0)

	for _, profile := range cfg.Profiles {
		for _, targetURL := range cfg.TargetURLs {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			default:
			}

			result := DiscoveryResult{
				Profile:   profile,
				TargetURL: targetURL,
				Timestamp: time.Now(),
			}

			s.logger.Info("discovering fingerprint",
				"profile", profile.Name,
				"target", targetURL,
				"headless", profile.Headless,
			)

			// Build the full URL
			fullURL := fmt.Sprintf("http://localhost:%d%s", s.config.HTTPPort, targetURL)

			// Launch Chrome with this profile's settings
			if err := s.LaunchChrome(fullURL, profile.Headless); err != nil {
				result.Error = fmt.Sprintf("launch failed: %v", err)
				results = append(results, result)
				continue
			}

			// Wait for the capture to complete
			time.Sleep(3 * time.Second)

			// Retrieve the latest capture
			captures := s.capture.ListCaptures(1, "")
			if len(captures) > 0 {
				result.CaptureID = captures[0].ID

				// Save the capture to a file
				fp, ok := s.capture.GetCapture(captures[0].ID)
				if ok {
					filename := fmt.Sprintf("%s_%s.json", profile.Name, time.Now().Format("20060102_150405"))
					outPath := filepath.Join(cfg.OutputDir, filename)

					f, err := os.Create(outPath)
					if err == nil {
						if err := fp.WriteJSON(f); err != nil {
							result.Error = fmt.Sprintf("write failed: %v", err)
						} else {
							result.OutputFile = outPath
							s.logger.Info("fingerprint saved", "file", outPath)
						}
						f.Close()
					}
				}
			}

			// Stop Chrome
			if err := s.StopChrome(); err != nil {
				s.logger.Warn("failed to stop Chrome", "error", err)
			}

			results = append(results, result)
		}
	}

	// Write discovery summary
	summaryPath := filepath.Join(cfg.OutputDir, "discovery_summary.json")
	if f, err := os.Create(summaryPath); err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		f.Close()
		s.logger.Info("discovery summary saved", "file", summaryPath)
	}

	return results, nil
}
