// Package cdpstealth provides CDP-based stealth actions that are more reliable than JS injection.
package cdpstealth

import (
	"context"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
)

// StealthConfig contains CDP stealth configuration
type StealthConfig struct {
	UserAgent         string
	Platform          string
	PlatformVersion   string
	ChromeVersion     string
	Mobile            bool
	Architecture      string
	Model             string
	Timezone          string
	Locale            string
	DisableAutomation bool
}

// DefaultConfig returns a default stealth configuration
func DefaultConfig() *StealthConfig {
	return &StealthConfig{
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Platform:          "macOS",
		PlatformVersion:   "10.15.7",
		ChromeVersion:     "120.0.0.0",
		Mobile:            false,
		Architecture:      "x86",
		Model:             "",
		Timezone:          "America/New_York",
		Locale:            "en-US",
		DisableAutomation: true,
	}
}

// Apply applies CDP stealth settings to the context
func Apply(ctx context.Context, cfg *StealthConfig) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// 1. Disable automation detection (key nodriver technique)
	if cfg.DisableAutomation {
		if err := emulation.SetAutomationOverride(false).Do(ctx); err != nil {
			return err
		}
	}

	// 2. Set user agent with metadata
	uaMetadata := &emulation.UserAgentMetadata{
		Platform:        cfg.Platform,
		PlatformVersion: cfg.PlatformVersion,
		Architecture:    cfg.Architecture,
		Model:           cfg.Model,
		Mobile:          cfg.Mobile,
		Brands: []*emulation.UserAgentBrandVersion{
			{Brand: "Not/A)Brand", Version: "8"},
			{Brand: "Chromium", Version: cfg.ChromeVersion[:2]},
			{Brand: "Google Chrome", Version: cfg.ChromeVersion[:2]},
		},
	}

	params := emulation.SetUserAgentOverride(cfg.UserAgent)
	params.UserAgentMetadata = uaMetadata
	if err := params.Do(ctx); err != nil {
		return err
	}

	// 3. Set timezone
	if err := emulation.SetTimezoneOverride(cfg.Timezone).Do(ctx); err != nil {
		return err
	}

	// 4. Set locale
	paramsLocale := emulation.SetLocaleOverride()
	paramsLocale.Locale = cfg.Locale
	if err := paramsLocale.Do(ctx); err != nil {
		return err
	}

	// 5. Set viewport defaults
	if err := emulation.SetDeviceMetricsOverride(1920, 1080, 1.0, false).Do(ctx); err != nil {
		return err
	}

	// 6. Disable default background color
	paramsBg := emulation.SetDefaultBackgroundColorOverride()
	paramsBg.Color = &cdp.RGBA{R: 255, G: 255, B: 255, A: 255}
	if err := paramsBg.Do(ctx); err != nil {
		return err
	}

	return nil
}

// ChromeVersions returns a list of recent Chrome versions
func ChromeVersions() []string {
	return []string{
		"120.0.0.0",
		"121.0.6167.85",
		"122.0.6266.112",
		"123.0.6312.66",
		"124.0.6360.122",
	}
}

// Platforms returns common platform values
func Platforms() []string {
	return []string{
		"macOS",
		"Windows",
		"Linux",
		"Android",
		"iOS",
	}
}

// Timezones returns common timezone values
func Timezones() []string {
	return []string{
		"America/New_York",
		"America/Chicago",
		"America/Denver",
		"America/Los_Angeles",
		"Europe/London",
		"Europe/Paris",
		"Asia/Tokyo",
		"Asia/Shanghai",
	}
}
