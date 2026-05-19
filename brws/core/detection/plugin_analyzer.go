package detection

import (
	"fmt"
	"math"
	"strings"
)

// PluginEntry represents a single browser plugin.
type PluginEntry struct {
	Name      string   `json:"name"`
	Filename  string   `json:"filename"`
	MimeTypes []string `json:"mimeTypes,omitempty"`
}

// PluginData holds plugin enumeration data for analysis.
type PluginData struct {
	Plugins     []PluginEntry `json:"plugins"`
	PluginCount int           `json:"plugin_count"`
	UserAgent   string        `json:"-"` // Set from request context, not from header
}

// PluginAnalyzer validates plugin data for headless/bot detection.
type PluginAnalyzer struct{}

// NewPluginAnalyzer creates a new PluginAnalyzer.
func NewPluginAnalyzer() *PluginAnalyzer {
	return &PluginAnalyzer{}
}

// Analyze runs the full plugin analysis suite.
func (pa *PluginAnalyzer) Analyze(data *PluginData) *VectorResult {
	result := &VectorResult{
		Vector:     "Plugin Analysis",
		Category:   VectorPlugin,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if data == nil {
		return result
	}

	isChrome := strings.Contains(strings.ToLower(data.UserAgent), "chrome")

	// Check 1: Empty plugins (headless signature — only for Chrome; Firefox has 0 plugins by design)
	if isChrome && len(data.Plugins) == 0 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "empty_plugins",
			Message: "Zero plugins detected — common headless signature",
			Weight:  weight,
			Field:   "plugin_count",
			Value:   "0",
		})
		result.Score += weight
	}

	// Check 2: Too few plugins on Chrome (Chrome 87+ has at least 3-5 default plugins)
	if isChrome && len(data.Plugins) > 0 && len(data.Plugins) < 3 {
		weight := 0.20
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "too_few_plugins",
			Message: fmt.Sprintf("Only %d plugins on Chrome (expected 3+)", len(data.Plugins)),
			Weight:  weight,
			Field:   "plugin_count",
			Value:   fmt.Sprintf("%d", len(data.Plugins)),
		})
		result.Score += weight
	}

	// Check 3: Spoofed plugin array (all plugins are identical numeric values)
	if len(data.Plugins) > 0 {
		allIdentical := true
		firstName := data.Plugins[0].Name
		for _, p := range data.Plugins[1:] {
			if p.Name != firstName {
				allIdentical = false
				break
			}
		}
		if allIdentical && len(data.Plugins) > 1 {
			weight := 0.40
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "spoofed_plugin_array",
				Message: fmt.Sprintf("All %d plugins are identical ('%s') — spoofed array", len(data.Plugins), firstName),
				Weight:  weight,
				Field:   "plugins",
				Value:   firstName,
			})
			result.Score += weight
		}
	}

	// Check 4: Missing PDF Viewer on Chrome 87+
	if isChrome && len(data.Plugins) > 0 {
		hasPDFViewer := false
		for _, p := range data.Plugins {
			nameLower := strings.ToLower(p.Name)
			if strings.Contains(nameLower, "pdf") {
				hasPDFViewer = true
				break
			}
		}
		if !hasPDFViewer {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "missing_pdf_viewer",
				Message: "Chrome browser but no PDF Viewer plugin detected",
				Weight:  weight,
				Field:   "plugins",
				Value:   "no_pdf_viewer",
			})
			result.Score += weight
		}
	}

	// Check 5: P11 — Missing MIME types on Chrome PDF plugins.
	// Real Chrome PDF plugins each report "application/pdf" in their MimeType array.
	// A plugin with the right name but no MIME types is a shallow stub.
	if isChrome && len(data.Plugins) > 0 {
		pdfPluginCount := 0
		pdfWithMime := 0
		for _, p := range data.Plugins {
			if strings.Contains(strings.ToLower(p.Name), "pdf") {
				pdfPluginCount++
				for _, mt := range p.MimeTypes {
					if strings.Contains(strings.ToLower(mt), "application/pdf") {
						pdfWithMime++
						break
					}
				}
			}
		}
		if pdfPluginCount > 0 && pdfWithMime == 0 {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "plugin_missing_mime_types",
				Message: fmt.Sprintf("%d PDF plugins but none report application/pdf MIME type", pdfPluginCount),
				Weight:  weight,
				Field:   "mimeTypes",
				Value:   "empty",
			})
			result.Score += weight
		}
	}

	// Check 6: Plugin Filename Consistency (Chrome 87+)
	// All Chrome PDF plugins use "internal-pdf-viewer" as the filename.
	if isChrome {
		for _, p := range data.Plugins {
			if strings.Contains(strings.ToLower(p.Name), "pdf") {
				if p.Filename != "internal-pdf-viewer" {
					weight := 0.35
					result.Indicators = append(result.Indicators, VectorIndicator{
						Check:   "suspicious_plugin_filename",
						Message: fmt.Sprintf("Chrome PDF plugin '%s' has non-standard filename '%s'", p.Name, p.Filename),
						Weight:  weight,
						Field:   "filename",
						Value:   p.Filename,
					})
					result.Score += weight
				}
			}
		}
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}
