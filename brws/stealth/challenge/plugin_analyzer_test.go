package challenge

import "testing"

func TestPluginAnalyzer_EmptyPlugins(t *testing.T) {
	pa := NewPluginAnalyzer()
	result := pa.Analyze(&PluginData{
		Plugins:     []PluginEntry{},
		PluginCount: 0,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	if !result.Detected {
		t.Errorf("expected detection for empty plugins, got score=%.3f", result.Score)
	}
	assertIndicatorPresent(t, result, "empty_plugins")
}

func TestPluginAnalyzer_ChromeWithPDF(t *testing.T) {
	pa := NewPluginAnalyzer()
	result := pa.Analyze(&PluginData{
		Plugins: []PluginEntry{
			{Name: "PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "Chrome PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "Chromium PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "Microsoft Edge PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "WebKit built-in PDF", Filename: "internal-pdf-viewer"},
		},
		PluginCount: 5,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	if result.Detected {
		t.Errorf("valid Chrome plugins should not be detected, score=%.3f, indicators=%v", result.Score, indicatorNames(result))
	}
}

func TestPluginAnalyzer_SpoofedArray(t *testing.T) {
	pa := NewPluginAnalyzer()
	result := pa.Analyze(&PluginData{
		Plugins: []PluginEntry{
			{Name: "0", Filename: ""},
			{Name: "0", Filename: ""},
			{Name: "0", Filename: ""},
			{Name: "0", Filename: ""},
			{Name: "0", Filename: ""},
		},
		PluginCount: 5,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	if !result.Detected {
		t.Errorf("expected detection for spoofed plugin array, got score=%.3f", result.Score)
	}
	assertIndicatorPresent(t, result, "spoofed_plugin_array")
}

func TestPluginAnalyzer_MissingPDFViewer(t *testing.T) {
	pa := NewPluginAnalyzer()
	result := pa.Analyze(&PluginData{
		Plugins: []PluginEntry{
			{Name: "Shockwave Flash", Filename: "pepflashplayer.dll"},
			{Name: "Chrome Remote Desktop Viewer", Filename: "internal-remoting-viewer"},
			{Name: "Native Client", Filename: "internal-nacl-plugin"},
		},
		PluginCount: 3,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	assertIndicatorPresent(t, result, "missing_pdf_viewer")
}

func TestPluginAnalyzer_TooFewPlugins(t *testing.T) {
	pa := NewPluginAnalyzer()
	result := pa.Analyze(&PluginData{
		Plugins: []PluginEntry{
			{Name: "PDF Viewer", Filename: "internal-pdf-viewer"},
		},
		PluginCount: 1,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	assertIndicatorPresent(t, result, "too_few_plugins")
}

func TestPluginAnalyzer_Nil(t *testing.T) {
	pa := NewPluginAnalyzer()
	result := pa.Analyze(nil)
	if result.Detected {
		t.Error("nil data should not be detected")
	}
}

// --- P11 Plugin MIME Type Tests ---

func TestPluginAnalyzer_MissingMimeTypes(t *testing.T) {
	pa := NewPluginAnalyzer()
	// PDF plugins without MIME types = shallow stub
	result := pa.Analyze(&PluginData{
		Plugins: []PluginEntry{
			{Name: "PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "Chrome PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "Chromium PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "Microsoft Edge PDF Viewer", Filename: "internal-pdf-viewer"},
			{Name: "WebKit built-in PDF", Filename: "internal-pdf-viewer"},
		},
		PluginCount: 5,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	assertIndicatorPresent(t, result, "plugin_missing_mime_types")
}

func TestPluginAnalyzer_WithMimeTypes(t *testing.T) {
	pa := NewPluginAnalyzer()
	// PDF plugins WITH MIME types = legitimate
	result := pa.Analyze(&PluginData{
		Plugins: []PluginEntry{
			{Name: "PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: []string{"application/pdf"}},
			{Name: "Chrome PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: []string{"application/pdf"}},
			{Name: "Chromium PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: []string{"application/pdf"}},
			{Name: "Microsoft Edge PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: []string{"application/pdf"}},
			{Name: "WebKit built-in PDF", Filename: "internal-pdf-viewer", MimeTypes: []string{"application/pdf"}},
		},
		PluginCount: 5,
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	})

	for _, ind := range result.Indicators {
		if ind.Check == "plugin_missing_mime_types" {
			t.Error("plugins with valid MIME types should not trigger mime type check")
		}
	}
	if result.Detected {
		t.Errorf("valid plugins with MIME types should not be detected, score=%.3f", result.Score)
	}
}
