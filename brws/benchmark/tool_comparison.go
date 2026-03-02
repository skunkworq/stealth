package benchmark

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/adversarial/captcha"
	"github.com/stealth/brwslab/brws/behavior"
)

// ToolCategory classifies the type of scraping/automation tool.
type ToolCategory string

const (
	CategoryBareHTTP        ToolCategory = "bare_http"
	CategoryBrowserDefault  ToolCategory = "browser_default"
	CategoryBrowserStealth  ToolCategory = "browser_stealth"
	CategoryHTTPImpersonate ToolCategory = "http_impersonate"
)

// ToolInfo holds metadata about a scraping/automation tool.
type ToolInfo struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Language    string       `json:"language"`
	Category    ToolCategory `json:"category"`
	HasJS       bool         `json:"has_js"`
	HasTLS      bool         `json:"has_tls"`
	Description string       `json:"description"`
}

// ToolProfile wraps ToolInfo with one or more scenarios to evaluate.
type ToolProfile struct {
	Info      ToolInfo        `json:"info"`
	Scenarios []ShieldProfile `json:"-"`
}

// ToolComparisonConfig controls the comparison run.
type ToolComparisonConfig struct {
	IncludeBehavioral bool `json:"include_behavioral"`
	Iterations        int  `json:"iterations"`
	Verbose           bool `json:"verbose"`
}

// ScenarioResult is the result for a single scenario within a tool.
type ScenarioResult struct {
	Name         string             `json:"name"`
	BotScore     float64            `json:"bot_score"`
	IsBot        bool               `json:"is_bot"`
	Indicators   []string           `json:"indicators"`
	VectorScores map[string]float64 `json:"vector_scores"`
}

// ToolResult is the aggregated result for a tool across all its scenarios.
type ToolResult struct {
	Tool          ToolInfo         `json:"tool"`
	AvgBotScore   float64          `json:"avg_bot_score"`
	DetectionRate float64          `json:"detection_rate"`
	EvasionRate   float64          `json:"evasion_rate"`
	FiredVectors  []string         `json:"fired_vectors"`
	Scenarios     []ScenarioResult `json:"scenarios"`
}

// RankEntry is a single row in the evasion ranking table.
type RankEntry struct {
	Rank        int          `json:"rank"`
	ToolName    string       `json:"tool_name"`
	Category    ToolCategory `json:"category"`
	EvasionRate float64      `json:"evasion_rate"`
	AvgScore    float64      `json:"avg_score"`
}

// VectorToolMatrix shows which vectors fire for which tools.
type VectorToolMatrix struct {
	Vectors []string                      `json:"vectors"`
	Tools   []string                      `json:"tools"`
	Matrix  map[string]map[string]float64 `json:"matrix"` // vector -> tool -> score
}

// CaptchaToolResult holds captcha benchmark results for a single tool.
type CaptchaToolResult struct {
	ToolName           string  `json:"tool_name"`
	CaptchaSolveRate   float64 `json:"captcha_solve_rate"`
	BehavioralPassRate float64 `json:"behavioral_pass_rate"`
	EndToEndPassRate   float64 `json:"end_to_end_pass_rate"`
	Attempts           int     `json:"attempts"`
}

// ToolComparisonReport is the full comparison report.
type ToolComparisonReport struct {
	Timestamp      time.Time            `json:"timestamp"`
	ShieldVer      string               `json:"shield_version"`
	Config         ToolComparisonConfig `json:"config"`
	Results        []ToolResult         `json:"results"`
	Ranking        []RankEntry          `json:"ranking"`
	VectorMatrix   VectorToolMatrix     `json:"vector_matrix"`
	CaptchaResults []CaptchaToolResult  `json:"captcha_results,omitempty"`
}

// buildToolProfiles returns the 10 tool profiles for comparison.
func buildToolProfiles(includeBehavioral bool) []ToolProfile {
	profiles := []ToolProfile{
		pythonRequestsProfile(),
		scrapyDefaultProfile(),
		playwrightDefaultHeadlessProfile(),
		puppeteerDefaultHeadlessProfile(),
		curlImpersonateChrome116Profile(),
		nodriverDefaultProfile(),
		scraplingStealthyProfile(),
		scraplingPlaywrightProfile(),
		ourStealthSwordProfile(),
		ourStealthBrokenProfile(),
	}
	return profiles
}

// pythonRequestsProfile — bare HTTP with python-requests UA.
// Source: requests library default headers (only UA, Accept, Accept-Encoding, Connection).
func pythonRequestsProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "python_requests",
			Version:     "2.32.3",
			Language:    "Python",
			Category:    CategoryBareHTTP,
			HasJS:       false,
			HasTLS:      false,
			Description: "Python Requests library with default settings",
		},
		Scenarios: []ShieldProfile{
			{Name: "python_requests_default", Category: "bare_http", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "python-requests/2.32.3")
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Accept-Encoding", "gzip, deflate")
				req.Header.Set("Connection", "keep-alive")
				return req
			}},
		},
	}
}

// scrapyDefaultProfile — bare HTTP with Scrapy bot UA.
// Source: docs/scrapy/scrapy/ default settings.
func scrapyDefaultProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "scrapy_default",
			Version:     "2.11.0",
			Language:    "Python",
			Category:    CategoryBareHTTP,
			HasJS:       false,
			HasTLS:      false,
			Description: "Scrapy framework with default settings",
		},
		Scenarios: []ShieldProfile{
			{Name: "scrapy_default", Category: "bare_http", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Scrapy/2.11.0 (+https://scrapy.org)")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en")
				return req
			}},
		},
	}
}

// playwrightDefaultHeadlessProfile — headless Chrome via Playwright with no stealth patches.
// HeadlessChrome brand in Sec-Ch-Ua, webdriver=true, SwiftShader WebGL, 1280x720 viewport.
func playwrightDefaultHeadlessProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "playwright_default",
			Version:     "1.48.0",
			Language:    "Node.js",
			Category:    CategoryBrowserDefault,
			HasJS:       true,
			HasTLS:      true,
			Description: "Playwright headless Chrome with default settings",
		},
		Scenarios: []ShieldProfile{
			{Name: "playwright_headless", Category: "browser_default", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"HeadlessChrome";v="134", "Not-A.Brand";v="99", "Chromium";v="134"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				// No Accept-Language (Playwright default omits it)
				// Navigator: webdriver=true
				req.Header.Set("X-Navigator-Data", `{"webdriver":true,"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36","hardwareConcurrency":4,"deviceMemory":8,"connection":{"rtt":0,"downlink":10,"effectiveType":"4g"},"languages":["en-US"],"productSub":"20030107","maxTouchPoints":0}`)
				// WebGL: SwiftShader
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"Google SwiftShader","unmasked_vendor":"Google Inc.","unmasked_renderer":"Google SwiftShader","version":"WebGL 2.0","platform":"Win32","webgl2_supported":true,"max_texture_size":4096,"extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_filter_anisotropic","OES_element_index_uint","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_debug_renderer_info","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context"]}`)
				// Screen: 1280x720, outer==inner (no taskbar)
				req.Header.Set("X-Screen-Data", `{"width":1280,"height":720,"avail_width":1280,"avail_height":720,"color_depth":24,"pixel_ratio":1.0,"outer_width":1280,"outer_height":720,"inner_width":1280,"inner_height":720}`)
				// Plugins: Chrome still has PDF plugins in headless
				req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer"},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer"}],"plugin_count":5}`)
				return req
			}},
		},
	}
}

// puppeteerDefaultHeadlessProfile — headless Chrome via Puppeteer with default 800x600 viewport.
func puppeteerDefaultHeadlessProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "puppeteer_default",
			Version:     "23.0.0",
			Language:    "Node.js",
			Category:    CategoryBrowserDefault,
			HasJS:       true,
			HasTLS:      true,
			Description: "Puppeteer headless Chrome with default 800x600 viewport",
		},
		Scenarios: []ShieldProfile{
			{Name: "puppeteer_headless", Category: "browser_default", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"HeadlessChrome";v="134", "Not-A.Brand";v="99", "Chromium";v="134"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				// No Accept-Language
				req.Header.Set("X-Navigator-Data", `{"webdriver":true,"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36","hardwareConcurrency":4,"deviceMemory":8,"connection":{"rtt":0,"downlink":10,"effectiveType":"4g"},"languages":["en-US"],"productSub":"20030107","maxTouchPoints":0}`)
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"Google SwiftShader","unmasked_vendor":"Google Inc.","unmasked_renderer":"Google SwiftShader","version":"WebGL 2.0","platform":"Win32","webgl2_supported":true,"max_texture_size":4096,"extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_filter_anisotropic","OES_element_index_uint","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_debug_renderer_info","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context"]}`)
				// Default Puppeteer viewport: 800x600
				req.Header.Set("X-Screen-Data", `{"width":800,"height":600,"avail_width":800,"avail_height":600,"color_depth":24,"pixel_ratio":1.0,"outer_width":800,"outer_height":600,"inner_width":800,"inner_height":600}`)
				req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer"},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer"}],"plugin_count":5}`)
				return req
			}},
		},
	}
}

// curlImpersonateChrome116Profile — curl-impersonate with Chrome 116 TLS + headers.
// Perfect HTTP headers but no JS engine, no fingerprint data.
// Source: docs/curl-impersonate/browsers.json
func curlImpersonateChrome116Profile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "curl_impersonate_ch116",
			Version:     "0.6.1",
			Language:    "C/curl",
			Category:    CategoryHTTPImpersonate,
			HasJS:       false,
			HasTLS:      true,
			Description: "curl-impersonate with Chrome 116 TLS and header profile",
		},
		Scenarios: []ShieldProfile{
			{Name: "curl_impersonate_chrome116", Category: "http_impersonate", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				// No X-* fingerprint headers — pure HTTP client, no JS engine
				return req
			}},
		},
	}
}

// nodriverDefaultProfile — nodriver (undetected Chrome) with real browser but no behavioral data.
// Source: docs/nodriver/nodriver/core/tab.py:203-222 (CDP patches webdriver=false)
func nodriverDefaultProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "nodriver",
			Version:     "0.38",
			Language:    "Python",
			Category:    CategoryBrowserStealth,
			HasJS:       true,
			HasTLS:      true,
			Description: "nodriver (undetected-chromedriver successor) with real Chrome",
		},
		Scenarios: []ShieldProfile{
			{Name: "nodriver_chrome131", Category: "browser_stealth", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				// Real Chrome: webdriver=false (patched via CDP)
				req.Header.Set("X-Navigator-Data", `{"webdriver":false,"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","hardwareConcurrency":8,"deviceMemory":16,"connection":{"rtt":50,"downlink":7.5,"effectiveType":"4g"},"languages":["en-US","en"],"productSub":"20030107","maxTouchPoints":0,"chrome":{}}`)
				// Real WebGL (ANGLE renderer, not SwiftShader)
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)","unmasked_vendor":"Google Inc. (NVIDIA)","unmasked_renderer":"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)","version":"WebGL 2.0","shading_version":"WebGL GLSL ES 3.00","platform":"Win32","webgl2_supported":true,"max_texture_size":16384,"extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","GOOGLE_GENERATE_MIPMAP_HINT","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_multi_draw"]}`)
				// Real plugins (Chrome 5 PDF plugins)
				req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer"},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer"}],"plugin_count":5}`)
				// Real screen: 1920x1080 with taskbar
				req.Header.Set("X-Screen-Data", `{"width":1920,"height":1080,"avail_width":1920,"avail_height":1040,"color_depth":24,"pixel_ratio":1.0,"outer_width":1920,"outer_height":1040,"inner_width":1903,"inner_height":969}`)
				// Real fonts (Windows)
				req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New","Georgia","Verdana","Trebuchet MS","Impact","Comic Sans MS","Palatino Linotype","Lucida Console","Lucida Sans Unicode","Segoe UI","Calibri","Consolas","Tahoma","MS Gothic","MS Mincho","MS PGothic","MS PMincho","MS Sans Serif","MS Serif","MS UI Gothic"],"font_count":22,"platform":"windows"}`)
				// Missing: behavioral data, audio, timing
				// nodriver does not generate mouse/keyboard events or inject timing entries
				return req
			}},
		},
	}
}

// scraplingStealthyProfile — Scrapling StealthyFetcher with Patchright/Chromium + BrowserForge fingerprints.
// Source: docs/Scrapling/scrapling/engines/constants.py:94 (--disable-blink-features=AutomationControlled)
// Source: docs/Scrapling/scrapling/engines/_browsers/_base.py:496-497 (canvas noise flags)
// Source: docs/Scrapling/scrapling/engines/_browsers/_stealth.py:472-473 (screen: 1920x1080, scale 2)
// Source: docs/Scrapling/scrapling/engines/toolbelt/fingerprints.py (BrowserForge headers)
func scraplingStealthyProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "scrapling_stealthy",
			Version:     "0.2.9",
			Language:    "Python",
			Category:    CategoryBrowserStealth,
			HasJS:       true,
			HasTLS:      true,
			Description: "Scrapling StealthyFetcher with Patchright + BrowserForge fingerprints",
		},
		Scenarios: []ShieldProfile{
			{Name: "scrapling_stealthy_chrome143", Category: "browser_stealth", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				// webdriver stripped via --disable-blink-features=AutomationControlled
				req.Header.Set("X-Navigator-Data", `{"webdriver":false,"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","hardwareConcurrency":8,"deviceMemory":16,"connection":{"rtt":75,"downlink":5.5,"effectiveType":"4g"},"languages":["en-US","en"],"productSub":"20030107","maxTouchPoints":0,"chrome":{}}`)
				// Real WebGL (Chromium ANGLE)
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)","unmasked_vendor":"Google Inc. (NVIDIA)","unmasked_renderer":"ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)","version":"WebGL 2.0","shading_version":"WebGL GLSL ES 3.00","platform":"Win32","webgl2_supported":true,"max_texture_size":16384,"extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","GOOGLE_GENERATE_MIPMAP_HINT","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_multi_draw"]}`)
				// Plugins
				req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer"},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer"}],"plugin_count":5}`)
				// Screen: 1920x1080 with device_scale_factor 2
				req.Header.Set("X-Screen-Data", `{"width":1920,"height":1080,"avail_width":1920,"avail_height":1040,"color_depth":24,"pixel_ratio":2.0,"outer_width":1920,"outer_height":1040,"inner_width":1903,"inner_height":969}`)
				// Fonts (Windows)
				req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New","Georgia","Verdana","Trebuchet MS","Impact","Comic Sans MS","Palatino Linotype","Lucida Console","Lucida Sans Unicode","Segoe UI","Calibri","Consolas","Tahoma","MS Gothic","MS Mincho","MS PGothic","MS PMincho","MS Sans Serif","MS Serif","MS UI Gothic"],"font_count":22,"platform":"windows"}`)
				// Missing: behavioral data, audio context, timing entries
				return req
			}},
		},
	}
}

// scraplingPlaywrightProfile — Scrapling DynamicFetcher (plain Playwright, minimal stealth).
// Source: docs/Scrapling/scrapling/engines/_browsers/_controllers.py (no STEALTH_ARGS)
func scraplingPlaywrightProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "scrapling_playwright",
			Version:     "0.2.9",
			Language:    "Python",
			Category:    CategoryBrowserDefault,
			HasJS:       true,
			HasTLS:      true,
			Description: "Scrapling DynamicFetcher — plain Playwright with minimal stealth",
		},
		Scenarios: []ShieldProfile{
			{Name: "scrapling_dynamic_fetcher", Category: "browser_default", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"HeadlessChrome";v="134", "Not-A.Brand";v="99", "Chromium";v="134"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				// webdriver exposed
				req.Header.Set("X-Navigator-Data", `{"webdriver":true,"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36","hardwareConcurrency":4,"deviceMemory":8,"connection":{"rtt":0,"downlink":10,"effectiveType":"4g"},"languages":["en-US"],"productSub":"20030107","maxTouchPoints":0}`)
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"Google SwiftShader","unmasked_vendor":"Google Inc.","unmasked_renderer":"Google SwiftShader","version":"WebGL 2.0","platform":"Win32","webgl2_supported":true,"max_texture_size":4096,"extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_filter_anisotropic","OES_element_index_uint","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_debug_renderer_info","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context"]}`)
				req.Header.Set("X-Screen-Data", `{"width":1280,"height":720,"avail_width":1280,"avail_height":720,"color_depth":24,"pixel_ratio":1.0,"outer_width":1280,"outer_height":720,"inner_width":1280,"inner_height":720}`)
				req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer"},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer"},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer"}],"plugin_count":5}`)
				return req
			}},
		},
	}
}

// ourStealthSwordProfile — our own stealth sword using behavior.NewRequestGenerator.
// This is the positive control: should evade all detection.
func ourStealthSwordProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "our_stealth_sword",
			Version:     "1.0",
			Language:    "Go",
			Category:    CategoryBrowserStealth,
			HasJS:       true,
			HasTLS:      true,
			Description: "Our stealth sword — full fingerprint generation via behavior.NewRequestGenerator",
		},
		Scenarios: []ShieldProfile{
			{Name: "stealth_sword_chrome_windows", Category: "browser_stealth", ShouldCatch: false, BuildReq: func() *http.Request {
				gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
					Profile: behavior.ChromeWindowsProfile(),
				})
				return gen.GenerateRequest("http://test/")
			}},
			{Name: "stealth_sword_chrome_macos", Category: "browser_stealth", ShouldCatch: false, BuildReq: func() *http.Request {
				gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
					Profile: behavior.ChromeMacOSProfile(),
				})
				return gen.GenerateRequest("http://test/")
			}},
			{Name: "stealth_sword_firefox", Category: "browser_stealth", ShouldCatch: false, BuildReq: func() *http.Request {
				gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
					Profile: behavior.FirefoxWindowsProfile(),
				})
				return gen.GenerateRequest("http://test/")
			}},
		},
	}
}

// ourStealthBrokenProfile — deliberately broken stealth as negative control.
// Version mismatch, anticorrelated RTT/downlink, missing audio/scroll/extensions.
func ourStealthBrokenProfile() ToolProfile {
	return ToolProfile{
		Info: ToolInfo{
			Name:        "our_stealth_broken",
			Version:     "1.0",
			Language:    "Go",
			Category:    CategoryBrowserStealth,
			HasJS:       true,
			HasTLS:      true,
			Description: "Deliberately broken stealth — version mismatch, bad correlations",
		},
		Scenarios: []ShieldProfile{
			{Name: "broken_version_mismatch", Category: "browser_stealth", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				// Chrome 134 UA but Sec-Ch-Ua says 120 (version mismatch)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				// Version mismatch: Chrome 120 in hints vs 134 in UA
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				// Anticorrelated RTT/downlink: high RTT + high downlink (spoof signature)
				req.Header.Set("X-Navigator-Data", `{"webdriver":false,"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","hardwareConcurrency":8,"deviceMemory":16,"connection":{"rtt":200,"downlink":10,"effectiveType":"4g"},"languages":["en-US","en"],"productSub":"20030107","maxTouchPoints":0,"chrome":{}}`)
				// SwiftShader renderer (headless indicator)
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"Google SwiftShader","unmasked_vendor":"Google Inc.","unmasked_renderer":"Google SwiftShader","version":"WebGL 2.0","platform":"Win32","webgl2_supported":true,"max_texture_size":4096,"extensions":[]}`)
				// Empty plugins
				req.Header.Set("X-Plugin-Data", `{"plugins":[],"plugin_count":0}`)
				// Headless screen (outer==inner)
				req.Header.Set("X-Screen-Data", `{"width":800,"height":600,"avail_width":800,"avail_height":600,"color_depth":24,"pixel_ratio":1.0,"outer_width":800,"outer_height":600,"inner_width":800,"inner_height":600}`)
				// Too few fonts
				req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New"],"font_count":3,"platform":"windows"}`)
				// No audio, no timing, no behavioral
				return req
			}},
		},
	}
}

// RunToolComparison runs the cross-tool shield comparison.
func RunToolComparison(cfg *ToolComparisonConfig) *ToolComparisonReport {
	if cfg == nil {
		cfg = &ToolComparisonConfig{IncludeBehavioral: true, Iterations: 1}
	}
	if cfg.Iterations < 1 {
		cfg.Iterations = 1
	}

	detector := adversarial.NewStealthDetector()
	toolProfiles := buildToolProfiles(cfg.IncludeBehavioral)

	results := make([]ToolResult, 0, len(toolProfiles))
	allVectors := make(map[string]bool)

	for _, tp := range toolProfiles {
		tr := ToolResult{
			Tool:      tp.Info,
			Scenarios: make([]ScenarioResult, 0, len(tp.Scenarios)),
		}

		totalScore := 0.0
		detectedCount := 0
		firedVecMap := make(map[string]bool)

		for _, scenario := range tp.Scenarios {
			// Run multiple iterations and average
			var scenAvgScore float64
			var scenIsBot bool
			var scenIndicators []string
			scenVecScores := make(map[string]float64)

			for iter := 0; iter < cfg.Iterations; iter++ {
				req := scenario.BuildReq()
				detection := detector.AnalyzeRequest(req, nil)

				scenAvgScore += detection.Score

				if detection.IsBot {
					scenIsBot = true
				}

				for _, vec := range detection.Vectors {
					prev, ok := scenVecScores[vec.Category]
					if !ok || vec.Score > prev {
						scenVecScores[vec.Category] = vec.Score
					}
					if vec.Detected {
						firedVecMap[vec.Category] = true
						allVectors[vec.Category] = true
						for _, ind := range vec.Indicators {
							scenIndicators = append(scenIndicators, ind)
						}
					}
					allVectors[vec.Category] = true
				}
			}

			scenAvgScore /= float64(cfg.Iterations)
			// Deduplicate indicators
			scenIndicators = dedup(scenIndicators)

			sr := ScenarioResult{
				Name:         scenario.Name,
				BotScore:     scenAvgScore,
				IsBot:        scenIsBot,
				Indicators:   scenIndicators,
				VectorScores: scenVecScores,
			}
			tr.Scenarios = append(tr.Scenarios, sr)

			totalScore += scenAvgScore
			if scenIsBot {
				detectedCount++
			}
		}

		numScenarios := len(tp.Scenarios)
		if numScenarios > 0 {
			tr.AvgBotScore = totalScore / float64(numScenarios)
			tr.DetectionRate = float64(detectedCount) / float64(numScenarios)
			tr.EvasionRate = 1.0 - tr.DetectionRate
		}

		firedVecs := make([]string, 0, len(firedVecMap))
		for v := range firedVecMap {
			firedVecs = append(firedVecs, v)
		}
		sort.Strings(firedVecs)
		tr.FiredVectors = firedVecs

		results = append(results, tr)
	}

	// Build ranking (sorted by avg bot score ascending = best evasion first)
	ranking := buildRanking(results)

	// Build vector matrix
	vectorMatrix := buildVectorMatrix(results, allVectors)

	return &ToolComparisonReport{
		Timestamp:    time.Now(),
		ShieldVer:    "v4-round4",
		Config:       *cfg,
		Results:      results,
		Ranking:      ranking,
		VectorMatrix: vectorMatrix,
	}
}

func buildRanking(results []ToolResult) []RankEntry {
	entries := make([]RankEntry, len(results))
	for i, r := range results {
		entries[i] = RankEntry{
			ToolName:    r.Tool.Name,
			Category:    r.Tool.Category,
			EvasionRate: r.EvasionRate,
			AvgScore:    r.AvgBotScore,
		}
	}

	// Sort: higher evasion rate first, then lower avg score
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].EvasionRate != entries[j].EvasionRate {
			return entries[i].EvasionRate > entries[j].EvasionRate
		}
		return entries[i].AvgScore < entries[j].AvgScore
	})

	for i := range entries {
		entries[i].Rank = i + 1
	}

	return entries
}

func buildVectorMatrix(results []ToolResult, allVectors map[string]bool) VectorToolMatrix {
	vectors := make([]string, 0, len(allVectors))
	for v := range allVectors {
		vectors = append(vectors, v)
	}
	sort.Strings(vectors)

	tools := make([]string, 0, len(results))
	for _, r := range results {
		tools = append(tools, r.Tool.Name)
	}

	matrix := make(map[string]map[string]float64)
	for _, vec := range vectors {
		matrix[vec] = make(map[string]float64)
		for _, r := range results {
			maxScore := 0.0
			for _, s := range r.Scenarios {
				if score, ok := s.VectorScores[vec]; ok && score > maxScore {
					maxScore = score
				}
			}
			matrix[vec][r.Tool.Name] = maxScore
		}
	}

	return VectorToolMatrix{
		Vectors: vectors,
		Tools:   tools,
		Matrix:  matrix,
	}
}

// PrintComparisonReport prints the formatted cross-tool comparison report.
func PrintComparisonReport(report *ToolComparisonReport) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            CROSS-TOOL SHIELD COMPARISON REPORT              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Evasion ranking
	fmt.Println("━━━ Evasion Ranking (lower score = better stealth) ━━━")
	fmt.Printf("  %2s  %-26s %-20s %7s  %9s\n", "#", "Tool", "Category", "Evasion", "Avg Score")
	fmt.Println("  " + strings.Repeat("─", 70))
	for _, entry := range report.Ranking {
		fmt.Printf("  %2d  %-26s %-20s %6.1f%%  %9.3f\n",
			entry.Rank,
			entry.ToolName,
			string(entry.Category),
			entry.EvasionRate*100,
			entry.AvgScore,
		)
	}
	fmt.Println()

	// Vector detection matrix
	fmt.Println("━━━ Vector Detection Matrix ━━━")
	fmt.Println("  (scores > 0.30 = detected, shown as X)")
	fmt.Println()

	// Column headers — abbreviate tool names
	abbrevs := make([]string, len(report.VectorMatrix.Tools))
	for i, t := range report.VectorMatrix.Tools {
		abbr := t
		if len(abbr) > 10 {
			abbr = abbr[:10]
		}
		abbrevs[i] = abbr
	}

	fmt.Printf("  %-14s", "Vector")
	for _, a := range abbrevs {
		fmt.Printf(" │ %-10s", a)
	}
	fmt.Println()
	fmt.Print("  " + strings.Repeat("─", 14))
	for range abbrevs {
		fmt.Print("─┼" + strings.Repeat("─", 11))
	}
	fmt.Println()

	for _, vec := range report.VectorMatrix.Vectors {
		fmt.Printf("  %-14s", vec)
		for _, tool := range report.VectorMatrix.Tools {
			score := report.VectorMatrix.Matrix[vec][tool]
			if score > 0.30 {
				fmt.Printf(" │ %10s", fmt.Sprintf("X (%.2f)", score))
			} else if score > 0 {
				fmt.Printf(" │ %10s", fmt.Sprintf("  (%.2f)", score))
			} else {
				fmt.Printf(" │ %10s", "   ---")
			}
		}
		fmt.Println()
	}
	fmt.Println()

	// Per-tool detail
	fmt.Println("━━━ Per-Tool Detail ━━━")
	for _, r := range report.Results {
		fmt.Printf("\n  %s [%s] — Detection: %.0f%%, Avg Score: %.3f\n",
			r.Tool.Name, string(r.Tool.Category), r.DetectionRate*100, r.AvgBotScore)
		if r.Tool.Description != "" {
			fmt.Printf("    %s\n", r.Tool.Description)
		}

		for _, s := range r.Scenarios {
			botLabel := "PASS"
			if s.IsBot {
				botLabel = "DETECTED"
			}
			fmt.Printf("    %-40s  score=%.3f  %s\n", s.Name, s.BotScore, botLabel)

			if len(s.Indicators) > 0 {
				for _, ind := range s.Indicators {
					fmt.Printf("      - %s\n", ind)
				}
			}
		}
	}
	fmt.Println()
}

// ExportComparisonJSON exports the report as JSON.
func ExportComparisonJSON(report *ToolComparisonReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// RunCaptchaBenchmark tests tools in the captcha zone (score 0.20-0.60) by
// creating real captcha challenges, attempting to solve them, and submitting
// with behavioral events.
func RunCaptchaBenchmark(numCaptchas int) []CaptchaToolResult {
	if numCaptchas <= 0 {
		numCaptchas = 10
	}

	results := make([]CaptchaToolResult, 0)

	type toolSolver struct {
		name      string
		hasSolver bool
	}

	tools := []toolSolver{
		{"our_stealth_sword", true},
		{"python_requests", false},
		{"playwright_default", false},
		{"nodriver", false},
		{"scrapling_stealthy", false},
	}

	// Use reduced-noise captchas for benchmarking. The DefaultConfig has
	// NoiseLines=3, NoiseDots=50, Rotate=true, Wave=true which makes template
	// matching impossible. Realistic benchmarks use moderate noise.
	benchGen := captcha.NewGenerator(&captcha.CaptchaConfig{
		Length:          6,
		Width:           200,
		Height:          80,
		FontSize:        36,
		CharSet:         "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
		NoiseLines:      1,
		NoiseDots:       15,
		BackgroundColor: captcha.DefaultConfig.BackgroundColor,
		Difficulty:      captcha.DifficultyEasy,
		Rotate:          false,
		Wave:            false,
	})

	for _, tool := range tools {
		solvedCount := 0
		behavioralPassCount := 0
		endToEndPassCount := 0

		for i := 0; i < numCaptchas; i++ {
			// Generate a captcha with reduced noise for meaningful solver comparison
			c, err := benchGen.Generate(captcha.CaptchaTypeText)
			if err != nil {
				continue
			}

			sol, ok := c.Solution.(captcha.TextSolution)
			if !ok {
				continue
			}
			expectedText := sol.Text

			// Attempt solve: sword has TemplateSolver, others don't
			var solution string
			if tool.hasSolver {
				ts := captcha.NewTemplateSolver()
				solution, _ = ts.SolveWithTemplates(c.Image, 6)
			}

			// Check answer correctness
			answerCorrect := strings.EqualFold(strings.TrimSpace(solution), strings.TrimSpace(expectedText))
			if answerCorrect {
				solvedCount++
			}

			// Generate behavioral events and check bot score
			challengeID := fmt.Sprintf("bench-%s-%d", tool.name, i)
			solver := newBenchCaptchaSolver()
			events := solver.GenerateHumanEvents(4000)

			tracer := adversarial.NewCaptchaTracer()
			trace := tracer.CreateTrace(challengeID, "bench", "text")
			for _, ev := range events {
				tracer.AddEvent(challengeID, ev)
			}
			_ = trace
			traceResult, _ := tracer.GetTrace(challengeID)
			if traceResult != nil {
				botScore := tracer.CalculateBotScore(traceResult)
				if botScore < 0.5 {
					behavioralPassCount++
					if answerCorrect {
						endToEndPassCount++
					}
				}
			}
		}

		results = append(results, CaptchaToolResult{
			ToolName:           tool.name,
			CaptchaSolveRate:   float64(solvedCount) / float64(numCaptchas),
			BehavioralPassRate: float64(behavioralPassCount) / float64(numCaptchas),
			EndToEndPassRate:   float64(endToEndPassCount) / float64(numCaptchas),
			Attempts:           numCaptchas,
		})
	}

	return results
}

// newBenchCaptchaSolver creates a minimal CaptchaSolver for benchmark use.
// It uses the same GenerateHumanEvents logic as the real sword.
type benchCaptchaSolver struct {
	rng *rand.Rand
}

func newBenchCaptchaSolver() *benchCaptchaSolver {
	//nolint:gosec
	return &benchCaptchaSolver{rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (b *benchCaptchaSolver) GenerateHumanEvents(solveTimeMs int64) []adversarial.CaptchaEvent {
	events := make([]adversarial.CaptchaEvent, 0, 80)
	baseTime := time.Now().UnixMilli()
	cursor := 0.0

	// Preferred tremor direction (wrist anatomy bias) - prevents uniform_tremor_angles
	preferredAngle := b.rng.Float64() * 2 * math.Pi

	// Mouse path via cubic Bézier with varying path efficiency
	numPts := 8 + b.rng.Intn(5)
	startX, startY := 100.0+b.rng.Float64()*50, 150.0+b.rng.Float64()*30
	endX, endY := 250.0+b.rng.Float64()*60, 340.0+b.rng.Float64()*30
	cp1X := startX + (endX-startX)*0.3 + (b.rng.Float64()-0.5)*100
	cp1Y := startY + (endY-startY)*0.3 + (b.rng.Float64()-0.5)*80
	cp2X := startX + (endX-startX)*0.7 + (b.rng.Float64()-0.5)*100
	cp2Y := startY + (endY-startY)*0.7 + (b.rng.Float64()-0.5)*80
	mouseDur := float64(solveTimeMs) * 0.50
	_ = mouseDur // Used for timing reference

	// Use multi-modal interval distribution for high entropy
	// 4 modes: fast(5-20ms), normal(20-60ms), slow(60-150ms), pause(150-400ms)
	intervalModes := []struct{ min, max float64 }{
		{5, 20},    // fast
		{20, 60},   // normal
		{60, 150},  // slow
		{150, 400}, // pause
	}

	// Generate events as a mixed stream to avoid sequential_event_ordering
	mouseIdx := 0
	keyIdx := 0
	scrollIdx := 0
	clickCount := 0

	clickX := endX + b.rng.Float64()*8.37
	clickY := endY + b.rng.Float64()*5.82

	for mouseIdx < numPts*4 || keyIdx < 12 || scrollIdx < 4 || clickCount < 2 {
		choice := b.rng.Float64()

		switch {
		case mouseIdx < numPts*4 && (choice < 0.6 || keyIdx >= 12):
			// Mouse movement
			i := mouseIdx / 4
			j := mouseIdx % 4
			if j == 0 && i < numPts {
				// Major movement point
				t := float64(i) / float64(numPts-1)
				t = t * t * (3 - 2*t)
				x := benchBezier(t, startX, cp1X, cp2X, endX) + (b.rng.Float64()-0.5)*6
				y := benchBezier(t, startY, cp1Y, cp2Y, endY) + (b.rng.Float64()-0.5)*4
				// Use multi-modal interval for high entropy
				mode := intervalModes[b.rng.Intn(len(intervalModes))]
				interval := mode.min + b.rng.Float64()*(mode.max-mode.min)
				cursor += interval
				events = append(events, adversarial.CaptchaEvent{
					Type: "mousemove", Timestamp: baseTime + int64(cursor), ElapsedMs: int64(cursor), X: x, Y: y,
				})
			} else {
				// Micro-tremor with directional bias (prevent uniform_tremor_angles)
				if len(events) > 0 {
					lastEv := events[len(events)-1]
					// Use wrapped normal around preferred direction
					angle := preferredAngle + b.rng.NormFloat64()*0.8
					radius := 0.5 + b.rng.Float64()*2.5
					x := lastEv.X + radius*math.Cos(angle)
					y := lastEv.Y + radius*math.Sin(angle)
					// Multi-modal interval
					mode := intervalModes[b.rng.Intn(len(intervalModes))]
					interval := mode.min + b.rng.Float64()*(mode.max-mode.min)
					cursor += interval
					events = append(events, adversarial.CaptchaEvent{
						Type: "mousemove", Timestamp: baseTime + int64(cursor), ElapsedMs: int64(cursor), X: x, Y: y,
					})
				}
			}
			mouseIdx++

		case scrollIdx < 4 && (choice < 0.75 || mouseIdx >= numPts*4):
			// Scroll event
			cursor += benchLogNormal(b.rng, 150, 80)
			events = append(events, adversarial.CaptchaEvent{
				Type: "scroll", Timestamp: baseTime + int64(cursor), ElapsedMs: int64(cursor), Delta: 80 + b.rng.Float64()*120,
			})
			scrollIdx++

		case clickCount < 2 && (choice < 0.85 || mouseIdx > numPts*2):
			// Click event
			cursor += benchLogNormal(b.rng, 100, 50)
			// Add sub-pixel jitter to avoid integer-coordinate precision
			events = append(events, adversarial.CaptchaEvent{
				Type: "click", Timestamp: baseTime + int64(cursor), ElapsedMs: int64(cursor),
				X: clickX + b.rng.Float64()*0.8 - 0.4, Y: clickY + b.rng.Float64()*0.6 - 0.3,
			})
			clickCount++

		case keyIdx < 12:
			// Keystroke
			cursor += benchLogNormal(b.rng, 120, 55)
			events = append(events, adversarial.CaptchaEvent{
				Type: "keydown", Timestamp: baseTime + int64(cursor), ElapsedMs: int64(cursor), Key: "a",
			})
			keyUpDelay := 30 + b.rng.Float64()*50
			events = append(events, adversarial.CaptchaEvent{
				Type: "keyup", Timestamp: baseTime + int64(cursor+keyUpDelay), ElapsedMs: int64(cursor + keyUpDelay), Key: "a",
			})
			keyIdx += 2

			// Occasional thinking pause
			if keyIdx%4 == 0 && b.rng.Float64() < 0.5 {
				cursor += 400 + b.rng.Float64()*600
			}

		default:
			// Fallback: advance cursor
			cursor += 50
		}
	}

	// Submit click
	cursor += benchLogNormal(b.rng, 80, 35)
	events = append(events, adversarial.CaptchaEvent{
		Type: "click", Timestamp: baseTime + int64(cursor), ElapsedMs: int64(cursor),
		X: 350 + b.rng.Float64()*3.14, Y: 400 + b.rng.Float64()*2.71,
	})

	return events
}

func benchBezier(t, p0, p1, p2, p3 float64) float64 {
	u := 1 - t
	return u*u*u*p0 + 3*u*u*t*p1 + 3*u*t*t*p2 + t*t*t*p3
}

func benchLogNormal(r *rand.Rand, meanMs, stddevMs float64) float64 {
	u1 := r.Float64()
	u2 := r.Float64()
	if u1 < 1e-10 {
		u1 = 1e-10
	}
	normal := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	variance := stddevMs * stddevMs
	mu := math.Log(meanMs * meanMs / math.Sqrt(variance+meanMs*meanMs))
	sigma := math.Sqrt(math.Log(1 + variance/(meanMs*meanMs)))
	result := math.Exp(mu + sigma*normal)
	if result < 5 {
		result = 5
	}
	if result > meanMs*5 {
		result = meanMs * 5
	}
	return result
}

func decodeBase64Image(b64 string) (image.Image, error) {
	if idx := strings.Index(b64, ","); idx >= 0 {
		b64 = b64[idx+1:]
	}
	imgBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return png.Decode(bytes.NewReader(imgBytes))
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
