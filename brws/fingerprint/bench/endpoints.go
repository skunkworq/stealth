// Package benchmark provides comprehensive endpoint configurations for testing
// different capabilities and protection levels across browser engines.
package benchmark

import (
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

// ProtectionLevel categorizes the type of protection on a target endpoint
type ProtectionLevel string

const (
	ProtectionNone       ProtectionLevel = "none"       // No protection (e.g., httpbin)
	ProtectionBasic      ProtectionLevel = "basic"      // Basic rate limiting
	ProtectionCloudflare ProtectionLevel = "cloudflare" // Cloudflare protection
	ProtectionIncapsula  ProtectionLevel = "incapsula"  // Incapsula/Imperva
	ProtectionAkamai     ProtectionLevel = "akamai"     // Akamai Bot Manager
	ProtectionDataDome   ProtectionLevel = "datadome"   // DataDome
	ProtectionPerimeterX ProtectionLevel = "perimeterx" // PerimeterX/Human
	ProtectionCustom     ProtectionLevel = "custom"     // Custom/proprietary
)

// CapabilityTest represents a test for a specific engine capability
type CapabilityTest string

const (
	CapJavaScript     CapabilityTest = "javascript"      // JS execution capability
	CapHTTP2          CapabilityTest = "http2"           // HTTP/2 support
	CapHTTP3          CapabilityTest = "http3"           // HTTP/3/QUIC support
	CapWebSocket      CapabilityTest = "websocket"       // WebSocket support
	CapIntercept      CapabilityTest = "intercept"       // Request interception
	CapPersistentProf CapabilityTest = "persistent_prof" // Persistent profile
	CapNetLog         CapabilityTest = "netlog"          // Network logging
)

// Endpoint represents a target URL for benchmarking
type Endpoint struct {
	Name            string            `json:"name" yaml:"name"`
	URL             string            `json:"url" yaml:"url"`
	Description     string            `json:"description" yaml:"description"`
	ExpectedContent string            `json:"expected_content" yaml:"expected_content"`
	Protection      ProtectionLevel   `json:"protection" yaml:"protection"`
	RequiredCaps    []CapabilityTest  `json:"required_caps,omitempty" yaml:"required_caps,omitempty"`
	Headers         map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Timeout         time.Duration     `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Retries         int               `json:"retries" yaml:"retries"`
	Category        string            `json:"category" yaml:"category"`
}

// EndpointCategory groups related endpoints
type EndpointCategory struct {
	Name        string     `json:"name" yaml:"name"`
	Description string     `json:"description" yaml:"description"`
	Endpoints   []Endpoint `json:"endpoints" yaml:"endpoints"`
}

// DefaultEndpoints returns the comprehensive endpoint configuration
func DefaultEndpoints() []EndpointCategory {
	return []EndpointCategory{
		{
			Name:        "basic",
			Description: "Basic connectivity and protocol tests",
			Endpoints: []Endpoint{
				{
					Name:            "httpbin_get",
					URL:             "https://httpbin.org/get",
					Description:     "Basic HTTP GET test",
					ExpectedContent: "origin",
					Protection:      ProtectionNone,
					Retries:         1,
					Category:        "basic",
				},
				{
					Name:            "httpbin_headers",
					URL:             "https://httpbin.org/headers",
					Description:     "Header reflection test",
					ExpectedContent: "User-Agent",
					Protection:      ProtectionNone,
					Retries:         1,
					Category:        "basic",
				},
				{
					Name:            "httpbin_ip",
					URL:             "https://httpbin.org/ip",
					Description:     "IP address check",
					ExpectedContent: "origin",
					Protection:      ProtectionNone,
					Retries:         1,
					Category:        "basic",
				},
				{
					Name:            "httpbin_user_agent",
					URL:             "https://httpbin.org/user-agent",
					Description:     "User-Agent reflection",
					ExpectedContent: "Mozilla",
					Protection:      ProtectionNone,
					Retries:         1,
					Category:        "basic",
				},
			},
		},
		{
			Name:        "protocol",
			Description: "Protocol-specific tests (HTTP/2, HTTP/3)",
			Endpoints: []Endpoint{
				{
					Name:            "http2_check",
					URL:             "https://www.google.com",
					Description:     "HTTP/2 protocol negotiation",
					ExpectedContent: "google",
					Protection:      ProtectionBasic,
					RequiredCaps:    []CapabilityTest{CapHTTP2},
					Retries:         2,
					Category:        "protocol",
				},
				{
					Name:            "cloudflare_http3",
					URL:             "https://cloudflare-quic.com",
					Description:     "HTTP/3/QUIC support test",
					ExpectedContent: "QUIC",
					Protection:      ProtectionNone,
					RequiredCaps:    []CapabilityTest{CapHTTP3},
					Retries:         2,
					Category:        "protocol",
				},
				{
					Name:            "http2_push",
					URL:             "https://nghttp2.org/httpbin/get",
					Description:     "HTTP/2 endpoint test",
					ExpectedContent: "headers",
					Protection:      ProtectionNone,
					RequiredCaps:    []CapabilityTest{CapHTTP2},
					Retries:         2,
					Category:        "protocol",
				},
			},
		},
		{
			Name:        "javascript",
			Description: "JavaScript execution tests",
			Endpoints: []Endpoint{
				{
					Name:            "js_challenge_react",
					URL:             "https://react.dev",
					Description:     "React documentation (heavy JS)",
					ExpectedContent: "React",
					Protection:      ProtectionNone,
					RequiredCaps:    []CapabilityTest{CapJavaScript},
					Timeout:         30 * time.Second,
					Retries:         2,
					Category:        "javascript",
				},
				{
					Name:            "js_challenge_vue",
					URL:             "https://vuejs.org",
					Description:     "Vue.js documentation (SPA)",
					ExpectedContent: "Vue",
					Protection:      ProtectionNone,
					RequiredCaps:    []CapabilityTest{CapJavaScript},
					Timeout:         30 * time.Second,
					Retries:         2,
					Category:        "javascript",
				},
				{
					Name:            "js_challenge_angular",
					URL:             "https://angular.io",
					Description:     "Angular documentation (complex JS)",
					ExpectedContent: "Angular",
					Protection:      ProtectionNone,
					RequiredCaps:    []CapabilityTest{CapJavaScript},
					Timeout:         30 * time.Second,
					Retries:         2,
					Category:        "javascript",
				},
			},
		},
		{
			Name:        "websocket",
			Description: "WebSocket capability tests",
			Endpoints: []Endpoint{
				{
					Name:            "websocket_echo",
					URL:             "https://www.websocket.org/echo.html",
					Description:     "WebSocket echo test",
					ExpectedContent: "WebSocket",
					Protection:      ProtectionNone,
					RequiredCaps:    []CapabilityTest{CapWebSocket, CapJavaScript},
					Timeout:         20 * time.Second,
					Retries:         2,
					Category:        "websocket",
				},
			},
		},
		{
			Name:        "content",
			Description: "Content-heavy pages",
			Endpoints: []Endpoint{
				{
					Name:            "wikipedia",
					URL:             "https://en.wikipedia.org/wiki/Benchmark",
					Description:     "Wikipedia article (static content)",
					ExpectedContent: "benchmark",
					Protection:      ProtectionNone,
					Retries:         2,
					Category:        "content",
				},
				{
					Name:            "news_bbc",
					URL:             "https://www.bbc.com",
					Description:     "BBC News (media heavy)",
					ExpectedContent: "BBC",
					Protection:      ProtectionBasic,
					Retries:         2,
					Category:        "content",
				},
				{
					Name:            "news_reuters",
					URL:             "https://www.reuters.com",
					Description:     "Reuters news",
					ExpectedContent: "Reuters",
					Protection:      ProtectionBasic,
					Retries:         2,
					Category:        "content",
				},
				{
					Name:            "hn_frontpage",
					URL:             "https://news.ycombinator.com",
					Description:     "Hacker News (lightweight)",
					ExpectedContent: "Hacker",
					Protection:      ProtectionNone,
					Retries:         2,
					Category:        "content",
				},
			},
		},
		{
			Name:        "protected",
			Description: "Protected endpoints (WAF/bot detection)",
			Endpoints: []Endpoint{
				{
					Name:            "coles_product",
					URL:             "https://www.coles.com.au/product/coles-hass-avocados-1-each-5900530",
					Description:     "Coles product page (Incapsula)",
					ExpectedContent: "avocado",
					Protection:      ProtectionIncapsula,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "protected",
				},
				{
					Name:            "etsy_product",
					URL:             "https://www.etsy.com",
					Description:     "Etsy homepage (multiple protections)",
					ExpectedContent: "Etsy",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "protected",
				},
				{
					Name:            "g2_reviews",
					URL:             "https://www.g2.com",
					Description:     "G2 reviews (DataDome)",
					ExpectedContent: "Software",
					Protection:      ProtectionDataDome,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "protected",
				},
				{
					Name:            "indeed_jobs",
					URL:             "https://www.indeed.com",
					Description:     "Indeed job search",
					ExpectedContent: "Indeed",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "protected",
				},
				{
					Name:            "glassdoor",
					URL:             "https://www.glassdoor.com",
					Description:     "Glassdoor reviews",
					ExpectedContent: "Glassdoor",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "protected",
				},
			},
		},
		{
			Name:        "cloudflare",
			Description: "Cloudflare-protected endpoints",
			Endpoints: []Endpoint{
				{
					Name:            "cf_challenge_page",
					URL:             "https://nowsecure.nl",
					Description:     "Cloudflare challenge test page",
					ExpectedContent: "nowsecure",
					Protection:      ProtectionCloudflare,
					RequiredCaps:    []CapabilityTest{CapJavaScript},
					Timeout:         60 * time.Second,
					Retries:         3,
					Category:        "cloudflare",
				},
				{
					Name:            "cf_js_challenge",
					URL:             "https://workers.cloudflare.com",
					Description:     "Cloudflare Workers site",
					ExpectedContent: "Cloudflare",
					Protection:      ProtectionCloudflare,
					Retries:         2,
					Category:        "cloudflare",
				},
			},
		},
		{
			Name:        "api",
			Description: "API endpoints (JSON responses)",
			Endpoints: []Endpoint{
				{
					Name:            "jsonplaceholder_posts",
					URL:             "https://jsonplaceholder.typicode.com/posts/1",
					Description:     "JSONPlaceholder API",
					ExpectedContent: "userId",
					Protection:      ProtectionNone,
					Retries:         1,
					Category:        "api",
				},
				{
					Name:            "httpbin_json",
					URL:             "https://httpbin.org/json",
					Description:     "JSON response test",
					ExpectedContent: "slideshow",
					Protection:      ProtectionNone,
					Retries:         1,
					Category:        "api",
				},
				{
					Name:            "github_api",
					URL:             "https://api.github.com",
					Description:     "GitHub API root",
					ExpectedContent: "current_user_url",
					Protection:      ProtectionBasic,
					Retries:         2,
					Category:        "api",
				},
			},
		},
		{
			Name:        "ecommerce",
			Description: "E-commerce platforms",
			Endpoints: []Endpoint{
				{
					Name:            "amazon_product",
					URL:             "https://www.amazon.com/dp/B08N5WRWNW",
					Description:     "Amazon product page",
					ExpectedContent: "Amazon",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "ecommerce",
				},
				{
					Name:            "ebay_product",
					URL:             "https://www.ebay.com",
					Description:     "EBay homepage",
					ExpectedContent: "eBay",
					Protection:      ProtectionBasic,
					Retries:         2,
					Category:        "ecommerce",
				},
				{
					Name:            "walmart_product",
					URL:             "https://www.walmart.com",
					Description:     "Walmart homepage",
					ExpectedContent: "Walmart",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "ecommerce",
				},
				{
					Name:            "target_product",
					URL:             "https://www.target.com",
					Description:     "Target homepage",
					ExpectedContent: "Target",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         2,
					Category:        "ecommerce",
				},
			},
		},
		{
			Name:        "social",
			Description: "Social media platforms (heavily protected)",
			Endpoints: []Endpoint{
				{
					Name:            "reddit_frontpage",
					URL:             "https://www.reddit.com",
					Description:     "Reddit front page",
					ExpectedContent: "Reddit",
					Protection:      ProtectionCustom,
					Timeout:         45 * time.Second,
					Retries:         3,
					Category:        "social",
				},
				{
					Name:            "twitter_profile",
					URL:             "https://twitter.com/elonmusk",
					Description:     "Twitter/X profile",
					ExpectedContent: "Elon",
					Protection:      ProtectionCustom,
					RequiredCaps:    []CapabilityTest{CapJavaScript},
					Timeout:         60 * time.Second,
					Retries:         3,
					Category:        "social",
				},
				{
					Name:            "linkedin_profile",
					URL:             "https://www.linkedin.com/in/williamhgates",
					Description:     "LinkedIn profile",
					ExpectedContent: "Bill",
					Protection:      ProtectionCustom,
					Timeout:         60 * time.Second,
					Retries:         3,
					Category:        "social",
				},
			},
		},
	}
}

// GetAllEndpoints returns all endpoints as a flat list
func GetAllEndpoints() []Endpoint {
	categories := DefaultEndpoints()
	var endpoints []Endpoint
	for _, cat := range categories {
		endpoints = append(endpoints, cat.Endpoints...)
	}
	return endpoints
}

// GetEndpointsByCategory returns endpoints filtered by category
func GetEndpointsByCategory(category string) []Endpoint {
	categories := DefaultEndpoints()
	for _, cat := range categories {
		if cat.Name == category {
			return cat.Endpoints
		}
	}
	return nil
}

// GetEndpointsByProtection returns endpoints filtered by protection level
func GetEndpointsByProtection(level ProtectionLevel) []Endpoint {
	var endpoints []Endpoint
	for _, ep := range GetAllEndpoints() {
		if ep.Protection == level {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

// GetEndpointsByCapability returns endpoints that require specific capabilities
func GetEndpointsByCapability(cap CapabilityTest) []Endpoint {
	var endpoints []Endpoint
	for _, ep := range GetAllEndpoints() {
		for _, c := range ep.RequiredCaps {
			if c == cap {
				endpoints = append(endpoints, ep)
				break
			}
		}
	}
	return endpoints
}

// FilterEndpointsByEngine returns endpoints compatible with an engine's capabilities
func FilterEndpointsByEngine(endpoints []Endpoint, caps engine.Capabilities) []Endpoint {
	var compatible []Endpoint
	for _, ep := range endpoints {
		if isCompatible(ep.RequiredCaps, caps) {
			compatible = append(compatible, ep)
		}
	}
	return compatible
}

// isCompatible checks if engine capabilities satisfy required capabilities
func isCompatible(required []CapabilityTest, caps engine.Capabilities) bool {
	for _, cap := range required {
		switch cap {
		case CapJavaScript:
			if !caps.JavaScript {
				return false
			}
		case CapHTTP2:
			if !caps.HTTP2 {
				return false
			}
		case CapHTTP3:
			if !caps.HTTP3 {
				return false
			}
		case CapWebSocket:
			if !caps.WebSocket {
				return false
			}
		case CapIntercept:
			if !caps.Intercept {
				return false
			}
		case CapPersistentProf:
			if !caps.PersistentProfile {
				return false
			}
		case CapNetLog:
			if !caps.NetLogExport {
				return false
			}
		}
	}
	return true
}
