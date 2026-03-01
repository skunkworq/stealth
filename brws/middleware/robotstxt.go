package middleware

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/stealth/brwslab/brws/engine"
)

type RobotstxtMiddleware struct {
	mu         sync.RWMutex
	rules      map[string]*RobotRules
	httpClient *http.Client
}

type RobotRules struct {
	Domain     string
	Sitemaps   []string
	Allow      []Rule
	Disallow   []Rule
	CrawlDelay float64
	Crawlable  bool
}

type Rule struct {
	Pattern string
	Allow   bool
}

func NewRobotstxtMiddleware() *RobotstxtMiddleware {
	return &RobotstxtMiddleware{
		rules:      make(map[string]*RobotRules),
		httpClient: &http.Client{},
	}
}

func (r *RobotstxtMiddleware) ProcessRequest(ctx context.Context, req *engine.Request) (*engine.Request, *Response) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return req, nil
	}

	domain := parsedURL.Hostname()

	if !r.isAllowed(domain, req.URL) {
		return nil, &Response{
			Error: &RobotsDeniedError{URL: req.URL, Domain: domain},
			Drop:  true,
		}
	}

	return req, nil
}

func (r *RobotstxtMiddleware) ProcessResponse(ctx context.Context, req *engine.Request, resp *engine.Response) (*engine.Response, *Response) {
	return resp, nil
}

func (r *RobotstxtMiddleware) ProcessException(ctx context.Context, req *engine.Request, err error) (*engine.Response, *Response) {
	return nil, nil
}

func (r *RobotstxtMiddleware) isAllowed(domain, urlPath string) bool {
	r.mu.RLock()
	rules, exists := r.rules[domain]
	r.mu.RUnlock()

	if !exists {
		rules = r.fetchRules(domain)
		if rules != nil {
			r.mu.Lock()
			r.rules[domain] = rules
			r.mu.Unlock()
		}
		return true
	}

	if !rules.Crawlable {
		return false
	}

	path := "/"
	if parsed, err := url.Parse(urlPath); err == nil {
		path = parsed.Path
	}

	for _, rule := range rules.Disallow {
		if matchesPattern(path, rule.Pattern) {
			for _, allow := range rules.Allow {
				if matchesPattern(path, allow.Pattern) {
					return true
				}
			}
			return false
		}
	}

	return true
}

func (r *RobotstxtMiddleware) fetchRules(domain string) *RobotRules {
	robotsURL := "http://" + domain + "/robots.txt"

	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		return &RobotRules{Domain: domain, Crawlable: true}
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return &RobotRules{Domain: domain, Crawlable: true}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &RobotRules{Domain: domain, Crawlable: true}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &RobotRules{Domain: domain, Crawlable: true}
	}

	return parseRobotstxt(domain, string(body))
}

func parseRobotstxt(domain, body string) *RobotRules {
	rules := &RobotRules{
		Domain:    domain,
		Crawlable: true,
		Allow:     make([]Rule, 0),
		Disallow:  make([]Rule, 0),
	}

	lines := strings.Split(body, "\n")
	var currentUserAgent string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		case "user-agent":
			currentUserAgent = strings.ToLower(value)
		case "disallow":
			if currentUserAgent != "" {
				rules.Disallow = append(rules.Disallow, Rule{Pattern: value, Allow: false})
			}
		case "allow":
			if currentUserAgent != "" {
				rules.Allow = append(rules.Allow, Rule{Pattern: value, Allow: true})
			}
		case "crawl-delay":
			if delay, err := strconv.ParseFloat(value, 64); err == nil {
				rules.CrawlDelay = delay
			}
		case "sitemap":
			rules.Sitemaps = append(rules.Sitemaps, value)
		}
	}

	return rules
}

func matchesPattern(path, pattern string) bool {
	if pattern == "" || pattern == "/" {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	if strings.HasSuffix(pattern, "$") {
		pattern = strings.TrimSuffix(pattern, "$")
		return path == pattern
	}

	return strings.Contains(path, pattern)
}

type RobotsDeniedError struct {
	URL    string
	Domain string
}

func (e *RobotsDeniedError) Error() string {
	return "robots.txt denied: " + e.URL
}
