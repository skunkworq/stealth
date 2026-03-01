package spider

type CrawlSpider struct {
	Name      string
	StartURLs []string
	Rules     []Rule
	Allowed   []string
	Denied    []string
}

type Rule struct {
	LinkExtractor LinkExtractor
	Callback      string
	Follow        bool
}

type LinkExtractor interface {
	ExtractLinks(response Response) []Link
}

type Link struct {
	URL    string
	Text   string
	Params map[string]string
}

type crawlSpider struct {
	name      string
	startURLs []string
	rules     []Rule
	allow     []string
	deny      []string
	parseFunc func(Response) []ParseResult
}

func NewCrawlSpider(name string, startURLs []string, rules []Rule) Spider {
	return &crawlSpider{
		name:      name,
		startURLs: startURLs,
		rules:     rules,
	}
}

func (s *crawlSpider) Name() string {
	return s.name
}

func (s *crawlSpider) StartRequests() []Request {
	var requests []Request
	for _, url := range s.startURLs {
		requests = append(requests, Request{
			URL:      url,
			Callback: s.Parse,
		})
	}
	return requests
}

func (s *crawlSpider) Parse(resp Response) []ParseResult {
	return s.parseFunc(resp)
}

func (s *crawlSpider) SetParseFunc(f func(Response) []ParseResult) {
	s.parseFunc = f
}

type RegexLinkExtractor struct {
	AllowPatterns []string
	DenyPatterns  []string
	CSSSelector   string
	XPathSelector string
}

func NewRegexLinkExtractor() *RegexLinkExtractor {
	return &RegexLinkExtractor{}
}

func (r *RegexLinkExtractor) ExtractLinks(resp Response) []Link {
	var links []Link

	if r.CSSSelector != "" {
		elements := resp.CSS(r.CSSSelector)
		for _, el := range elements {
			href := el.Attr("href")
			if href != "" {
				links = append(links, Link{
					URL:  href,
					Text: el.Text(),
				})
			}
		}
	}

	if r.XPathSelector != "" {
		elements := resp.XPath(r.XPathSelector)
		for _, el := range elements {
			href := el.Attr("href")
			if href != "" {
				links = append(links, Link{
					URL:  href,
					Text: el.Text(),
				})
			}
		}
	}

	return links
}

func AllowDomains(domains ...string) func(*RegexLinkExtractor) {
	return func(e *RegexLinkExtractor) {
		_ = domains
	}
}

func RestrictCSS(selector string) func(*RegexLinkExtractor) {
	return func(e *RegexLinkExtractor) {
		e.CSSSelector = selector
	}
}

func RestrictXPath(xpath string) func(*RegexLinkExtractor) {
	return func(e *RegexLinkExtractor) {
		e.XPathSelector = xpath
	}
}
