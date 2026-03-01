package spider

type Settings interface {
	Get(key string) any
	GetString(key string) string
	GetInt(key string) int
	GetBool(key string) bool
	GetFloat(key string) float64
	GetList(key string) []string

	Set(key string, value any)
	SetPriority(key string, value any, priority Priority)

	Copy() Settings
}

type Priority int

const (
	PriorityDefault Priority = iota
	PriorityLow
	PriorityMedium
	PriorityHigh
	PriorityCommand
)

type defaultSettings struct {
	data map[string]any
}

func DefaultSettings() Settings {
	return &defaultSettings{
		data: map[string]any{
			"CONCURRENT_REQUESTS":            16,
			"CONCURRENT_REQUESTS_PER_DOMAIN": 8,
			"DOWNLOAD_DELAY":                 0,
			"DOWNLOAD_TIMEOUT":               180,
			"RETRY_ENABLED":                  true,
			"RETRY_TIMES":                    2,
			"RETRY_HTTP_CODES":               []int{500, 502, 503, 504, 408, 429},
			"COOKIES_ENABLED":                true,
			"TELNET_CONSOLE_ENABLED":         false,
			"DEFAULT_REQUEST_HEADERS": map[string]string{
				"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.5",
				"Accept-Encoding": "gzip, deflate",
				"Connection":      "keep-alive",
			},
			"SPIDER_MIDDLEWARES":              map[string]int{},
			"DOWNLOADER_MIDDLEWARES":          map[string]int{},
			"ITEM_PIPELINES":                  map[string]int{},
			"AUTOTHROTTLE_ENABLED":            false,
			"AUTOTHROTTLE_START_DELAY":        5,
			"AUTOTHROTTLE_MAX_DELAY":          60,
			"AUTOTHROTTLE_TARGET_CONCURRENCY": 1.0,
			"HTTPCACHE_ENABLED":               false,
			"LOG_LEVEL":                       "INFO",
			"ROBOTSTXT_OBEY":                  true,
			"CLOSESPIDER_ITEMCOUNT":           0,
			"CLOSESPIDER_REQUESTCOUNT":        0,
			"CLOSESPIDER_ERRORCOUNT":          0,
			"CLOSESPIDER_TIMEOUT":             0,
		},
	}
}

func (s *defaultSettings) Get(key string) any {
	if v, ok := s.data[key]; ok {
		return v
	}
	return nil
}

func (s *defaultSettings) GetString(key string) string {
	if v, ok := s.data[key].(string); ok {
		return v
	}
	return ""
}

func (s *defaultSettings) GetInt(key string) int {
	switch v := s.data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}

func (s *defaultSettings) GetBool(key string) bool {
	if v, ok := s.data[key].(bool); ok {
		return v
	}
	return false
}

func (s *defaultSettings) GetFloat(key string) float64 {
	if v, ok := s.data[key].(float64); ok {
		return v
	}
	return 0
}

func (s *defaultSettings) GetList(key string) []string {
	if v, ok := s.data[key].([]string); ok {
		return v
	}
	if v, ok := s.data[key].([]interface{}); ok {
		result := make([]string, len(v))
		for i, item := range v {
			if s, ok := item.(string); ok {
				result[i] = s
			}
		}
		return result
	}
	return nil
}

func (s *defaultSettings) Set(key string, value any) {
	s.data[key] = value
}

func (s *defaultSettings) SetPriority(key string, value any, priority Priority) {
	s.data[key] = value
}

func (s *defaultSettings) Copy() Settings {
	dataCopy := make(map[string]any)
	for k, v := range s.data {
		dataCopy[k] = v
	}
	return &defaultSettings{data: dataCopy}
}
