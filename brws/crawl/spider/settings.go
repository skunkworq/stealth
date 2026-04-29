package spider

import (
	"time"
)

type Settings struct {
	data map[string]interface{}
}

func NewSettings() *Settings {
	s := &Settings{
		data: make(map[string]interface{}),
	}
	s.setDefaults()
	return s
}

func (s *Settings) setDefaults() {
	s.data["ENGINE"] = "native"
	s.data["CONCURRENT_REQUESTS"] = 16
	s.data["CONCURRENT_REQUESTS_PER_DOMAIN"] = 8
	s.data["CONCURRENT_REQUESTS_PER_IP"] = 0
	s.data["DOWNLOAD_DELAY"] = 0
	s.data["DOWNLOAD_TIMEOUT"] = 180 * time.Second
	s.data["MAX_DEPTH"] = 0
	s.data["MAX_DEPTH_PRECEDENCE"] = true
	s.data["MAX_REQUEST_SIZE"] = 0
	s.data["RETRY_ENABLED"] = true
	s.data["RETRY_TIMES"] = 2
	s.data["RETRY_HTTP_CODES"] = []int{500, 502, 503, 504, 408, 429}
	s.data["ROBOTSTXT_OBEY"] = true
	s.data["USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	s.data["DEFAULT_HEADERS"] = map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.5",
		"Accept-Encoding":           "gzip, deflate",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
	}
	s.data["COOKIES_ENABLED"] = true
	s.data["TELNET_CONSOLE_ENABLED"] = false
	s.data["DEFAULT_INPUT_ENCODING"] = "utf-8"
	s.data["FEED_EXPORT_ENCODING"] = "utf-8"
	s.data["LOG_LEVEL"] = "INFO"
	s.data["LOG_ENCODING"] = "utf-8"
	s.data["LOG_FORMAT"] = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
	s.data["LOG_DATEFORMAT"] = "%Y-%m-%d %H:%M:%S"
	s.data["REDIRECT_ENABLED"] = true
	s.data["REDIRECT_MAX_TIMES"] = 20
	s.data["REDIRECT_MAX_METAREFRESH_DELAY"] = 10 * time.Second
	s.data["COOKIES_DEBUG"] = false
	s.data["DOWNLOAD_MAX_FAILURES"] = 5
	s.data["DOWNLOAD_FAILURE_WAIT"] = 10 * time.Second
	s.data["AUTOTHROTTLE_ENABLED"] = false
	s.data["AUTOTHROTTLE_START_DELAY"] = 1 * time.Second
	s.data["AUTOTHROTTLE_MAX_DELAY"] = 60 * time.Second
	s.data["AUTOTHROTTLE_TARGET_CONCURRENCY"] = 1.0
	s.data["AUTOTHROTTLE_DEBUG"] = false
	s.data["HTTPCACHE_ENABLED"] = false
	s.data["MEMUSAGE_ENABLED"] = true
	s.data["MEMUSAGE_LIMIT_MB"] = 0
	s.data["MEMUSAGE_CHECK_INTERVAL"] = 1 * time.Minute
	s.data["CLOSESPIDER_TIMEOUT"] = 0
	s.data["CLOSESPIDER_ITEMCOUNT"] = 0
	s.data["CLOSESPIDER_PAGECOUNT"] = 0
	s.data["CLOSESPIDER_ERRORCOUNT"] = 0
	s.data["SCHEDULER_PRIORITY_QUEUE"] = "scrapy.pqueues.ScrapyPriorityQueue"
	s.data["SCHEDULER_DISK_QUEUE"] = "scrapy.pqueues.ScrapyDiskQueue"
	s.data["SCHEDULER_MEMORY_QUEUE"] = "scrapy.pqueues.ScrapyMemoryQueue"
	s.data["SCHEDULER_PRIORITIES_REVERSE"] = true
	s.data["REQUEST_FINGERPRINTER_IMPLEMENTATION"] = "2.7"
	s.data["TWISTED_REACTOR"] = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
	s.data["FEED_FORMAT"] = "jsonlines"
	s.data["FEED_URI"] = ""
	s.data["FEED_EXPORT_BATCH_ITEM_COUNT"] = 100
}

func (s *Settings) Get(key string) interface{} {
	return s.data[key]
}

func (s *Settings) GetString(key string) string {
	if v, ok := s.data[key].(string); ok {
		return v
	}
	return ""
}

func (s *Settings) GetBool(key string) bool {
	if v, ok := s.data[key].(bool); ok {
		return v
	}
	return false
}

func (s *Settings) GetInt(key string) int {
	switch v := s.data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func (s *Settings) GetFloat(key string) float64 {
	if v, ok := s.data[key].(float64); ok {
		return v
	}
	return 0
}

func (s *Settings) GetDuration(key string) time.Duration {
	if v, ok := s.data[key].(time.Duration); ok {
		return v
	}
	return 0
}

func (s *Settings) GetStringList(key string) []string {
	if v, ok := s.data[key].([]string); ok {
		return v
	}
	return nil
}

func (s *Settings) GetIntList(key string) []int {
	if v, ok := s.data[key].([]int); ok {
		return v
	}
	return nil
}

func (s *Settings) GetDict(key string) map[string]interface{} {
	if v, ok := s.data[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func (s *Settings) Set(key string, value interface{}) {
	s.data[key] = value
}

func (s *Settings) SetDefault(key string, value interface{}) {
	if _, exists := s.data[key]; !exists {
		s.data[key] = value
	}
}

func (s *Settings) Setdict(values map[string]interface{}) {
	for k, v := range values {
		s.data[k] = v
	}
}

func (s *Settings) Copy() *Settings {
	newSettings := &Settings{
		data: make(map[string]interface{}),
	}
	for k, v := range s.data {
		newSettings.data[k] = v
	}
	return newSettings
}

func (s *Settings) Freeze() {
}

func (s *Settings) GetFloatWithDefault(key string, defaultValue float64) float64 {
	if v, ok := s.data[key].(float64); ok {
		return v
	}
	return defaultValue
}

func (s *Settings) GetIntWithDefault(key string, defaultValue int) int {
	switch v := s.data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return defaultValue
}

func (s *Settings) GetBoolWithDefault(key string, defaultValue bool) bool {
	if v, ok := s.data[key].(bool); ok {
		return v
	}
	return defaultValue
}
