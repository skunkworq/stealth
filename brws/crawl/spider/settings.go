package spider

import (
	"time"
)

// Settings keys provide type-safe access to spider configuration.
const (
	AUTOTHROTTLEDEBUGKey = "AUTOTHROTTLE_DEBUG"
	AUTOTHROTTLEENABLEDKey = "AUTOTHROTTLE_ENABLED"
	AUTOTHROTTLEMAXDELAYKey = "AUTOTHROTTLE_MAX_DELAY"
	AUTOTHROTTLESTARTDELAYKey = "AUTOTHROTTLE_START_DELAY"
	AUTOTHROTTLETARGETCONCURRENCYKey = "AUTOTHROTTLE_TARGET_CONCURRENCY"
	CLOSESPIDERERRORCOUNTKey = "CLOSESPIDER_ERRORCOUNT"
	CLOSESPIDERITEMCOUNTKey = "CLOSESPIDER_ITEMCOUNT"
	CLOSESPIDERPAGECOUNTKey = "CLOSESPIDER_PAGECOUNT"
	CLOSESPIDERTIMEOUTKey = "CLOSESPIDER_TIMEOUT"
	CONCURRENTREQUESTSKey = "CONCURRENT_REQUESTS"
	CONCURRENTREQUESTSPERDOMAINKey = "CONCURRENT_REQUESTS_PER_DOMAIN"
	CONCURRENTREQUESTSPERIPKey = "CONCURRENT_REQUESTS_PER_IP"
	COOKIESDEBUGKey = "COOKIES_DEBUG"
	COOKIESENABLEDKey = "COOKIES_ENABLED"
	DEFAULTHEADERSKey = "DEFAULT_HEADERS"
	DEFAULTINPUTENCODINGKey = "DEFAULT_INPUT_ENCODING"
	DOWNLOADDELAYKey = "DOWNLOAD_DELAY"
	DOWNLOADFAILUREWAITKey = "DOWNLOAD_FAILURE_WAIT"
	DOWNLOADMAXFAILURESKey = "DOWNLOAD_MAX_FAILURES"
	DOWNLOADTIMEOUTKey = "DOWNLOAD_TIMEOUT"
	ENGINEKey = "ENGINE"
	FEEDEXPORTBATCHITEMCOUNTKey = "FEED_EXPORT_BATCH_ITEM_COUNT"
	FEEDEXPORTENCODINGKey = "FEED_EXPORT_ENCODING"
	FEEDFORMATKey = "FEED_FORMAT"
	FEEDURIKey = "FEED_URI"
	HTTPCACHEENABLEDKey = "HTTPCACHE_ENABLED"
	LOGDATEFORMATKey = "LOG_DATEFORMAT"
	LOGENCODINGKey = "LOG_ENCODING"
	LOGFORMATKey = "LOG_FORMAT"
	LOGLEVELKey = "LOG_LEVEL"
	MAXDEPTHKey = "MAX_DEPTH"
	MAXDEPTHPRECEDENCEKey = "MAX_DEPTH_PRECEDENCE"
	MAXREQUESTSIZEKey = "MAX_REQUEST_SIZE"
	MEMUSAGECHECKINTERVALKey = "MEMUSAGE_CHECK_INTERVAL"
	MEMUSAGEENABLEDKey = "MEMUSAGE_ENABLED"
	MEMUSAGELIMITMBKey = "MEMUSAGE_LIMIT_MB"
	REDIRECTENABLEDKey = "REDIRECT_ENABLED"
	REDIRECTMAXMETAREFRESHDELAYKey = "REDIRECT_MAX_METAREFRESH_DELAY"
	REDIRECTMAXTIMESKey = "REDIRECT_MAX_TIMES"
	REQUESTFINGERPRINTERIMPLEMENTATIONKey = "REQUEST_FINGERPRINTER_IMPLEMENTATION"
	RETRYENABLEDKey = "RETRY_ENABLED"
	RETRYHTTPCODESKey = "RETRY_HTTP_CODES"
	RETRYTIMESKey = "RETRY_TIMES"
	ROBOTSTXTOBEYKey = "ROBOTSTXT_OBEY"
	SCHEDULERDISKQUEUEKey = "SCHEDULER_DISK_QUEUE"
	SCHEDULERMEMORYQUEUEKey = "SCHEDULER_MEMORY_QUEUE"
	SCHEDULERPRIORITIESREVERSEKey = "SCHEDULER_PRIORITIES_REVERSE"
	SCHEDULERPRIORITYQUEUEKey = "SCHEDULER_PRIORITY_QUEUE"
	TELNETCONSOLEENABLEDKey = "TELNET_CONSOLE_ENABLED"
	TWISTEDREACTORKey = "TWISTED_REACTOR"
	USERAGENTKey = "USER_AGENT"
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
	s.data[ENGINEKey] = "native"
	s.data[CONCURRENTREQUESTSKey] = 16
	s.data[CONCURRENTREQUESTSPERDOMAINKey] = 8
	s.data[CONCURRENTREQUESTSPERIPKey] = 0
	s.data[DOWNLOADDELAYKey] = 0
	s.data[DOWNLOADTIMEOUTKey] = 180 * time.Second
	s.data[MAXDEPTHKey] = 0
	s.data[MAXDEPTHPRECEDENCEKey] = true
	s.data[MAXREQUESTSIZEKey] = 0
	s.data[RETRYENABLEDKey] = true
	s.data[RETRYTIMESKey] = 2
	s.data[RETRYHTTPCODESKey] = []int{500, 502, 503, 504, 408, 429}
	s.data[ROBOTSTXTOBEYKey] = true
	s.data[USERAGENTKey] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	s.data[DEFAULTHEADERSKey] = map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.5",
		"Accept-Encoding":           "gzip, deflate",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
	}
	s.data[COOKIESENABLEDKey] = true
	s.data[TELNETCONSOLEENABLEDKey] = false
	s.data[DEFAULTINPUTENCODINGKey] = "utf-8"
	s.data[FEEDEXPORTENCODINGKey] = "utf-8"
	s.data[LOGLEVELKey] = "INFO"
	s.data[LOGENCODINGKey] = "utf-8"
	s.data[LOGFORMATKey] = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
	s.data[LOGDATEFORMATKey] = "%Y-%m-%d %H:%M:%S"
	s.data[REDIRECTENABLEDKey] = true
	s.data[REDIRECTMAXTIMESKey] = 20
	s.data[REDIRECTMAXMETAREFRESHDELAYKey] = 10 * time.Second
	s.data[COOKIESDEBUGKey] = false
	s.data[DOWNLOADMAXFAILURESKey] = 5
	s.data[DOWNLOADFAILUREWAITKey] = 10 * time.Second
	s.data[AUTOTHROTTLEENABLEDKey] = false
	s.data[AUTOTHROTTLESTARTDELAYKey] = 1 * time.Second
	s.data[AUTOTHROTTLEMAXDELAYKey] = 60 * time.Second
	s.data[AUTOTHROTTLETARGETCONCURRENCYKey] = 1.0
	s.data[AUTOTHROTTLEDEBUGKey] = false
	s.data[HTTPCACHEENABLEDKey] = false
	s.data[MEMUSAGEENABLEDKey] = true
	s.data[MEMUSAGELIMITMBKey] = 0
	s.data[MEMUSAGECHECKINTERVALKey] = 1 * time.Minute
	s.data[CLOSESPIDERTIMEOUTKey] = 0
	s.data[CLOSESPIDERITEMCOUNTKey] = 0
	s.data[CLOSESPIDERPAGECOUNTKey] = 0
	s.data[CLOSESPIDERERRORCOUNTKey] = 0
	s.data[SCHEDULERPRIORITYQUEUEKey] = "scrapy.pqueues.ScrapyPriorityQueue"
	s.data[SCHEDULERDISKQUEUEKey] = "scrapy.pqueues.ScrapyDiskQueue"
	s.data[SCHEDULERMEMORYQUEUEKey] = "scrapy.pqueues.ScrapyMemoryQueue"
	s.data[SCHEDULERPRIORITIESREVERSEKey] = true
	s.data[REQUESTFINGERPRINTERIMPLEMENTATIONKey] = "2.7"
	s.data[TWISTEDREACTORKey] = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
	s.data[FEEDFORMATKey] = "jsonlines"
	s.data[FEEDURIKey] = ""
	s.data[FEEDEXPORTBATCHITEMCOUNTKey] = 100
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
