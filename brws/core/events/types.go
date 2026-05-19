package events

type CrawlerStarted struct {
	Crawler any
}

type CrawlerStopped struct {
	Crawler any
}

type SpiderOpened struct {
	Spider any
}

type SpiderClosed struct {
	Spider any
}

type SpiderError struct {
	Spider any
	Error  error
}

type SpiderIdle struct {
	Spider any
}

type RequestScheduled struct {
	Request any
}

type RequestDropped struct {
	Request any
	Reason  error
}

type RequestError struct {
	Request any
	Error   error
}

type ResponseReceived struct {
	Request  any
	Response any
}

type ResponseDownloaded struct {
	Request  any
	Response any
}

type ItemScraped struct {
	Item any
}

type ItemDropped struct {
	Item   any
	Reason error
}

type ItemError struct {
	Item  any
	Error error
}

type EngineStarted struct{}

type EngineStopped struct{}

type Stats struct {
	StartTime    int64
	ItemsCount   int64
	RequestCount int64
	ErrorCount   int64
}
