package cloudflare

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/core/detection"
	"github.com/skunkworq/stealth/brws/core/types"
)

// TestServer is a test server for adversarial detection testing
type TestServer struct {
	Server     *httptest.Server
	URL        string
	Detections []DetectionRecord
	mu         sync.RWMutex
	TLSConfig  *tls.Config
	UseTLS     bool
	ServerCert *tls.Certificate
}

// DetectionRecord represents a single detection event recorded by the test server
type DetectionRecord struct {
	Timestamp     time.Time      `json:"timestamp"`
	RequestID     string         `json:"request_id"`
	IsBot         bool           `json:"is_bot"`
	Score         float64        `json:"score"`
	Indicators    []detection.Indicator    `json:"indicators"`
	TLS           *detection.TLSAnalysis   `json:"tls,omitempty"`
	HTTP          *detection.HTTPAnalysis  `json:"http,omitempty"`
	VectorResults []detection.VectorResult `json:"vector_results,omitempty"`
	Request       *RequestInfo   `json:"request,omitempty"`
	Response      *ResponseInfo  `json:"response,omitempty"`
}

// RequestInfo contains details about an HTTP request received by the test server
type RequestInfo struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Headers     map[string]string `json:"headers"`
	HeaderOrder []string          `json:"header_order"`
	RemoteAddr  string            `json:"remote_addr"`
	TLS         *TLSInfo          `json:"tls,omitempty"`
}

// TLSInfo contains TLS connection details from the client
type TLSInfo struct {
	Version         string   `json:"version"`
	CipherSuite     string   `json:"cipher_suite"`
	ServerName      string   `json:"server_name"`
	SupportedGroups []string `json:"supported_groups"`
	SignatureAlgs   []string `json:"signature_algs"`
	ALPN            string   `json:"alpn"`
}

// ResponseInfo contains details about the HTTP response sent by the test server
type ResponseInfo struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	BodyLength int               `json:"body_length"`
	TTFB       int               `json:"ttfb"`
}

// NewTestServer creates a new test server for adversarial detection testing
func NewTestServer() *TestServer {
	ts := &TestServer{
		Detections: make([]DetectionRecord, 0),
	}

	handler := http.HandlerFunc(ts.handleRequest)
	ts.Server = httptest.NewServer(handler)
	ts.URL = ts.Server.URL

	return ts
}

func (ts *TestServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	record := DetectionRecord{
		Timestamp: time.Now(),
		RequestID: generateRequestID(),
		Request: &RequestInfo{
			Method:      r.Method,
			URL:         r.URL.String(),
			Host:        r.Host,
			Headers:     make(map[string]string),
			HeaderOrder: make([]string, 0),
			RemoteAddr:  r.RemoteAddr,
		},
		Response: &ResponseInfo{
			StatusCode: 200,
			Headers:    make(map[string]string),
			BodyLength: 0,
		},
	}

	for key, values := range r.Header {
		if len(values) > 0 {
			record.Request.Headers[key] = values[0]
			record.Request.HeaderOrder = append(record.Request.HeaderOrder, key)
		}
	}

	detector := detection.NewAnalyzer()
	vm := detection.NewVectorMap()

	httpResult := vm.AnalyzeHTTP(r)
	record.VectorResults = append(record.VectorResults, *httpResult)

	_, headersScore := detector.DetectFromHeaders(r.Header)
	record.Score = headersScore

	if r.TLS != nil {
		record.Request.TLS = &TLSInfo{
			Version:     fmt.Sprintf("0x%04x", r.TLS.Version),
			CipherSuite: fmt.Sprintf("0x%04x", r.TLS.CipherSuite),
			ServerName:  r.TLS.ServerName,
		}

		tlsAnalysis := &detection.TLSAnalysis{
			Version: record.Request.TLS.Version,
			SNI:     r.TLS.ServerName,
		}
		record.TLS = tlsAnalysis
	}

	totalScore := record.Score
	for _, vr := range record.VectorResults {
		totalScore += vr.Score
	}
	if len(record.VectorResults) > 0 {
		record.Score = totalScore / float64(len(record.VectorResults)+1)
	}

	record.IsBot = record.Score > 0.3

	if record.IsBot {
		record.Indicators = append(record.Indicators, detection.Indicator{
			Category: "http",
			Name:     "bot_detection",
			Severity: record.Score,
			Message:  fmt.Sprintf("Bot detected with score %.2f", record.Score),
		})

		for _, vr := range record.VectorResults {
			for _, ind := range vr.Indicators {
				record.Indicators = append(record.Indicators, detection.Indicator{
					Category: string(vr.Category),
					Name:     ind.Check,
					Severity: ind.Weight,
					Message:  ind.Message,
				})
			}
		}
	}

	record.Response.TTFB = int(time.Since(startTime).Milliseconds())

	ts.mu.Lock()
	ts.Detections = append(ts.Detections, record)
	ts.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Detection-Score", fmt.Sprintf("%.2f", record.Score))
	w.Header().Set("X-Is-Bot", fmt.Sprintf("%v", record.IsBot))

	response := map[string]interface{}{
		"request_id":     record.RequestID,
		"is_bot":         record.IsBot,
		"score":          record.Score,
		"indicators":     record.Indicators,
		"headers":        record.Request.Headers,
		"vector_results": record.VectorResults,
	}

	if record.IsBot {
		response["detection_details"] = map[string]interface{}{
			"reason":  "Fingerprint analysis detected bot-like patterns",
			"vectors": record.VectorResults,
		}
	}

	jsonResp, err := json.Marshal(response)
	if err != nil {
		http.Error(w, `{"error": "marshal failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jsonResp)
}

// GetDetections returns all detection records collected by the test server
func (ts *TestServer) GetDetections() []DetectionRecord {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.Detections
}

// GetLastDetection returns the most recent detection record, or nil if none exist
func (ts *TestServer) GetLastDetection() *DetectionRecord {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	if len(ts.Detections) == 0 {
		return nil
	}
	return &ts.Detections[len(ts.Detections)-1]
}

// ClearDetections removes all detection records from the test server
func (ts *TestServer) ClearDetections() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Detections = make([]DetectionRecord, 0)
}

// Close shuts down the test server
func (ts *TestServer) Close() {
	ts.Server.Close()
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// FingerprintTestServer is a specialized test server for fingerprint-based detection
type FingerprintTestServer struct {
	Listener   net.Listener
	Server     *http.Server
	URL        string
	Detections []FingerprintDetection
	mu         sync.RWMutex
	TLSEnabled bool
}

// FingerprintDetection represents a detection based on fingerprint analysis
type FingerprintDetection struct {
	Timestamp    time.Time     `json:"timestamp"`
	ConnectionID string        `json:"connection_id"`
	TLSHandshake *TLSHandshake `json:"tls_handshake,omitempty"`
	HTTPRequest  *HTTPRequest  `json:"http_request,omitempty"`
	Analysis     *Analysis     `json:"analysis"`
	ShouldBlock  bool          `json:"should_block"`
	BlockReason  string        `json:"block_reason,omitempty"`
}

// TLSHandshake contains details about a TLS handshake
type TLSHandshake struct {
	ClientHello     *ClientHelloInfo `json:"client_hello"`
	JA4             string           `json:"ja4"`
	JA3             string           `json:"ja3"`
	CipherSuites    []string         `json:"cipher_suites"`
	Extensions      []string         `json:"extensions"`
	SupportedGroups []string         `json:"supported_groups"`
	SignatureAlgs   []string         `json:"signature_algs"`
	ALPN            string           `json:"alpn"`
	ServerName      string           `json:"server_name"`
	Version         string           `json:"version"`
	HasGREASE       bool             `json:"has_grease"`
	HasALPS         bool             `json:"has_alps"`
}

// ClientHelloInfo contains details from the TLS Client Hello message
type ClientHelloInfo struct {
	CipherSuites      []uint16 `json:"cipher_suites"`
	ServerName        string   `json:"server_name"`
	SupportedCurves   []uint16 `json:"supported_curves"`
	SupportedPoints   []uint8  `json:"supported_points"`
	SignatureSchemes  []uint16 `json:"signature_schemes"`
	SupportedProtos   []string `json:"supported_protos"`
	SupportedVersions []uint16 `json:"supported_versions"`
	Conn              net.Conn `json:"conn"`
}

// HTTPRequest contains HTTP request information for fingerprint analysis
type HTTPRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	HTTPVersion string            `json:"http_version"`
	Headers     map[string]string `json:"headers"`
	HeaderOrder []string          `json:"header_order"`
	RemoteAddr  string            `json:"remote_addr"`
	TLSVersion  uint16            `json:"tls_version"`
	CipherSuite uint16            `json:"cipher_suite"`
}

// Analysis contains the results of fingerprint analysis
type Analysis struct {
	BotScore      float64        `json:"bot_score"`
	IsBot         bool           `json:"is_bot"`
	Confidence    float64        `json:"confidence"`
	VectorResults []detection.VectorResult `json:"vector_results"`
	Indicators    []detection.Indicator    `json:"indicators"`
	Anomalies     []string       `json:"anomalies"`
}

// NewFingerprintTestServer creates a new fingerprint test server
func NewFingerprintTestServer() (*FingerprintTestServer, error) {
	fts := &FingerprintTestServer{
		Detections: make([]FingerprintDetection, 0),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", fts.handleRequest)

	fts.Server = &http.Server{
		Addr:         "127.0.0.1:0",
		Handler:      mux,
		ReadTimeout:  constants.DefaultReadTimeout,
		WriteTimeout: constants.DefaultWriteTimeout,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	fts.Listener = ln
	fts.URL = "http://" + ln.Addr().String()

	go func() { _ = fts.Server.Serve(ln) }()

	return fts, nil
}

func (fts *FingerprintTestServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	fp := FingerprintDetection{
		Timestamp:    time.Now(),
		ConnectionID: generateRequestID(),
		Analysis:     &Analysis{},
	}

	fp.HTTPRequest = &HTTPRequest{
		Method:      r.Method,
		URL:         r.URL.String(),
		HTTPVersion: r.Proto,
		Headers:     make(map[string]string),
		HeaderOrder: make([]string, 0),
		RemoteAddr:  r.RemoteAddr,
	}

	for key, values := range r.Header {
		if len(values) > 0 {
			fp.HTTPRequest.Headers[key] = values[0]
			fp.HTTPRequest.HeaderOrder = append(fp.HTTPRequest.HeaderOrder, key)
		}
	}

	if r.TLS != nil {
		fp.HTTPRequest.TLSVersion = r.TLS.Version
		fp.HTTPRequest.CipherSuite = r.TLS.CipherSuite
	}

	vm := detection.NewVectorMap()

	httpResult := vm.AnalyzeHTTP(r)
	fp.Analysis.VectorResults = append(fp.Analysis.VectorResults, *httpResult)

	detector := detection.NewAnalyzer()
	isBot, score := detector.DetectFromHeaders(r.Header)
	fp.Analysis.BotScore = score
	fp.Analysis.IsBot = isBot

	for _, vr := range fp.Analysis.VectorResults {
		for _, ind := range vr.Indicators {
			fp.Analysis.Indicators = append(fp.Analysis.Indicators, detection.Indicator{
				Category: string(vr.Category),
				Name:     ind.Check,
				Severity: ind.Weight,
				Message:  ind.Message,
			})
		}
	}

	if isBot {
		fp.ShouldBlock = true
		fp.BlockReason = fmt.Sprintf("Bot detected with score %.2f", score)
		fp.Analysis.Anomalies = append(fp.Analysis.Anomalies, fp.BlockReason)

		for _, vr := range fp.Analysis.VectorResults {
			for _, ind := range vr.Indicators {
				fp.Analysis.Anomalies = append(fp.Analysis.Anomalies, ind.Message)
			}
		}
	}

	fp.Analysis.Confidence = fp.Analysis.BotScore

	fts.mu.Lock()
	fts.Detections = append(fts.Detections, fp)
	fts.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Bot-Score", fmt.Sprintf("%.2f", fp.Analysis.BotScore))
	w.Header().Set("X-Is-Bot", fmt.Sprintf("%v", fp.Analysis.IsBot))

	response := map[string]interface{}{
		"connection_id": fp.ConnectionID,
		"is_bot":        fp.Analysis.IsBot,
		"bot_score":     fp.Analysis.BotScore,
		"confidence":    fp.Analysis.Confidence,
		"should_block":  fp.ShouldBlock,
		"headers":       fp.HTTPRequest.Headers,
		"vectors":       fp.Analysis.VectorResults,
	}

	if fp.ShouldBlock {
		response["block_reason"] = fp.BlockReason
		response["anomalies"] = fp.Analysis.Anomalies
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// GetDetections returns all fingerprint detections collected by the server
func (fts *FingerprintTestServer) GetDetections() []FingerprintDetection {
	fts.mu.RLock()
	defer fts.mu.RUnlock()
	return fts.Detections
}

// GetLastDetection returns the most recent fingerprint detection, or nil if none exist
func (fts *FingerprintTestServer) GetLastDetection() *FingerprintDetection {
	fts.mu.RLock()
	defer fts.mu.RUnlock()
	if len(fts.Detections) == 0 {
		return nil
	}
	return &fts.Detections[len(fts.Detections)-1]
}

// Close shuts down the fingerprint test server gracefully
func (fts *FingerprintTestServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return fts.Server.Shutdown(ctx)
}

// RunFingerprintTest runs a single fingerprint test against the specified URL
func RunFingerprintTest(client *http.Client, url string) (*Analysis, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req) //nolint:gosec // SSRF protection is caller's responsibility
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	analysis := &Analysis{
		BotScore:   0,
		IsBot:      false,
		Confidence: 0,
	}

	if scoreHeader := resp.Header.Get("X-Bot-Score"); scoreHeader != "" {
		_, _ = fmt.Sscanf(scoreHeader, "%f", &analysis.BotScore)
	}
	if isBotHeader := resp.Header.Get("X-Is-Bot"); isBotHeader != "" {
		analysis.IsBot = isBotHeader == "true"
	}

	_ = body // body read but not used for analysis
	analysis.Confidence = analysis.BotScore

	return analysis, nil
}

// TestResult represents the outcome of a single fingerprint test
type TestResult struct {
	TestName        string
	Passed          bool
	IsBot           bool
	Score           float64
	Detected        bool
	Indicators      []detection.Indicator
	VectorResults   []detection.VectorResult
	Error           error
	RequestHeaders  http.Header
	ResponseHeaders http.Header
}

// RunTestSuite runs a suite of fingerprint tests and returns the results
func RunTestSuite(tests []struct {
	Name    string
	Request func(*http.Request)
},
) []TestResult {
	results := make([]TestResult, 0)

	server := NewTestServer()
	defer server.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // InsecureSkipVerify required for test client
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	for _, test := range tests {
		server.ClearDetections()

		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			results = append(results, TestResult{
				TestName: test.Name,
				Passed:   false,
				Error:    err,
			})
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")

		if test.Request != nil {
			test.Request(req)
		}

		resp, err := client.Do(req) //nolint:gosec // SSRF protection is caller's responsibility
		if err != nil {
			results = append(results, TestResult{
				TestName: test.Name,
				Passed:   false,
				Error:    err,
			})
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		detection := server.GetLastDetection()

		result := TestResult{
			TestName:        test.Name,
			Passed:          !detection.IsBot,
			IsBot:           detection.IsBot,
			Score:           detection.Score,
			Detected:        detection.IsBot,
			Indicators:      detection.Indicators,
			VectorResults:   detection.VectorResults,
			RequestHeaders:  req.Header,
			ResponseHeaders: resp.Header,
		}
		results = append(results, result)
	}

	return results
}

// PrintTestResults outputs test results in a formatted manner
func PrintTestResults(results []TestResult) {
	_, _ = fmt.Fprintln(os.Stdout, "\n=== Fingerprint Test Results ===")

	passed := 0
	failed := 0

	for _, r := range results {
		status := "PASS"
		if r.Detected {
			status = "FAIL"
			failed++
		} else {
			passed++
		}

		_, _ = fmt.Fprintf(os.Stdout, "[%s] %s\n", status, r.TestName)
		_, _ = fmt.Fprintf(os.Stdout, "      Score: %.2f | Detected: %v\n", r.Score, r.Detected)

		if len(r.VectorResults) > 0 {
			_, _ = fmt.Fprintln(os.Stdout, "      Vectors:")
			for _, vr := range r.VectorResults {
				if vr.Detected {
					_, _ = fmt.Fprintf(os.Stdout, "        - %s: %.2f\n", vr.Vector, vr.Score)
					for _, ind := range vr.Indicators {
						_, _ = fmt.Fprintf(os.Stdout, "            * %s\n", ind.Message)
					}
				}
			}
		}
		_, _ = fmt.Fprintln(os.Stdout)
	}

	_, _ = fmt.Fprintf(os.Stdout, "Summary: %d passed, %d failed\n", passed, failed)
}

// AnalyzeFingerprint performs analysis on a complete fingerprint
func AnalyzeFingerprint(fp *types.CompleteFingerprint) *Analysis {
	analysis := &Analysis{
		BotScore:      0,
		IsBot:         false,
		Confidence:    0,
		VectorResults: make([]detection.VectorResult, 0),
		Indicators:    make([]detection.Indicator, 0),
		Anomalies:     make([]string, 0),
	}

	vm := detection.NewVectorMap()

	results := vm.AnalyzeComplete(fp)
	analysis.VectorResults = results

	var totalScore float64
	for _, vr := range results {
		totalScore += vr.Score

		if vr.Detected {
			analysis.Anomalies = append(analysis.Anomalies, fmt.Sprintf("%s vector detected", vr.Vector))
			for _, ind := range vr.Indicators {
				analysis.Indicators = append(analysis.Indicators, detection.Indicator{
					Category: string(vr.Category),
					Name:     ind.Check,
					Severity: ind.Weight,
					Message:  ind.Message,
				})
				analysis.Anomalies = append(analysis.Anomalies, ind.Message)
			}
		}
	}

	if len(results) > 0 {
		analysis.BotScore = totalScore / float64(len(results))
	}

	analysis.IsBot = analysis.BotScore > 0.3
	analysis.Confidence = analysis.BotScore

	return analysis
}

// ExpectHuman evaluates headers and returns whether they appear to be from a human user
func ExpectHuman(headers http.Header) (bool, float64, []string) {
	vm := detection.NewVectorMap()

	req := &http.Request{
		Header: headers,
	}

	httpResult := vm.AnalyzeHTTP(req)

	detector := detection.NewAnalyzer()
	isBot, score := detector.DetectFromHeaders(headers)

	anomalies := make([]string, 0)
	for _, ind := range httpResult.Indicators {
		anomalies = append(anomalies, ind.Message)
	}

	totalScore := (score + httpResult.Score) / 2

	return !isBot && !httpResult.Detected, totalScore, anomalies
}
