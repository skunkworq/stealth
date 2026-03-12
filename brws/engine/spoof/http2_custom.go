// Package spoof provides custom HTTP/2 transport for browser impersonation
package spoof

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// CustomHTTP2Transport provides fine-grained HTTP/2 control for impersonation
type CustomHTTP2Transport struct {
	// Settings frame configuration
	Settings []http2.Setting

	// Flow control window sizes
	InitialStreamWindowSize uint32
	InitialConnWindowSize   uint32

	// Header ordering
	PseudoHeaderOrder []string
	HeaderOrder       []string

	// PRIORITY frame configuration (P9.2)
	// Chrome sends PRIORITY on initial stream: weight=256, exclusive=true, depends=0
	PriorityWeight    uint8
	PriorityExclusive bool
	PriorityDependsOn uint32
	SendPriority      bool // whether to emit PRIORITY frames

	// Internal state
	conn     net.Conn
	framer   *http2.Framer
	mu       sync.Mutex
	streamID uint32
}

// ChromeHTTP2Transport returns HTTP/2 config matching Chrome
func ChromeHTTP2Transport() *CustomHTTP2Transport {
	return &CustomHTTP2Transport{
		// Chrome sends SETTINGS in this order with these values
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0}, // Disabled
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456}, // 6MB
			{ID: http2.SettingMaxFrameSize, Val: 16384},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		},
		InitialStreamWindowSize: 6291456,
		InitialConnWindowSize:   6291456,

		// Chrome's pseudo-header order
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},

		// Chrome's regular header order
		HeaderOrder: []string{
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
		},

		// Chrome sends PRIORITY: weight=256, exclusive, depends on stream 0
		PriorityWeight:    255, // http2 wire weight is 0-255, maps to 1-256
		PriorityExclusive: true,
		PriorityDependsOn: 0,
		SendPriority:      true,
	}
}

// FirefoxHTTP2Transport returns HTTP/2 config matching Firefox
func FirefoxHTTP2Transport() *CustomHTTP2Transport {
	return &CustomHTTP2Transport{
		// Firefox sends fewer settings
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 131072},
			{ID: http2.SettingInitialWindowSize, Val: 131072}, // 128KB
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		},
		InitialStreamWindowSize: 131072,
		InitialConnWindowSize:   12517377, // Firefox uses different values

		// Firefox's pseudo-header order
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},

		// Firefox's regular header order
		HeaderOrder: []string{
			"user-agent",
			"accept",
			"accept-language",
			"accept-encoding",
			"upgrade-insecure-requests",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-fetch-user",
			"te",
		},

		// Firefox uses urgency-based priority (RFC 9218), not PRIORITY frames
		SendPriority: false,
	}
}

// Dial establishes HTTP/2 connection with custom handshake
func (t *CustomHTTP2Transport) Dial(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp dial: %w", err)
	}

	t.conn = conn
	t.framer = http2.NewFramer(conn, conn)

	// Send HTTP/2 preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("writing preface: %w", err)
	}

	// Send SETTINGS frame with custom order/values
	if err := t.framer.WriteSettings(t.Settings...); err != nil {
		_ = conn.Close()
		return fmt.Errorf("writing settings: %w", err)
	}

	// Send WINDOW_UPDATE for connection-level flow control
	if t.InitialConnWindowSize > 0 {
		// Initial window is 65535, we need to send increment
		increment := t.InitialConnWindowSize - 65535
		if increment > 0 {
			if err := t.framer.WriteWindowUpdate(0, increment); err != nil {
				_ = conn.Close()
				return fmt.Errorf("writing window update: %w", err)
			}
		}
	}

	// Read server's SETTINGS frame
	frame, err := t.framer.ReadFrame()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("reading server settings: %w", err)
	}

	if _, ok := frame.(*http2.SettingsFrame); !ok {
		_ = conn.Close()
		return fmt.Errorf("expected settings frame, got %T", frame)
	}

	// Send SETTINGS ACK
	if err := t.framer.WriteSettingsAck(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("writing settings ack: %w", err)
	}

	return nil
}

// SendRequest sends an HTTP/2 request with custom header ordering
func (t *CustomHTTP2Transport) SendRequest(
	method, authority, scheme, path string,
	headers map[string]string,
	body []byte,
) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get next stream ID (odd numbers for client-initiated)
	t.streamID += 2
	streamID := t.streamID

	// Encode headers with custom ordering
	headerBlock, err := t.encodeHeaders(method, authority, scheme, path, headers)
	if err != nil {
		return nil, fmt.Errorf("encoding headers: %w", err)
	}

	// Send HEADERS frame
	endStream := len(body) == 0

	// Chrome sends PRIORITY in the HEADERS frame via the Priority field
	headersParam := http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndStream:     endStream,
		EndHeaders:    true,
	}

	// Attach PRIORITY data to the HEADERS frame if configured (P9.2)
	if t.SendPriority {
		headersParam.Priority = http2.PriorityParam{
			StreamDep: t.PriorityDependsOn,
			Exclusive: t.PriorityExclusive,
			Weight:    t.PriorityWeight,
		}
	}

	if err := t.framer.WriteHeaders(headersParam); err != nil {
		return nil, fmt.Errorf("writing headers: %w", err)
	}

	// Send body if present
	if len(body) > 0 {
		if err := t.framer.WriteData(streamID, true, body); err != nil {
			return nil, fmt.Errorf("writing body: %w", err)
		}
	}

	// Read response. Stream WINDOW_UPDATE is sent after first DATA frame (P9.3),
	// matching Chrome's behavior of deferring flow control until data arrives.
	return t.readResponse(streamID)
}

// encodeHeaders encodes headers with browser-specific ordering
func (t *CustomHTTP2Transport) encodeHeaders(
	method, authority, scheme, path string,
	headers map[string]string,
) ([]byte, error) {
	var buf bytes.Buffer

	encoder := hpack.NewEncoder(&buf)

	// Encode pseudo-headers in specific order
	for _, pseudo := range t.PseudoHeaderOrder {
		switch pseudo {
		case ":method":
			if err := encoder.WriteField(hpack.HeaderField{
				Name: ":method", Value: method, Sensitive: false,
			}); err != nil {
				return nil, err
			}
		case ":authority":
			if err := encoder.WriteField(hpack.HeaderField{
				Name: ":authority", Value: authority, Sensitive: false,
			}); err != nil {
				return nil, err
			}
		case ":scheme":
			if err := encoder.WriteField(hpack.HeaderField{
				Name: ":scheme", Value: scheme, Sensitive: false,
			}); err != nil {
				return nil, err
			}
		case ":path":
			if err := encoder.WriteField(hpack.HeaderField{
				Name: ":path", Value: path, Sensitive: false,
			}); err != nil {
				return nil, err
			}
		}
	}

	// Encode regular headers in specific order
	for _, name := range t.HeaderOrder {
		if value, ok := headers[name]; ok {
			if err := encoder.WriteField(hpack.HeaderField{
				Name:      strings.ToLower(name),
				Value:     value,
				Sensitive: false,
			}); err != nil {
				return nil, err
			}
		}
	}

	// Add any remaining headers not in the order
	for name, value := range headers {
		lowerName := strings.ToLower(name)
		if !strings.HasPrefix(lowerName, ":") && !inStringSlice(name, t.HeaderOrder) {
			if err := encoder.WriteField(hpack.HeaderField{
				Name:      lowerName,
				Value:     value,
				Sensitive: false,
			}); err != nil {
				return nil, err
			}
		}
	}

	return buf.Bytes(), nil
}

// readResponse reads HTTP/2 response, assembling multi-frame bodies.
// Sends a stream-level WINDOW_UPDATE after the first DATA frame to match
// Chrome's deferred flow control behavior (P9.3).
func (t *CustomHTTP2Transport) readResponse(streamID uint32) (*http.Response, error) {
	var headers http.Header
	var statusCode int
	var bodyBuf bytes.Buffer
	sentStreamWindowUpdate := false

	for {
		frame, err := t.framer.ReadFrame()
		if err != nil {
			return nil, err
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if f.StreamID != streamID {
				continue
			}

			// Decode headers
			headers, statusCode, err = t.decodeHeaders(f.HeaderBlockFragment())
			if err != nil {
				return nil, err
			}

			if f.StreamEnded() {
				return &http.Response{
					StatusCode: statusCode,
					Header:     headers,
					Proto:      "HTTP/2.0",
					ProtoMajor: 2,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}

		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}

			// P9.3: Send stream WINDOW_UPDATE after first DATA frame (Chrome behavior).
			// Real browsers defer this until data arrives, not at connection setup.
			if !sentStreamWindowUpdate && t.InitialStreamWindowSize > 0 {
				increment := t.InitialStreamWindowSize - 65535
				if increment > 0 {
					_ = t.framer.WriteWindowUpdate(streamID, increment)
				}
				sentStreamWindowUpdate = true
			}

			// Accumulate body data across frames
			bodyBuf.Write(f.Data())

			if f.StreamEnded() {
				return &http.Response{
					StatusCode: statusCode,
					Header:     headers,
					Proto:      "HTTP/2.0",
					ProtoMajor: 2,
					Body:       io.NopCloser(bytes.NewReader(bodyBuf.Bytes())),
				}, nil
			}

		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return nil, fmt.Errorf("stream reset: %d", f.ErrCode)
			}

		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("server sent GOAWAY: %d", f.ErrCode)

		case *http2.WindowUpdateFrame:
			// Server flow control — acknowledge and continue
			continue

		case *http2.SettingsFrame:
			// Server settings update — ACK if not already acked
			if !f.IsAck() {
				_ = t.framer.WriteSettingsAck()
			}
		}
	}
}

// decodeHeaders decodes HPACK header block
func (t *CustomHTTP2Transport) decodeHeaders(block []byte) (http.Header, int, error) {
	header := make(http.Header)

	var statusCode int

	// HPACK decoder
	decoder := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			_, _ = fmt.Sscanf(f.Value, "%d", &statusCode)
		} else if !strings.HasPrefix(f.Name, ":") {
			header.Add(f.Name, f.Value)
		}
	})

	if _, err := decoder.Write(block); err != nil {
		return nil, 0, err
	}

	return header, statusCode, nil
}

// Close closes the HTTP/2 connection
func (t *CustomHTTP2Transport) Close() error {
	if t.conn != nil {
		// Send GOAWAY frame
		_ = t.framer.WriteGoAway(0, http2.ErrCodeNo, nil)
		return t.conn.Close()
	}
	return nil
}

// Helper functions
func inStringSlice(s string, slice []string) bool {
	for _, item := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
