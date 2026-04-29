// Package lab provides raw packet capture capabilities for complete fingerprint extraction
package lab

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/fingerprint/tls/parser"
)

// RawCaptureListener wraps a net.Listener to capture raw TLS handshakes
type RawCaptureListener struct {
	net.Listener

	OnClientHello func(*ClientHello, []byte)
}

// Accept wraps accept to intercept connections
func (l *RawCaptureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &rawCaptureConn{
		Conn:          conn,
		onClientHello: l.OnClientHello,
	}, nil
}

// rawCaptureConn wraps a connection to capture TLS ClientHello
type rawCaptureConn struct {
	net.Conn

	onClientHello     func(*ClientHello, []byte)
	mu                sync.Mutex
	buffer            []byte
	parsed            bool
	handshakeCaptured bool
}

// Read intercepts reads to capture ClientHello
func (c *rawCaptureConn) Read(p []byte) (n int, err error) {
	// Normal read
	n, err = c.Conn.Read(p)

	// Capture if we haven't already
	if n > 0 && !c.parsed {
		c.mu.Lock()
		c.buffer = append(c.buffer, p[:n]...)

		// Try to parse ClientHello
		if len(c.buffer) >= 5 && !c.handshakeCaptured {
			// Check for TLS handshake record
			if c.buffer[0] == 0x16 { // Handshake content type
				recordLen := int(c.buffer[3])<<8 | int(c.buffer[4])
				if len(c.buffer) >= 5+recordLen {
					// We have a complete record
					ch, err := ParseClientHello(c.buffer)
					if err == nil && c.onClientHello != nil {
						c.handshakeCaptured = true
						c.onClientHello(ch, c.buffer[:5+recordLen])
					}
					c.parsed = true
				}
			}
		}
		c.mu.Unlock()
	}

	return n, err
}

// RawCaptureServer provides complete TLS fingerprint capture
type RawCaptureServer struct {
	config    *ServerConfig
	listener  net.Listener
	tlsConfig *tls.Config

	// Callbacks
	OnFingerprint func(*CompleteFingerprint)

	// Storage
	mu                sync.RWMutex
	fingerprints      map[string]*CompleteFingerprint
	latestClientHello *ClientHello
}

// NewRawCaptureServer creates a server with raw capture capability
func NewRawCaptureServer(config *ServerConfig) *RawCaptureServer {
	return &RawCaptureServer{
		config:       config,
		fingerprints: make(map[string]*CompleteFingerprint),
	}
}

// Start begins serving with raw capture
func (s *RawCaptureServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.HTTPSPort)

	// Create base listener
	baseListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Wrap with capture capability
	s.listener = &RawCaptureListener{
		Listener: baseListener,
		OnClientHello: func(ch *ClientHello, raw []byte) {
			s.mu.Lock()
			s.latestClientHello = ch
			s.mu.Unlock()
		},
	}

	// Create TLS config
	s.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return s.handleClientHello(hello)
		},
	}

	return nil
}

// handleClientHello processes TLS ClientHello
func (s *RawCaptureServer) handleClientHello(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	s.mu.RLock()
	ch := s.latestClientHello
	s.mu.RUnlock()

	if ch != nil {
		// Build complete fingerprint
		fp := &CompleteFingerprint{
			ID:        generateID(),
			Timestamp: time.Now(),
			SourceIP:  hello.Conn.RemoteAddr().String(),
		}

		// Convert to our format
		fp.TLS = ch.ToFingerprint()

		// Store
		s.mu.Lock()
		s.fingerprints[fp.ID] = fp
		s.mu.Unlock()

		// Notify
		if s.OnFingerprint != nil {
			s.OnFingerprint(fp)
		}
	}

	// Return default config
	return nil, nil
}

// TLSRecordCapture captures TLS records from a connection
// This can be used to intercept and analyze TLS traffic

type TLSRecordCapture struct {
	conn        net.Conn
	readBuffer  bytes.Buffer
	writeBuffer bytes.Buffer

	OnRecord func(record *TLSRecord, direction string)
	mu       sync.Mutex
}

// NewTLSRecordCapture creates a capturing wrapper
func NewTLSRecordCapture(conn net.Conn, onRecord func(*TLSRecord, string)) *TLSRecordCapture {
	return &TLSRecordCapture{
		conn:     conn,
		OnRecord: onRecord,
	}
}

// Read captures incoming TLS records
func (t *TLSRecordCapture) Read(p []byte) (n int, err error) {
	n, err = t.conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		t.readBuffer.Write(p[:n])
		t.parseRecords("incoming")
		t.mu.Unlock()
	}
	return n, err
}

// Write captures outgoing TLS records
func (t *TLSRecordCapture) Write(p []byte) (n int, err error) {
	n, err = t.conn.Write(p)
	if n > 0 {
		t.mu.Lock()
		t.writeBuffer.Write(p[:n])
		t.parseRecords("outgoing")
		t.mu.Unlock()
	}
	return n, err
}

// parseRecords parses buffered data for TLS records
func (t *TLSRecordCapture) parseRecords(direction string) {
	buf := &t.readBuffer
	if direction == "outgoing" {
		buf = &t.writeBuffer
	}

	data := buf.Bytes()
	offset := 0

	for len(data) >= 5 {
		contentType := data[0]
		version := uint16(data[1])<<8 | uint16(data[2])
		length := uint16(data[3])<<8 | uint16(data[4])

		if len(data) < 5+int(length) {
			// Incomplete record
			break
		}

		record := &TLSRecord{
			ContentType: contentType,
			Version:     version,
			Length:      length,
			Data:        make([]byte, length),
		}
		copy(record.Data, data[5:5+length])

		if t.OnRecord != nil {
			t.OnRecord(record, direction)
		}

		offset = 5 + int(length)
		data = data[offset:]
	}

	// Keep remaining data
	if offset > 0 {
		buf.Next(offset)
	}
}

// Close implements net.Conn
func (t *TLSRecordCapture) Close() error {
	return t.conn.Close()
}

// LocalAddr implements net.Conn
func (t *TLSRecordCapture) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr implements net.Conn
func (t *TLSRecordCapture) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// SetDeadline implements net.Conn
func (t *TLSRecordCapture) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// SetReadDeadline implements net.Conn
func (t *TLSRecordCapture) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline implements net.Conn
func (t *TLSRecordCapture) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// CaptureFromConnection captures a fingerprint from an established connection
func CaptureFromConnection(conn net.Conn) (*CompleteFingerprint, error) {
	fp := &CompleteFingerprint{
		ID:        generateID(),
		Timestamp: time.Now(),
		SourceIP:  conn.RemoteAddr().String(),
	}

	// If it's a TLS connection, extract TLS info
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		state := tlsConn.ConnectionState()
		fp.TLS = &TLSFingerprint{
			Version:     state.Version,
			VersionName: tlsVersionName(state.Version),
			JA3String:   "", // Would need raw capture
			JA3Hash:     "",
		}

		if state.NegotiatedProtocol != "" {
			fp.TLS.ALPN = []string{state.NegotiatedProtocol}
		}
	}

	return fp, nil
}

// AnalyzeClientHello provides detailed analysis
func AnalyzeClientHello(data []byte) (*ClientHelloAnalysis, error) {
	ch, err := ParseClientHello(data)
	if err != nil {
		return nil, err
	}

	analysis := &ClientHelloAnalysis{
		ClientHello:  ch,
		RawHex:       hex.EncodeToString(data),
		BrowserGuess: guessBrowser(ch),
		IsChrome:     isChromeSignature(ch),
		IsFirefox:    isFirefoxSignature(ch),
		IsSafari:     isSafariSignature(ch),
	}

	return analysis, nil
}

// ClientHelloAnalysis contains analysis results
type ClientHelloAnalysis struct {
	ClientHello  *ClientHello
	RawHex       string
	BrowserGuess string
	IsChrome     bool
	IsFirefox    bool
	IsSafari     bool
}

// guessBrowser attempts to identify browser from fingerprint
func guessBrowser(ch *ClientHello) string {
	// Check for Chrome signatures
	if isChromeSignature(ch) {
		return "Chrome/Edge"
	}
	if isFirefoxSignature(ch) {
		return "Firefox"
	}
	if isSafariSignature(ch) {
		return "Safari"
	}
	return "Unknown"
}

// isChromeSignature checks for Chrome-specific TLS signatures
func isChromeSignature(ch *ClientHello) bool {
	// Chrome signatures:
	// - TLS 1.3
	// - Specific extension set including ALPS (0x11)
	// - GREASE extensions
	// - X25519 + P-256 key shares

	if ch.Version != 0x0303 { // TLS 1.2 version in hello (actual version in supported_versions)
		return false
	}

	// Check for ALPS extension (Chrome-specific)
	hasALPS := false
	hasGREASE := false

	for _, ext := range ch.Extensions {
		if ext.Type == 0x0011 { // ALPS
			hasALPS = true
		}
		if tlsparser.IsGREASE(ext.Type) {
			hasGREASE = true
		}
	}

	return hasALPS || hasGREASE
}

// isFirefoxSignature checks for Firefox-specific signatures
func isFirefoxSignature(ch *ClientHello) bool {
	// Firefox uses different extension ordering
	// No ALPS extension
	// Different supported groups

	hasALPS := false
	for _, ext := range ch.Extensions {
		if ext.Type == 0x0011 {
			hasALPS = true
			break
		}
	}

	return !hasALPS && len(ch.Extensions) > 10
}

// isSafariSignature checks for Safari-specific signatures
func isSafariSignature(ch *ClientHello) bool {
	// Safari has different cipher suite ordering
	// No TLS 1.3 early data

	return false // Would need more specific checks
}

// HTTP2FrameCapture captures HTTP/2 frames from a connection
type HTTP2FrameCapture struct {
	reader io.Reader
	writer io.Writer

	OnFrame func(frameType, flags uint8, streamID uint32, payload []byte)

	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
}

// NewHTTP2FrameCapture creates an HTTP/2 frame capture wrapper
func NewHTTP2FrameCapture(reader io.Reader, writer io.Writer, onFrame func(uint8, uint8, uint32, []byte)) *HTTP2FrameCapture {
	return &HTTP2FrameCapture{
		reader:  reader,
		writer:  writer,
		OnFrame: onFrame,
	}
}

// Read captures incoming HTTP/2 frames
func (h *HTTP2FrameCapture) Read(p []byte) (n int, err error) {
	n, err = h.reader.Read(p)
	if n > 0 {
		h.readBuf.Write(p[:n])
		h.parseFrames(&h.readBuf)
	}
	return n, err
}

// Write captures outgoing HTTP/2 frames
func (h *HTTP2FrameCapture) Write(p []byte) (n int, err error) {
	// First write, then capture
	n, err = h.writer.Write(p)
	if n > 0 {
		h.writeBuf.Write(p[:n])
		h.parseFrames(&h.writeBuf)
	}
	return n, err
}

// parseFrames parses buffered data for HTTP/2 frames
func (h *HTTP2FrameCapture) parseFrames(buf *bytes.Buffer) {
	data := buf.Bytes()
	offset := 0

	// Check for connection preface
	if len(data) >= 24 {
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if bytes.Equal(data[:24], preface) {
			if h.OnFrame != nil {
				h.OnFrame(0xFF, 0, 0, []byte("CONNECTION_PREFACE"))
			}
			offset = 24
			data = data[24:]
		}
	}

	// Parse frames (9 byte header + payload)
	for len(data) >= 9 {
		length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		frameType := data[3]
		flags := data[4]
		streamID := uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
		streamID &= 0x7FFFFFFF // Clear reserved bit

		if len(data) < 9+int(length) {
			// Incomplete frame
			break
		}

		if h.OnFrame != nil {
			h.OnFrame(frameType, flags, streamID, data[9:9+int(length)])
		}

		offset += 9 + int(length)
		data = data[9+int(length):]
	}

	if offset > 0 {
		buf.Next(offset)
	}
}

// HTTP2Frame types
const (
	HTTP2FrameData         = 0x0
	HTTP2FrameHeaders      = 0x1
	HTTP2FramePriority     = 0x2
	HTTP2FrameRSTStream    = 0x3
	HTTP2FrameSettings     = 0x4
	HTTP2FramePushPromise  = 0x5
	HTTP2FramePing         = 0x6
	HTTP2FrameGoAway       = 0x7
	HTTP2FrameWindowUpdate = 0x8
	HTTP2FrameContinuation = 0x9
)

// FrameTypeName returns the name of an HTTP/2 frame type
func FrameTypeName(t uint8) string {
	names := map[uint8]string{
		HTTP2FrameData:         "DATA",
		HTTP2FrameHeaders:      "HEADERS",
		HTTP2FramePriority:     "PRIORITY",
		HTTP2FrameRSTStream:    "RST_STREAM",
		HTTP2FrameSettings:     "SETTINGS",
		HTTP2FramePushPromise:  "PUSH_PROMISE",
		HTTP2FramePing:         "PING",
		HTTP2FrameGoAway:       "GOAWAY",
		HTTP2FrameWindowUpdate: "WINDOW_UPDATE",
		HTTP2FrameContinuation: "CONTINUATION",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", t)
}

// ParseSettingsFrame parses a SETTINGS frame payload
func ParseSettingsFrame(payload []byte) []HTTP2Setting {
	var settings []HTTP2Setting

	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		value := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])

		settings = append(settings, HTTP2Setting{
			ID:    id,
			Name:  SettingName(id),
			Value: value,
		})
	}

	return settings
}

// SettingName returns the name of a SETTINGS parameter
func SettingName(id uint16) string {
	names := map[uint16]string{
		0x1: "HEADER_TABLE_SIZE",
		0x2: "ENABLE_PUSH",
		0x3: "MAX_CONCURRENT_STREAMS",
		0x4: "INITIAL_WINDOW_SIZE",
		0x5: "MAX_FRAME_SIZE",
		0x6: "MAX_HEADER_LIST_SIZE",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", id)
}
