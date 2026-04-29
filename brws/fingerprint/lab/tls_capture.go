// Package lab provides TLS ClientHello capture at the connection level
package lab

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/fingerprint/tls/parser"
	"github.com/skunkworq/stealth/brws/core/types"
)

// tlsCaptureStore holds captured fingerprints keyed by remote address
var tlsCaptureStore = &sync.Map{}

// GetTLSCapture retrieves a captured TLS fingerprint by remote address
func GetTLSCapture(remoteAddr string) *types.CompleteFingerprint {
	if val, ok := tlsCaptureStore.Load(remoteAddr); ok {
		// Remove from store to prevent memory leaks
		tlsCaptureStore.Delete(remoteAddr)
		return val.(*types.CompleteFingerprint)
	}
	return nil
}

// CapturingListener wraps a net.Listener to capture TLS handshakes
type CapturingListener struct {
	net.Listener

	OnClientHello func(*tlsparser.ClientHello, *types.CompleteFingerprint)
}

// Accept waits for and returns the next connection to the listener,
// wrapping it to capture the TLS ClientHello
func (l *CapturingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &capturingConn{
		Conn:          conn,
		onClientHello: l.OnClientHello,
		buffer:        &bytes.Buffer{},
		readChan:      make(chan []byte, 10),
	}, nil
}

// capturingConn wraps a net.Conn to capture TLS ClientHello
type capturingConn struct {
	net.Conn

	onClientHello func(*tlsparser.ClientHello, *types.CompleteFingerprint)
	mu            sync.Mutex
	buffer        *bytes.Buffer
	readChan      chan []byte
	captured      bool

	// Parsed data
	clientHello *tlsparser.ClientHello
	fingerprint *types.CompleteFingerprint
}

// Read captures incoming data to extract ClientHello
func (c *capturingConn) Read(p []byte) (n int, err error) {
	// If we have buffered data from capture, return it first
	select {
	case buf := <-c.readChan:
		n = copy(p, buf)
		if len(buf) > n {
			c.readChan <- buf[n:]
		}
		return n, nil
	default:
	}

	// Read from underlying connection
	n, err = c.Conn.Read(p)
	if n > 0 && !c.captured {
		c.mu.Lock()
		c.buffer.Write(p[:n])

		// Try to parse ClientHello if we have enough data
		if !c.captured && c.buffer.Len() >= 5 {
			data := c.buffer.Bytes()
			// Check for TLS handshake
			if len(data) >= 5 && data[0] == 0x16 {
				recordLen := int(data[3])<<8 | int(data[4])
				if len(data) >= 5+recordLen {
					ch, err := ParseClientHello(data[:5+recordLen])
					if err == nil {
						c.captured = true
						c.clientHello = ch

						// Build fingerprint
						c.fingerprint = c.buildFingerprint(ch, data[:5+recordLen])

						// Store by remote address for lookup
						tlsCaptureStore.Store(c.RemoteAddr().String(), c.fingerprint)

						if c.onClientHello != nil {
							go c.onClientHello(ch, c.fingerprint)
						}
					}
				}
			}
		}
		c.mu.Unlock()
	}

	return n, err
}

// buildFingerprint creates a fingerprint from parsed ClientHello
func (c *capturingConn) buildFingerprint(ch *tlsparser.ClientHello, raw []byte) *types.CompleteFingerprint {
	fp := &types.CompleteFingerprint{
		ID:        generateID(),
		Timestamp: time.Now(),
		SourceIP:  c.RemoteAddr().String(),
	}

	// Convert to TLSFingerprint
	fp.TLS = ch.ToFingerprint()
	fp.TLS.RawClientHello = hex.EncodeToString(raw)

	return fp
}

// GetFingerprint returns the captured fingerprint
func (c *capturingConn) GetFingerprint() *types.CompleteFingerprint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fingerprint
}

// TLSInfo holds information extracted from TLS connection
type TLSInfo struct {
	Version            uint16
	CipherSuite        uint16
	ServerName         string
	NegotiatedProtocol string
	RawClientHello     []byte
}

// ExtractTLSInfo extracts TLS information from a connection
func ExtractTLSInfo(conn net.Conn) *TLSInfo {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}

	state := tlsConn.ConnectionState()
	return &TLSInfo{
		Version:            state.Version,
		CipherSuite:        state.CipherSuite,
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
	}
}

// FullRequestCapture captures complete request details
type FullRequestCapture struct {
	Timestamp   time.Time
	RemoteAddr  string
	Method      string
	URL         string
	Protocol    string
	Headers     http.Header
	Body        []byte
	TLS         *TLSInfo
	Fingerprint *types.CompleteFingerprint
}

// CaptureMiddleware returns middleware that captures full request details
func CaptureMiddleware(captureFunc func(*FullRequestCapture)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capture := &FullRequestCapture{
				Timestamp:  time.Now(),
				RemoteAddr: r.RemoteAddr,
				Method:     r.Method,
				URL:        r.URL.String(),
				Protocol:   r.Proto,
				Headers:    r.Header.Clone(),
			}

			// Capture TLS info
			if r.TLS != nil {
				capture.TLS = &TLSInfo{
					Version:            r.TLS.Version,
					CipherSuite:        r.TLS.CipherSuite,
					ServerName:         r.TLS.ServerName,
					NegotiatedProtocol: r.TLS.NegotiatedProtocol,
				}
			}

			// Read body if present
			if r.Body != nil {
				body, _ := readBody(r.Body)
				capture.Body = body
				r.Body = restoreBody(body)
			}

			if captureFunc != nil {
				captureFunc(capture)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// readBody reads and returns body bytes
func readBody(body io.Reader) ([]byte, error) {
	buf := &bytes.Buffer{}
	_, err := buf.ReadFrom(body)
	return buf.Bytes(), err
}

// restoreBody creates a new ReadCloser from bytes
func restoreBody(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}
