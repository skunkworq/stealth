package tlsfprint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

type TLSParser struct {
	readBuf []byte
	offset  int
}

func NewTLSParser(data []byte) *TLSParser {
	return &TLSParser{
		readBuf: data,
		offset:  0,
	}
}

func (p *TLSParser) ReadByte() (byte, error) {
	if p.offset >= len(p.readBuf) {
		return 0, io.EOF
	}
	b := p.readBuf[p.offset]
	p.offset++
	return b, nil
}

func (p *TLSParser) ReadUint16() (uint16, error) {
	if p.offset+2 > len(p.readBuf) {
		return 0, io.EOF
	}
	v := binary.BigEndian.Uint16(p.readBuf[p.offset : p.offset+2])
	p.offset += 2
	return v, nil
}

func (p *TLSParser) ReadUint24() (uint32, error) {
	if p.offset+3 > len(p.readBuf) {
		return 0, io.EOF
	}
	v := uint32(p.readBuf[p.offset]) << 16
	v |= uint32(p.readBuf[p.offset+1]) << 8
	v |= uint32(p.readBuf[p.offset+2])
	p.offset += 3
	return v, nil
}

func (p *TLSParser) ReadBytes(n int) ([]byte, error) {
	if p.offset+n > len(p.readBuf) {
		return nil, io.EOF
	}
	b := make([]byte, n)
	copy(b, p.readBuf[p.offset:p.offset+n])
	p.offset += n
	return b, nil
}

func (p *TLSParser) ReadVariableBytes(maxLen int) ([]byte, error) {
	lenBytes, err := p.ReadUint16()
	if err != nil {
		return nil, err
	}
	if int(lenBytes) > maxLen {
		return nil, fmt.Errorf("length %d exceeds max %d", lenBytes, maxLen)
	}
	return p.ReadBytes(int(lenBytes))
}

func ParseRawClientHello(data []byte) (*RawClientHello, error) {
	p := NewTLSParser(data)

	contentType, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading content type: %w", err)
	}

	if contentType != 0x16 {
		return nil, fmt.Errorf("not a handshake (content type 0x%02x)", contentType)
	}

	versionMajor, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading version major: %w", err)
	}
	versionMinor, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading version minor: %w", err)
	}
	version := uint16(versionMajor)<<8 | uint16(versionMinor)

	_, err = p.ReadBytes(2)
	if err != nil {
		return nil, fmt.Errorf("skipping length: %w", err)
	}

	handshakeType, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading handshake type: %w", err)
	}

	if handshakeType != 0x01 {
		return nil, fmt.Errorf("not a ClientHello (handshake type 0x%02x)", handshakeType)
	}

	handshakeLen, err := p.ReadUint24()
	if err != nil {
		return nil, fmt.Errorf("reading handshake length: %w", err)
	}

	clientHelloVersionMajor, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading client hello version major: %w", err)
	}
	clientHelloVersionMinor, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading client hello version minor: %w", err)
	}
	clientHelloVersion := uint16(clientHelloVersionMajor)<<8 | uint16(clientHelloVersionMinor)

	random, err := p.ReadBytes(32)
	if err != nil {
		return nil, fmt.Errorf("reading random: %w", err)
	}

	sessionIDLen, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading session ID length: %w", err)
	}

	sessionID, err := p.ReadBytes(int(sessionIDLen))
	if err != nil {
		return nil, fmt.Errorf("reading session ID: %w", err)
	}

	cipherSuitesLen, err := p.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading cipher suites length: %w", err)
	}

	cipherSuitesCount := int(cipherSuitesLen) / 2
	cipherSuites := make([]uint16, 0, cipherSuitesCount)
	for i := 0; i < cipherSuitesCount; i++ {
		cs, err := p.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("reading cipher suite: %w", err)
		}
		cipherSuites = append(cipherSuites, cs)
	}

	compressionMethodsLen, err := p.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading compression methods length: %w", err)
	}

	compressionMethods, err := p.ReadBytes(int(compressionMethodsLen))
	if err != nil {
		return nil, fmt.Errorf("reading compression methods: %w", err)
	}

	var extensions []ExtensionInfo
	extensionsLen, err := p.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("reading extensions length: %w", err)
	}

	if extensionsLen > 0 {
		extData, err := p.ReadBytes(int(extensionsLen))
		if err != nil {
			return nil, fmt.Errorf("reading extensions: %w", err)
		}

		extParser := NewTLSParser(extData)
		for extParser.offset < len(extData) {
			extType, err := extParser.ReadUint16()
			if err != nil {
				break // Stop parsing extensions on error - intentional
			}
			extLen, err := extParser.ReadUint16()
			if err != nil {
				break // Stop parsing extensions on error - intentional
			}
			extVal, err := extParser.ReadBytes(int(extLen))
			if err != nil {
				break // Stop parsing extensions on error - intentional
			}

			ext := ExtensionInfo{
				Type:     extType,
				TypeStr:  ExtensionToString(extType),
				Name:     ExtensionToString(extType),
				Data:     extVal,
				IsGrease: IsGreaseValue(extType),
			}

			switch extType {
			case 0:
				ext.Value = parseSNIServerName(extVal)
			case 43:
				ext.Value = parseSupportedVersions(extVal)
			}

			extensions = append(extensions, ext)
		}
	}

	//nolint:nilerr // Intentional: stop parsing extensions on error, return what we have
	return &RawClientHello{
		Raw:                data,
		TLSVersion:         version,
		ClientHelloVersion: clientHelloVersion,
		Random:             random,
		SessionID:          sessionID,
		CipherSuites:       cipherSuites,
		CompressionMethods: compressionMethods,
		Extensions:         extensions,
		HandshakeLength:    handshakeLen,
		HasGREASE:          hasGREASESuites(cipherSuites),
	}, nil
}

type RawClientHello struct {
	Raw                []byte
	TLSVersion         uint16
	ClientHelloVersion uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []ExtensionInfo
	HandshakeLength    uint32
	HasGREASE          bool
}

func parseSNIServerName(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	p := NewTLSParser(data)
	nameType, err := p.ReadByte()
	if err != nil || nameType != 0 {
		return ""
	}
	nameLen, err := p.ReadUint16()
	if err != nil {
		return ""
	}
	name, err := p.ReadBytes(int(nameLen))
	if err != nil {
		return ""
	}
	return string(name)
}

func parseSupportedVersions(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var versions []string
	p := NewTLSParser(data)
	for p.offset < len(data) {
		v, err := p.ReadByte()
		if err != nil {
			break
		}
		versions = append(versions, VersionToString(uint16(v)<<8))
	}
	return join(versions, ",")
}

func hasGREASESuites(suites []uint16) bool {
	for _, s := range suites {
		if IsGreaseValue(s) {
			return true
		}
	}
	return false
}

func join(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

type SNIAnalyzer struct {
	observations []SNIObservation
}

type SNIObservation struct {
	SNI          string
	Length       int
	IsWildcard   bool
	DomainLevels int
	TLD          string
	IsIP         bool
	IsPublic     bool
}

func NewSNIAnalyzer() *SNIAnalyzer {
	return &SNIAnalyzer{
		observations: make([]SNIObservation, 0),
	}
}

func (a *SNIAnalyzer) Analyze(sni string) SNIObservation {
	obs := SNIObservation{
		SNI:        sni,
		Length:     len(sni),
		IsWildcard: false,
		IsIP:       false,
	}

	if sni == "" {
		return obs
	}

	if isIP(sni) {
		obs.IsIP = true
		return obs
	}

	if len(sni) > 2 && sni[0] == '*' && sni[1] == '.' {
		obs.IsWildcard = true
		sni = sni[1:]
	}

	parts := bytes.Split([]byte(sni), []byte("."))
	obs.DomainLevels = len(parts)
	if len(parts) > 0 {
		obs.TLD = string(parts[len(parts)-1])
	}

	obs.IsPublic = isPublicTLD(obs.TLD)

	a.observations = append(a.observations, obs)
	return obs
}

func (a *SNIAnalyzer) GetObservations() []SNIObservation {
	return a.observations
}

func (a *SNIAnalyzer) GetWildcardRatio() float64 {
	if len(a.observations) == 0 {
		return 0
	}
	count := 0
	for _, obs := range a.observations {
		if obs.IsWildcard {
			count++
		}
	}
	return float64(count) / float64(len(a.observations))
}

func (a *SNIAnalyzer) GetAverageLength() float64 {
	if len(a.observations) == 0 {
		return 0
	}
	sum := 0
	for _, obs := range a.observations {
		sum += obs.Length
	}
	return float64(sum) / float64(len(a.observations))
}

func isIP(s string) bytesMatcher {
	parts := bytes.Split([]byte(s), []byte("."))
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) > 3 {
			return false
		}
	}
	return true
}

type bytesMatcher bool

func isPublicTLD(tld string) bool {
	publicTLDs := map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true,
		"io": true, "co": true, "ai": true, "me": true, "info": true,
		"biz": true, "cn": true, "de": true, "fr": true, "jp": true,
		"ru": true, "br": true, "in": true, "au": true, "uk": true,
	}
	return publicTLDs[tld]
}

type ConnectionStateTracker struct {
	states    map[string]*ConnectionState
	maxStates int
}

type ConnectionState struct {
	ConnectionID  string
	RemoteAddr    string
	LocalAddr     string
	Protocol      string
	CipherSuite   uint16
	TLSVersion    uint16
	SessionID     []byte
	SessionTicket []byte
	Established   bool
	Closed        bool
	RequestsCount int
	BytesSent     int64
	BytesReceived int64
	StartTime     int64
	EndTime       int64
	HandshakeTime int64
}

func NewConnectionStateTracker(maxStates int) *ConnectionStateTracker {
	if maxStates <= 0 {
		maxStates = 1000
	}
	return &ConnectionStateTracker{
		states:    make(map[string]*ConnectionState),
		maxStates: maxStates,
	}
}

func (t *ConnectionStateTracker) AddConnection(connID, remote, local string) *ConnectionState {
	state := &ConnectionState{
		ConnectionID: connID,
		RemoteAddr:   remote,
		LocalAddr:    local,
		StartTime:    nowUnix(),
	}

	if len(t.states) >= t.maxStates {
		t.evictOldest()
	}

	t.states[connID] = state
	return state
}

func (t *ConnectionStateTracker) GetConnection(connID string) *ConnectionState {
	return t.states[connID]
}

func (t *ConnectionStateTracker) UpdateTLS(connID string, version uint16, cipher uint16) {
	if state, ok := t.states[connID]; ok {
		state.TLSVersion = version
		state.CipherSuite = cipher
	}
}

func (t *ConnectionStateTracker) SetSessionID(connID string, sessionID []byte) {
	if state, ok := t.states[connID]; ok {
		state.SessionID = sessionID
	}
}

func (t *ConnectionStateTracker) SetSessionTicket(connID string, ticket []byte) {
	if state, ok := t.states[connID]; ok {
		state.SessionTicket = ticket
	}
}

func (t *ConnectionStateTracker) MarkEstablished(connID string, handshakeTime int64) {
	if state, ok := t.states[connID]; ok {
		state.Established = true
		state.HandshakeTime = handshakeTime
	}
}

func (t *ConnectionStateTracker) CloseConnection(connID string) {
	if state, ok := t.states[connID]; ok {
		state.Closed = true
		state.EndTime = nowUnix()
	}
}

func (t *ConnectionStateTracker) IncrementRequests(connID string) {
	if state, ok := t.states[connID]; ok {
		state.RequestsCount++
	}
}

func (t *ConnectionStateTracker) AddBytesSent(connID string, n int64) {
	if state, ok := t.states[connID]; ok {
		state.BytesSent += n
	}
}

func (t *ConnectionStateTracker) AddBytesReceived(connID string, n int64) {
	if state, ok := t.states[connID]; ok {
		state.BytesReceived += n
	}
}

func (t *ConnectionStateTracker) GetActiveConnections() []*ConnectionState {
	var active []*ConnectionState
	for _, state := range t.states {
		if state.Established && !state.Closed {
			active = append(active, state)
		}
	}
	return active
}

func (t *ConnectionStateTracker) GetClosedConnections() []*ConnectionState {
	var closed []*ConnectionState
	for _, state := range t.states {
		if state.Closed {
			closed = append(closed, state)
		}
	}
	return closed
}

func (t *ConnectionStateTracker) GetResumedConnections() []*ConnectionState {
	var resumed []*ConnectionState
	for _, state := range t.states {
		if len(state.SessionID) > 0 || len(state.SessionTicket) > 0 {
			resumed = append(resumed, state)
		}
	}
	return resumed
}

func (t *ConnectionStateTracker) GetAverageHandshakeTime() int64 {
	var total int64
	var count int
	for _, state := range t.states {
		if state.Established && state.HandshakeTime > 0 {
			total += state.HandshakeTime
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / int64(count)
}

func (t *ConnectionStateTracker) evictOldest() {
	var oldest string
	var oldestTime int64 = 1<<63 - 1
	for id, state := range t.states {
		if state.StartTime < oldestTime {
			oldestTime = state.StartTime
			oldest = id
		}
	}
	if oldest != "" {
		delete(t.states, oldest)
	}
}

func nowUnix() int64 {
	return time.Now().Unix()
}
