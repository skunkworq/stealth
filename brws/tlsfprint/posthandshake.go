package tlsfprint

import (
	"fmt"
	"sync"
	"time"
)

type SessionTicket struct {
	Ticket    []byte
	Label     string
	Age       time.Duration
	CreatedAt time.Time
	UsedCount int
	Lifetime  time.Duration
	MaxUse    int
}

type TLS13PostHandshake struct {
	EarlyData         bool
	EarlyDataSize     int
	EarlyDataSent     bool
	EarlyDataAccepted bool

	SessionTickets []SessionTicket

	NewSessionTicket interface{}

	HandshakeComplete bool

	ZeroRTTState TLS13EarlyDataState
}

type TLS13EarlyDataState int

const (
	EarlyDataNotUsed TLS13EarlyDataState = iota
	EarlyDataSent
	EarlyDataAccepted
	EarlyDataRejected
)

type ConnectionReuseTracker struct {
	mu              sync.RWMutex
	connections     map[string]*ConnectionInfo
	maxConnections  int
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

type ConnectionInfo struct {
	RemoteAddr string
	RemoteSNI  string

	CreatedAt  time.Time
	LastUsedAt time.Time

	ReuseCount    int
	TotalRequests int

	TLSVersion  uint16
	CipherSuite uint16

	SessionID      []byte
	SessionTickets [][]byte

	EarlyDataUsed bool

	PacketsSent int
	PacketsRecv int
	BytesSent   int64
	BytesRecv   int64

	Latencies []time.Duration

	Closed      bool
	CloseReason string
}

func NewConnectionReuseTracker(maxConnections int, cleanupInterval time.Duration) *ConnectionReuseTracker {
	if maxConnections == 0 {
		maxConnections = 1000
	}
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}

	return &ConnectionReuseTracker{
		connections:     make(map[string]*ConnectionInfo),
		maxConnections:  maxConnections,
		cleanupInterval: cleanupInterval,
	}
}

func (t *ConnectionReuseTracker) RecordConnection(id string, info *ConnectionInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.connections) >= t.maxConnections {
		t.cleanup()
	}

	t.connections[id] = info
}

func (t *ConnectionReuseTracker) RecordReuse(id string, latency time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn, ok := t.connections[id]; ok {
		conn.ReuseCount++
		conn.LastUsedAt = time.Now()
		conn.TotalRequests++
		conn.Latencies = append(conn.Latencies, latency)

		if len(conn.Latencies) > 100 {
			conn.Latencies = conn.Latencies[1:]
		}
	}
}

func (t *ConnectionReuseTracker) RecordSessionTicket(id string, ticket []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn, ok := t.connections[id]; ok {
		conn.SessionTickets = append(conn.SessionTickets, ticket)
	}
}

func (t *ConnectionReuseTracker) CloseConnection(id, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn, ok := t.connections[id]; ok {
		conn.Closed = true
		conn.CloseReason = reason
	}
}

func (t *ConnectionReuseTracker) GetConnection(id string) *ConnectionInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connections[id]
}

func (t *ConnectionReuseTracker) GetAllConnections() []*ConnectionInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*ConnectionInfo, 0, len(t.connections))
	for _, conn := range t.connections {
		result = append(result, conn)
	}
	return result
}

func (t *ConnectionReuseTracker) cleanup() {
	now := time.Now()
	if now.Sub(t.lastCleanup) < t.cleanupInterval {
		return
	}

	t.lastCleanup = now

	var toDelete []string
	for id, conn := range t.connections {
		if conn.Closed || now.Sub(conn.LastUsedAt) > 10*time.Minute {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		delete(t.connections, id)
	}
}

func (t *ConnectionReuseTracker) GetStats() *ConnectionReuseStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := &ConnectionReuseStats{
		TotalConnections: len(t.connections),
	}

	var totalReuse, totalRequests int64
	var totalLatency time.Duration

	for _, conn := range t.connections {
		stats.ActiveConnections++

		totalReuse += int64(conn.ReuseCount)
		totalRequests += int64(conn.TotalRequests)

		if len(conn.Latencies) > 0 {
			for _, l := range conn.Latencies {
				totalLatency += l
			}
			avgLat := totalLatency / time.Duration(len(conn.Latencies))
			stats.AvgLatency = avgLat
		}

		if conn.EarlyDataUsed {
			stats.EarlyDataUsed++
		}

		if len(conn.SessionTickets) > 0 {
			stats.ConnectionsWithTickets++
		}
	}

	if stats.ActiveConnections > 0 {
		stats.ReuseRate = float64(totalReuse) / float64(stats.ActiveConnections)
	}

	return stats
}

type ConnectionReuseStats struct {
	TotalConnections       int
	ActiveConnections      int
	ReuseRate              float64
	AvgLatency             time.Duration
	EarlyDataUsed          int
	ConnectionsWithTickets int
}

type TLS13SessionManager struct {
	tickets map[string][]SessionTicket
	mu      sync.RWMutex
}

func NewTLS13SessionManager() *TLS13SessionManager {
	return &TLS13SessionManager{
		tickets: make(map[string][]SessionTicket),
	}
}

func (m *TLS13SessionManager) StoreTicket(serverName string, ticket SessionTicket) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tickets[serverName] = append(m.tickets[serverName], ticket)
}

func (m *TLS13SessionManager) GetTicket(serverName string) *SessionTicket {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tickets := m.tickets[serverName]
	if len(tickets) == 0 {
		return nil
	}

	now := time.Now()
	for i := range tickets {
		ticket := &tickets[i]
		if now.Sub(ticket.CreatedAt) < ticket.Lifetime && ticket.UsedCount < ticket.MaxUse {
			ticket.UsedCount++
			return ticket
		}
	}

	return nil
}

func (m *TLS13SessionManager) Cleanup(serverName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var valid []SessionTicket
	now := time.Now()
	for _, ticket := range m.tickets[serverName] {
		if now.Sub(ticket.CreatedAt) < ticket.Lifetime && ticket.UsedCount < ticket.MaxUse {
			valid = append(valid, ticket)
		}
	}
	m.tickets[serverName] = valid
}

type HandshakeMetrics struct {
	HandshakeDuration time.Duration

	TLSVersion  uint16
	CipherSuite uint16

	ServerAuthTime time.Duration
	ClientAuthTime time.Duration

	SessionResumed bool

	EarlyDataAttempted bool
	EarlyDataAccepted  bool
	EarlyDataBytes     int

	CertificateVerifyTime time.Duration
	ServerKeyExchangeTime time.Duration

	TotalBytesSent int64
	TotalBytesRecv int64

	PacketCount int
}

func (m *HandshakeMetrics) String() string {
	return fmt.Sprintf("Handshake{duration: %v, version: 0x%04x, cipher: 0x%04x, resumed: %t, early_data: %t}",
		m.HandshakeDuration,
		m.TLSVersion,
		m.CipherSuite,
		m.SessionResumed,
		m.EarlyDataAttempted,
	)
}

type HandshakeAnalyzer struct {
	mu         sync.RWMutex
	handshakes []HandshakeMetrics
}

func NewHandshakeAnalyzer() *HandshakeAnalyzer {
	return &HandshakeAnalyzer{
		handshakes: make([]HandshakeMetrics, 0),
	}
}

func (a *HandshakeAnalyzer) Record(m HandshakeMetrics) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.handshakes = append(a.handshakes, m)

	if len(a.handshakes) > 10000 {
		a.handshakes = a.handshakes[1:]
	}
}

func (a *HandshakeAnalyzer) GetStats() *HandshakeAnalyzerStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := &HandshakeAnalyzerStats{
		TotalHandshakes: len(a.handshakes),
	}

	if len(a.handshakes) == 0 {
		return stats
	}

	var totalDuration time.Duration
	var totalEarlyData int
	var resumedCount int

	for _, h := range a.handshakes {
		totalDuration += h.HandshakeDuration
		if h.EarlyDataAttempted {
			totalEarlyData++
		}
		if h.SessionResumed {
			resumedCount++
		}
	}

	stats.AvgHandshakeDuration = totalDuration / time.Duration(len(a.handshakes))
	stats.EarlyDataUsageRate = float64(totalEarlyData) / float64(len(a.handshakes))
	stats.SessionResumptionRate = float64(resumedCount) / float64(len(a.handshakes))

	var minDuration, maxDuration = a.handshakes[0].HandshakeDuration, a.handshakes[0].HandshakeDuration
	for _, h := range a.handshakes {
		if h.HandshakeDuration < minDuration {
			minDuration = h.HandshakeDuration
		}
		if h.HandshakeDuration > maxDuration {
			maxDuration = h.HandshakeDuration
		}
	}
	stats.MinHandshakeDuration = minDuration
	stats.MaxHandshakeDuration = maxDuration

	return stats
}

type HandshakeAnalyzerStats struct {
	TotalHandshakes       int
	AvgHandshakeDuration  time.Duration
	MinHandshakeDuration  time.Duration
	MaxHandshakeDuration  time.Duration
	SessionResumptionRate float64
	EarlyDataUsageRate    float64
}

type PostHandshakeAnalyzer struct {
	mu             sync.RWMutex
	postHandshakes []PostHandshakeEvent
}

type PostHandshakeEvent struct {
	Timestamp time.Time
	Type      string
	Success   bool
	Duration  time.Duration
	Error     string
	SessionID string
}

func NewPostHandshakeAnalyzer() *PostHandshakeAnalyzer {
	return &PostHandshakeAnalyzer{
		postHandshakes: make([]PostHandshakeEvent, 0),
	}
}

func (a *PostHandshakeAnalyzer) Record(event PostHandshakeEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.postHandshakes = append(a.postHandshakes, event)

	if len(a.postHandshakes) > 10000 {
		a.postHandshakes = a.postHandshakes[1:]
	}
}

func (a *PostHandshakeAnalyzer) RecordNewSessionTicket(sessionID string, duration time.Duration) {
	a.Record(PostHandshakeEvent{
		Timestamp: time.Now(),
		Type:      "new_session_ticket",
		Success:   true,
		Duration:  duration,
		SessionID: sessionID,
	})
}

func (a *PostHandshakeAnalyzer) RecordKeyUpdate(duration time.Duration, err error) {
	a.Record(PostHandshakeEvent{
		Timestamp: time.Now(),
		Type:      "key_update",
		Success:   err == nil,
		Duration:  duration,
		Error:     fmt.Sprintf("%v", err),
	})
}

func (a *PostHandshakeAnalyzer) RecordHandshakeDone(duration time.Duration) {
	a.Record(PostHandshakeEvent{
		Timestamp: time.Now(),
		Type:      "handshake_done",
		Success:   true,
		Duration:  duration,
	})
}

func (a *PostHandshakeAnalyzer) GetStats() *PostHandshakeStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := &PostHandshakeStats{
		TotalEvents: len(a.postHandshakes),
	}

	eventCounts := make(map[string]int)
	successCounts := make(map[string]int)

	for _, e := range a.postHandshakes {
		eventCounts[e.Type]++
		if e.Success {
			successCounts[e.Type]++
		}
	}

	stats.ByType = eventCounts
	stats.SuccessRate = make(map[string]float64)

	for t, count := range eventCounts {
		if success, ok := successCounts[t]; ok {
			stats.SuccessRate[t] = float64(success) / float64(count)
		}
	}

	return stats
}

type PostHandshakeStats struct {
	TotalEvents int
	ByType      map[string]int
	SuccessRate map[string]float64
}

type KeyUpdateFingerprint struct {
	RequestDirection string
	RequestTime      time.Time
	ProcessingTime   time.Duration
	SequenceNumber   uint64
	Errors           []string
}

type TLS13KeyUpdateAnalyzer struct {
	mu           sync.RWMutex
	observations []KeyUpdateFingerprint
}

func NewTLS13KeyUpdateAnalyzer() *TLS13KeyUpdateAnalyzer {
	return &TLS13KeyUpdateAnalyzer{
		observations: make([]KeyUpdateFingerprint, 0),
	}
}

func (a *TLS13KeyUpdateAnalyzer) RecordKeyUpdate(dir string, seq uint64, dur time.Duration, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	fp := KeyUpdateFingerprint{
		RequestDirection: dir,
		RequestTime:      time.Now(),
		ProcessingTime:   dur,
		SequenceNumber:   seq,
	}
	if err != nil {
		fp.Errors = append(fp.Errors, err.Error())
	}
	a.observations = append(a.observations, fp)
}

func (a *TLS13KeyUpdateAnalyzer) GetFingerprint() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.observations) == 0 {
		return "no_key_updates"
	}

	counts := make(map[string]int)
	var totalDur time.Duration
	errorCount := 0

	for _, o := range a.observations {
		counts[o.RequestDirection]++
		totalDur += o.ProcessingTime
		if len(o.Errors) > 0 {
			errorCount++
		}
	}

	avgDur := totalDur / time.Duration(len(a.observations))
	dir := "unidirectional"
	if counts["client"] > 0 && counts["server"] > 0 {
		dir = "bidirectional"
	}
	errStr := "ok"
	if errorCount > 0 {
		errStr = "err"
	}
	return fmt.Sprintf("ku_%d_%s_%s_%dms",
		len(a.observations),
		dir,
		errStr,
		avgDur.Milliseconds())
}

type SessionTicketTiming struct {
	TicketAge        time.Duration
	IssueTime        time.Time
	UsedLatency      time.Duration
	AcceptLatency    time.Duration
	EarlyDataEnabled bool
}

type SessionTicketTimingAnalyzer struct {
	mu          sync.RWMutex
	ticketStats []SessionTicketTiming
}

func NewSessionTicketTimingAnalyzer() *SessionTicketTimingAnalyzer {
	return &SessionTicketTimingAnalyzer{
		ticketStats: make([]SessionTicketTiming, 0),
	}
}

func (a *SessionTicketTimingAnalyzer) RecordTicketIssue(age time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.ticketStats = append(a.ticketStats, SessionTicketTiming{
		TicketAge: age,
		IssueTime: time.Now(),
	})
}

func (a *SessionTicketTimingAnalyzer) RecordTicketUse(idx int, latency time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if idx >= 0 && idx < len(a.ticketStats) {
		a.ticketStats[idx].UsedLatency = latency
	}
}

func (a *SessionTicketTimingAnalyzer) GetTimingFingerprint() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.ticketStats) == 0 {
		return "no_tickets"
	}

	var totalAge, totalLatency time.Duration
	earlyDataEnabled := 0

	for _, t := range a.ticketStats {
		totalAge += t.TicketAge
		totalLatency += t.UsedLatency
		if t.EarlyDataEnabled {
			earlyDataEnabled++
		}
	}

	avgAge := totalAge / time.Duration(len(a.ticketStats))
	avgLatency := totalLatency / time.Duration(len(a.ticketStats))

	return fmt.Sprintf("st_%d_%dms_%dms_ed%d",
		len(a.ticketStats),
		avgAge.Milliseconds(),
		avgLatency.Milliseconds(),
		earlyDataEnabled)
}
