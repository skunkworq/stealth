package tlsfprint

import (
	"encoding/hex"
	"fmt"
)

type PSKFingerprint struct {
	HasPSK           bool
	PSKMode          string
	PSKIdentities    []string
	PSKBinderLengths []int
	PSKCount         int
	EarlyDataAllowed bool
	EarlyDataSize    int
}

func AnalyzePSK(ch *ClientHelloInfo) *PSKFingerprint {
	fp := &PSKFingerprint{
		HasPSK:           false,
		PSKIdentities:    make([]string, 0),
		PSKBinderLengths: make([]int, 0),
		PSKCount:         0,
	}

	fp.HasPSK = hasExt(ch.ExtensionsList, 41)
	fp.EarlyDataAllowed = hasExt(ch.ExtensionsList, 35)

	if fp.HasPSK {
		fp.PSKMode = "psk_dhe_ke"
		fp.PSKCount = len(ch.CipherSuites)
	}

	return fp
}

func (f *PSKFingerprint) ToString() string {
	mode := f.PSKMode
	if mode == "" {
		mode = "none"
	}
	earlyData := "no"
	if f.EarlyDataAllowed {
		earlyData = "yes"
	}
	return fmt.Sprintf("psk:%s,count:%d,early:%s", mode, f.PSKCount, earlyData)
}

type PSKSession struct {
	Identity       string
	CreatedAt      int64
	LastUsedAt     int64
	UsesRemaining  int
	TicketAgeAdd   uint32
	TicketNonce    []byte
	TicketLifetime int
	Label          string
}

func NewPSKSession(identity string) *PSKSession {
	return &PSKSession{
		Identity:      identity,
		CreatedAt:     0,
		LastUsedAt:    0,
		UsesRemaining: 1,
		Label:         "external",
	}
}

func (s *PSKSession) IsExpired() bool {
	if s.TicketLifetime == 0 {
		return false
	}
	return s.LastUsedAt > s.CreatedAt+int64(s.TicketLifetime)
}

func (s *PSKSession) IsUsable() bool {
	return s.UsesRemaining > 0 && !s.IsExpired()
}

func (s *PSKSession) MarkUsed() {
	s.LastUsedAt = 0
	s.UsesRemaining--
}

type PSKStore struct {
	sessions map[string]*PSKSession
}

func NewPSKStore() *PSKStore {
	return &PSKStore{
		sessions: make(map[string]*PSKSession),
	}
}

func (s *PSKStore) AddSession(identity string, session *PSKSession) {
	s.sessions[identity] = session
}

func (s *PSKStore) GetSession(identity string) *PSKSession {
	return s.sessions[identity]
}

func (s *PSKStore) RemoveSession(identity string) {
	delete(s.sessions, identity)
}

func (s *PSKStore) GetAllSessions() []*PSKSession {
	sessions := make([]*PSKSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

func (s *PSKStore) GetUsableSessions() []*PSKSession {
	var sessions []*PSKSession
	for _, session := range s.sessions {
		if session.IsUsable() {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

type PSKAnalyzer struct {
	observations []PSKFingerprint
	store        *PSKStore
}

func NewPSKAnalyzer() *PSKAnalyzer {
	return &PSKAnalyzer{
		observations: make([]PSKFingerprint, 0),
		store:        NewPSKStore(),
	}
}

func (a *PSKAnalyzer) Record(ch *ClientHelloInfo) {
	fp := AnalyzePSK(ch)
	a.observations = append(a.observations, *fp)
}

func (a *PSKAnalyzer) GetStats() *PSKStats {
	stats := &PSKStats{
		TotalConnections:   len(a.observations),
		PSKUsedCount:       0,
		EarlyDataUsedCount: 0,
		AveragePSKPerConn:  0.0,
		MostCommonPSKMode:  "none",
	}

	var pskTotal int
	for _, obs := range a.observations {
		if obs.HasPSK {
			stats.PSKUsedCount++
		}
		if obs.EarlyDataAllowed {
			stats.EarlyDataUsedCount++
		}
		pskTotal += obs.PSKCount
	}

	if stats.TotalConnections > 0 {
		stats.AveragePSKPerConn = float64(pskTotal) / float64(stats.TotalConnections)
	}

	modeCounts := make(map[string]int)
	for _, obs := range a.observations {
		modeCounts[obs.PSKMode]++
	}
	var maxCount int
	for mode, count := range modeCounts {
		if count > maxCount {
			maxCount = count
			stats.MostCommonPSKMode = mode
		}
	}

	return stats
}

type PSKStats struct {
	TotalConnections   int
	PSKUsedCount       int
	EarlyDataUsedCount int
	AveragePSKPerConn  float64
	MostCommonPSKMode  string
}

type PSKCompatibilityChecker struct {
	clientPSKs []string
	serverPSKs []string
}

func NewPSKCompatibilityChecker() *PSKCompatibilityChecker {
	return &PSKCompatibilityChecker{
		clientPSKs: make([]string, 0),
		serverPSKs: make([]string, 0),
	}
}

func (c *PSKCompatibilityChecker) SetClientIdentities(identities []string) {
	c.clientPSKs = identities
}

func (c *PSKCompatibilityChecker) SetServerIdentities(identities []string) {
	c.serverPSKs = identities
}

func (c *PSKCompatibilityChecker) HasCompatiblePSK() bool {
	for _, clientID := range c.clientPSKs {
		for _, serverID := range c.serverPSKs {
			if clientID == serverID {
				return true
			}
		}
	}
	return false
}

func (c *PSKCompatibilityChecker) GetMatchingIdentities() []string {
	var matches []string
	for _, clientID := range c.clientPSKs {
		for _, serverID := range c.serverPSKs {
			if clientID == serverID {
				matches = append(matches, clientID)
			}
		}
	}
	return matches
}

func CalculatePSKBinderHash(identity, binderInput []byte, hashLen int) string {
	binderData := make([]byte, len(identity)+len(binderInput))
	copy(binderData, identity)
	copy(binderData[len(identity):], binderInput)

	hash := make([]byte, hashLen)
	for i := range hash {
		hash[i] = binderData[i%len(binderData)]
	}

	return hex.EncodeToString(hash)
}

type ZeroRTTAnalyzer struct {
	observations []ZeroRTTInfo
}

type ZeroRTTInfo struct {
	EarlyDataReceived bool
	EarlyDataSize     int
	RetryRequested    bool
}

func NewZeroRTTAnalyzer() *ZeroRTTAnalyzer {
	return &ZeroRTTAnalyzer{
		observations: make([]ZeroRTTInfo, 0),
	}
}

func (a *ZeroRTTAnalyzer) Record(earlyData bool, size int) {
	info := ZeroRTTInfo{
		EarlyDataReceived: earlyData,
		EarlyDataSize:     size,
	}
	a.observations = append(a.observations, info)
}

func (a *ZeroRTTAnalyzer) RecordRetry() {
	if len(a.observations) > 0 {
		a.observations[len(a.observations)-1].RetryRequested = true
	}
}

func (a *ZeroRTTAnalyzer) GetStats() *ZeroRTTStats {
	stats := &ZeroRTTStats{
		TotalAttempts: len(a.observations),
	}

	for _, obs := range a.observations {
		if obs.EarlyDataReceived {
			stats.SuccessfulCount++
			stats.TotalBytes += obs.EarlyDataSize
		}
		if obs.RetryRequested {
			stats.RetryCount++
		}
	}

	if stats.TotalAttempts > 0 {
		stats.SuccessRate = float64(stats.SuccessfulCount) / float64(stats.TotalAttempts)
	}

	if stats.SuccessfulCount > 0 {
		stats.AverageBytes = float64(stats.TotalBytes) / float64(stats.SuccessfulCount)
	}

	return stats
}

type ZeroRTTStats struct {
	TotalAttempts   int
	SuccessfulCount int
	RetryCount      int
	TotalBytes      int
	AverageBytes    float64
	SuccessRate     float64
}

func (s *ZeroRTTStats) ToString() string {
	return fmt.Sprintf("0-RTT: attempts=%d, success=%d, retry=%d, rate=%.2f%%",
		s.TotalAttempts, s.SuccessfulCount, s.RetryCount, s.SuccessRate*100)
}
