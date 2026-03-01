package tlsfprint

import (
	"fmt"
	"sort"
	"sync"
)

type ServerTLSFingerprint struct {
	ServerName  string
	TLSVersion  uint16
	CipherSuite uint16
	Extensions  []uint16
	SessionID   []byte
	Random      []byte

	SupportedVersions []uint16
	SupportedGroups   []uint16
	SignatureAlgs     []uint16
	ALPN              []string
}

type ServerFingerprintAnalyzer struct {
	mu           sync.RWMutex
	observations []ServerTLSFingerprint
	stats        *ServerStats
}

type ServerStats struct {
	TotalConnections   int64
	ByTLSVersion       map[string]int64
	ByCipherSuite      map[string]int64
	ByALPN             map[string]int64
	AverageHandshakeMs float64
}

func NewServerFingerprintAnalyzer() *ServerFingerprintAnalyzer {
	return &ServerFingerprintAnalyzer{
		observations: make([]ServerTLSFingerprint, 0),
		stats: &ServerStats{
			ByTLSVersion:  make(map[string]int64),
			ByCipherSuite: make(map[string]int64),
			ByALPN:        make(map[string]int64),
		},
	}
}

func (a *ServerFingerprintAnalyzer) RecordServerHello(serverName string, sh *ServerHelloInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()

	randomBytes := sh.Random[:]
	fp := ServerTLSFingerprint{
		ServerName:  serverName,
		CipherSuite: sh.CipherSuite,
		Extensions:  extTypesFromExt(sh.Extensions),
		SessionID:   sh.SessionID,
		Random:      randomBytes,
		TLSVersion:  sh.Version,
	}

	a.observations = append(a.observations, fp)
	a.updateStats(&fp)
}

func extTypesFromExt(exts []ExtensionInfo) []uint16 {
	var types []uint16
	for _, e := range exts {
		types = append(types, e.Type)
	}
	return types
}

func (a *ServerFingerprintAnalyzer) updateStats(fp *ServerTLSFingerprint) {
	a.stats.TotalConnections++

	verStr := fmt.Sprintf("0x%04x", fp.TLSVersion)
	a.stats.ByTLSVersion[verStr]++

	cipherStr := fmt.Sprintf("0x%04x", fp.CipherSuite)
	a.stats.ByCipherSuite[cipherStr]++

	if len(fp.ALPN) > 0 {
		a.stats.ByALPN[fp.ALPN[0]]++
	}
}

func (a *ServerFingerprintAnalyzer) GetStats() *ServerStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := *a.stats
	stats.ByTLSVersion = make(map[string]int64)
	stats.ByCipherSuite = make(map[string]int64)
	stats.ByALPN = make(map[string]int64)

	for k, v := range a.stats.ByTLSVersion {
		stats.ByTLSVersion[k] = v
	}
	for k, v := range a.stats.ByCipherSuite {
		stats.ByCipherSuite[k] = v
	}
	for k, v := range a.stats.ByALPN {
		stats.ByALPN[k] = v
	}

	return &stats
}

func (a *ServerFingerprintAnalyzer) GetObservations() []ServerTLSFingerprint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]ServerTLSFingerprint, len(a.observations))
	copy(result, a.observations)
	return result
}

type ServerSignatureDatabase struct {
	mu         sync.RWMutex
	signatures map[string]ServerSignature
}

type ServerSignature struct {
	Name            string
	TLSVersions     []uint16
	CipherSuites    []uint16
	Extensions      []uint16
	ALPN            []string
	CertificateSPKI string
	KeyShareGroups  []uint16
}

func NewServerSignatureDatabase() *ServerSignatureDatabase {
	db := &ServerSignatureDatabase{
		signatures: make(map[string]ServerSignature),
	}
	db.initDefaults()
	return db
}

func (db *ServerSignatureDatabase) initDefaults() {
	db.signatures["nginx"] = ServerSignature{
		Name:         "nginx",
		TLSVersions:  []uint16{0x0303, 0x0304},
		CipherSuites: []uint16{0xc02f, 0xc030, 0x009f, 0x006b, 0x003d},
		Extensions:   []uint16{0xff, 0x00, 0x0b, 0x0d, 0x17, 0x23},
		ALPN:         []string{"h2", "http/1.1"},
	}

	db.signatures["apache"] = ServerSignature{
		Name:         "apache",
		TLSVersions:  []uint16{0x0303, 0x0304},
		CipherSuites: []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030},
		Extensions:   []uint16{0xff, 0x00, 0x0b, 0x0d, 0x17, 0x23},
		ALPN:         []string{"h2", "http/1.1"},
	}

	db.signatures["cloudflare"] = ServerSignature{
		Name:         "cloudflare",
		TLSVersions:  []uint16{0x0303, 0x0304},
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions:   []uint16{0xff, 0x00, 0x0b, 0x0d, 0x17, 0x23, 0x001d},
		ALPN:         []string{"h3", "h3-29", "h2", "http/1.1"},
	}

	db.signatures["aws-alb"] = ServerSignature{
		Name:         "aws-alb",
		TLSVersions:  []uint16{0x0303, 0x0304},
		CipherSuites: []uint16{0xc02f, 0xc030, 0x009f, 0x002f, 0x0035},
		Extensions:   []uint16{0xff, 0x00, 0x0b, 0x0d, 0x17},
		ALPN:         []string{"h2", "http/1.1"},
	}
}

func (db *ServerSignatureDatabase) Register(sig ServerSignature) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.signatures[sig.Name] = sig
}

func (db *ServerSignatureDatabase) Identify(fp *ServerTLSFingerprint) (string, float64) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var bestMatch string
	var bestScore float64

	for name, sig := range db.signatures {
		score := calculateServerMatchScore(fp, &sig)
		if score > bestScore {
			bestScore = score
			bestMatch = name
		}
	}

	return bestMatch, bestScore
}

func calculateServerMatchScore(fp *ServerTLSFingerprint, sig *ServerSignature) float64 {
	var score float64
	var total float64

	total += 1
	if containsUint16(fp.TLSVersion, sig.TLSVersions) {
		score += 1
	}

	total += 1
	if containsUint16(fp.CipherSuite, sig.CipherSuites) {
		score += 1
	}

	total += 1
	if containsUint16s(fp.Extensions, sig.Extensions) {
		score += 1
	}

	total += 1
	if containsString(fp.ALPN, sig.ALPN) {
		score += 1
	}

	return score / total
}

func containsUint16(haystack uint16, needles []uint16) bool {
	for _, n := range needles {
		if haystack == n {
			return true
		}
	}
	return false
}

func containsUint16s(haystack, needles []uint16) bool {
	if len(needles) == 0 {
		return true
	}
	count := 0
	for _, n := range needles {
		for _, h := range haystack {
			if h == n {
				count++
				break
			}
		}
	}
	return count >= len(needles)/2
}

func containsString(haystack, needles []string) bool {
	for _, n := range needles {
		for _, h := range haystack {
			if h == n {
				return true
			}
		}
	}
	return false
}

type ServerHelloCollector struct {
	mu           sync.RWMutex
	serverHellos map[string]*ServerHelloInfo
	maxSize      int
}

func NewServerHelloCollector(maxSize int) *ServerHelloCollector {
	if maxSize == 0 {
		maxSize = 1000
	}
	return &ServerHelloCollector{
		serverHellos: make(map[string]*ServerHelloInfo),
		maxSize:      maxSize,
	}
}

func (c *ServerHelloCollector) Record(traceID string, sh *ServerHelloInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.serverHellos) >= c.maxSize {
		var oldest string
		for k := range c.serverHellos {
			oldest = k
			break
		}
		delete(c.serverHellos, oldest)
	}

	c.serverHellos[traceID] = sh
}

func (c *ServerHelloCollector) Get(traceID string) *ServerHelloInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverHellos[traceID]
}

func (c *ServerHelloCollector) GetAll() []*ServerHelloInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*ServerHelloInfo, 0, len(c.serverHellos))
	for _, sh := range c.serverHellos {
		result = append(result, sh)
	}
	return result
}

type ServerFingerprintExporter struct {
	analyzer *ServerFingerprintAnalyzer
	db       *ServerSignatureDatabase
}

func NewServerFingerprintExporter(analyzer *ServerFingerprintAnalyzer) *ServerFingerprintExporter {
	return &ServerFingerprintExporter{
		analyzer: analyzer,
		db:       NewServerSignatureDatabase(),
	}
}

func (e *ServerFingerprintExporter) ExportSummary() ServerExportSummary {
	stats := e.analyzer.GetStats()
	obs := e.analyzer.GetObservations()

	var cipherDistribution []CipherCount
	cipherCounts := make(map[string]int)
	for _, o := range obs {
		cipherCounts[fmt.Sprintf("0x%04x", o.CipherSuite)]++
	}
	for c, count := range cipherCounts {
		cipherDistribution = append(cipherDistribution, CipherCount{Cipher: c, Count: count})
	}
	sort.Slice(cipherDistribution, func(i, j int) bool {
		return cipherDistribution[i].Count > cipherDistribution[j].Count
	})

	return ServerExportSummary{
		TotalConnections:    stats.TotalConnections,
		TLSVersionBreakdown: stats.ByTLSVersion,
		CipherDistribution:  cipherDistribution[:minInt(10, len(cipherDistribution))],
		ALPNBreakdown:       stats.ByALPN,
	}
}

type ServerExportSummary struct {
	TotalConnections    int64
	TLSVersionBreakdown map[string]int64
	CipherDistribution  []CipherCount
	ALPNBreakdown       map[string]int64
}

type CipherCount struct {
	Cipher string
	Count  int
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type ServerPreferenceAnalyzer struct {
	mu            sync.RWMutex
	clientHello   *ClientHelloInfo
	serverHello   *ServerHelloInfo
	clientCiphers []uint16
	serverCiphers []uint16
}

func NewServerPreferenceAnalyzer() *ServerPreferenceAnalyzer {
	return &ServerPreferenceAnalyzer{
		clientCiphers: make([]uint16, 0),
		serverCiphers: make([]uint16, 0),
	}
}

func (a *ServerPreferenceAnalyzer) RecordClientHello(ch *ClientHelloInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clientHello = ch
	a.clientCiphers = ch.CipherSuites
}

func (a *ServerPreferenceAnalyzer) RecordServerHello(sh *ServerHelloInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.serverHello = sh
	a.serverCiphers = append(a.serverCiphers, sh.CipherSuite)
}

func (a *ServerPreferenceAnalyzer) GetServerPreference() string {
	if len(a.clientCiphers) == 0 || a.serverHello == nil {
		return "unknown"
	}

	for _, clientPref := range a.clientCiphers {
		if clientPref == a.serverHello.CipherSuite {
			return "client"
		}
	}

	return "server"
}

func (a *ServerPreferenceAnalyzer) GetPreferenceOrder() int {
	if a.serverHello == nil {
		return -1
	}

	serverCipher := a.serverHello.CipherSuite
	for i, c := range a.clientCiphers {
		if c == serverCipher {
			return i
		}
	}

	return -1
}

func (a *ServerPreferenceAnalyzer) IsResumed() bool {
	if a.clientHello == nil || a.serverHello == nil {
		return false
	}

	if len(a.clientHello.SessionID) > 0 && len(a.serverHello.SessionID) > 0 {
		if string(a.clientHello.SessionID) == string(a.serverHello.SessionID) {
			return true
		}
	}

	return false
}
