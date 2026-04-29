package tlsfprint

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"
)

type TLSObservation struct {
	Timestamp    time.Time `json:"timestamp"`
	ConnectionID string    `json:"connection_id"`
	RemoteAddr   string    `json:"remote_addr"`

	TLSVersion  uint16 `json:"tls_version"`
	CipherSuite uint16 `json:"cipher_suite"`
	ServerName  string `json:"server_name"`
	ALPN        string `json:"alpn"`

	CipherOrder    []uint16 `json:"cipher_order"`
	ExtensionOrder []uint16 `json:"extension_order"`
	GREASEFound    bool     `json:"grease_found"`
	GREASECount    int      `json:"grease_count"`

	KeyShareGroups []uint16 `json:"key_share_groups"`
	SignatureAlgs  []uint16 `json:"signature_algs"`
	SupportedVers  []uint16 `json:"supported_versions"`

	RawClientHello []byte `json:"raw_client_hello,omitempty"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (o *TLSObservation) ToJA3() string {
	var ciphers []string
	for _, c := range o.CipherOrder {
		ciphers = append(ciphers, fmt.Sprintf("%04x", c))
	}
	var exts []string
	for _, e := range o.ExtensionOrder {
		exts = append(exts, fmt.Sprintf("%d", e))
	}
	return fmt.Sprintf("%04x,%s,%s", o.TLSVersion, joinStrings(ciphers, "-"), joinStrings(exts, "-"))
}

func (o *TLSObservation) ToJA4() string {
	ver := "00"
	if o.TLSVersion >= 0x0304 {
		ver = "13"
	} else if o.TLSVersion >= 0x0303 {
		ver = "12"
	}

	alpnStr := "_"
	if o.ALPN == "h2" {
		alpnStr = "h2"
	}

	greaseSuffix := ""
	if o.GREASEFound {
		greaseSuffix = "d"
	}

	return fmt.Sprintf("t%s%s_%04x%s", ver, alpnStr, o.CipherSuite, greaseSuffix)
}

func joinStrings(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += sep + s[i]
	}
	return result
}

type TLSObserver struct {
	mu           sync.RWMutex
	observations []TLSObservation
	config       *ObserverConfig
	stats        *ObserverStats
	seenJA4      map[string]bool
}

type ObserverConfig struct {
	MaxObservations int
	Enabled         bool
	ExportFormat    string
	OutputPath      string
	IncludeRaw      bool
}

type ObserverStats struct {
	TotalObservations int64            `json:"total_observations"`
	UniqueJA4         int64            `json:"unique_ja4"`
	UniqueJA3         int64            `json:"unique_ja3"`
	AvgHandshakeMs    float64          `json:"avg_handshake_ms"`
	GREASEFrequency   float64          `json:"grease_frequency"`
	ByTLSVersion      map[string]int64 `json:"by_tls_version"`
	ByCipherSuite     map[string]int64 `json:"by_cipher_suite"`
}

func NewTLSObserver(config *ObserverConfig) *TLSObserver {
	if config == nil {
		config = &ObserverConfig{
			Enabled:         true,
			MaxObservations: 10000,
		}
	}
	return &TLSObserver{
		config:       config,
		observations: make([]TLSObservation, 0),
		stats: &ObserverStats{
			ByTLSVersion:  make(map[string]int64),
			ByCipherSuite: make(map[string]int64),
		},
		seenJA4: make(map[string]bool),
	}
}

func (o *TLSObserver) Record(obs *TLSObservation) {
	if !o.config.Enabled {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.observations = append(o.observations, *obs)
	if o.config.MaxObservations > 0 && len(o.observations) > o.config.MaxObservations {
		o.observations = o.observations[1:]
	}

	o.updateStats(obs)
}

func (o *TLSObserver) updateStats(obs *TLSObservation) {
	o.stats.TotalObservations++

	ja4 := obs.ToJA4()
	if !o.seenJA4[ja4] {
		o.stats.UniqueJA4++
		o.seenJA4[ja4] = true
	}

	if obs.GREASEFound {
		o.stats.GREASEFrequency++
	}
}

func (o *TLSObserver) GetObservations() []TLSObservation {
	o.mu.RLock()
	defer o.mu.RUnlock()
	result := make([]TLSObservation, len(o.observations))
	copy(result, o.observations)
	return result
}

func (o *TLSObserver) GetStats() *ObserverStats {
	o.mu.RLock()
	defer o.mu.RUnlock()
	stats := &ObserverStats{
		TotalObservations: o.stats.TotalObservations,
		UniqueJA4:         o.stats.UniqueJA4,
		UniqueJA3:         o.stats.UniqueJA3,
		AvgHandshakeMs:    o.stats.AvgHandshakeMs,
		GREASEFrequency:   o.stats.GREASEFrequency,
		ByTLSVersion:      make(map[string]int64),
		ByCipherSuite:     make(map[string]int64),
	}
	for k, v := range o.stats.ByTLSVersion {
		stats.ByTLSVersion[k] = v
	}
	for k, v := range o.stats.ByCipherSuite {
		stats.ByCipherSuite[k] = v
	}
	if stats.TotalObservations > 0 {
		stats.GREASEFrequency = stats.GREASEFrequency / float64(stats.TotalObservations)
	}
	return stats
}

func (o *TLSObserver) ExportJSON(path string) error {
	obs := o.GetObservations()
	data, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (o *TLSObserver) ExportCSV(path string) error {
	obs := o.GetObservations()
	file, err := os.Create(path) //nolint:gosec // Path is controlled by caller
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"timestamp", "connection_id", "remote_addr",
		"tls_version", "cipher_suite", "server_name", "alpn",
		"cipher_order", "extension_order", "grease_found", "grease_count",
		"key_share_groups", "signature_algs", "supported_versions",
	}
	_ = writer.Write(header)

	for _, ob := range obs {
		row := []string{
			ob.Timestamp.Format(time.RFC3339),
			ob.ConnectionID,
			ob.RemoteAddr,
			fmt.Sprintf("%04x", ob.TLSVersion),
			fmt.Sprintf("%04x", ob.CipherSuite),
			ob.ServerName,
			ob.ALPN,
			fmt.Sprintf("%v", ob.CipherOrder),
			fmt.Sprintf("%v", ob.ExtensionOrder),
			fmt.Sprintf("%t", ob.GREASEFound),
			fmt.Sprintf("%d", ob.GREASECount),
			fmt.Sprintf("%v", ob.KeyShareGroups),
			fmt.Sprintf("%v", ob.SignatureAlgs),
			fmt.Sprintf("%v", ob.SupportedVers),
		}
		_ = writer.Write(row)
	}

	return nil
}

type TLSObservationVector struct {
	CipherCount       int
	ExtensionCount    int
	KeyShareCount     int
	SignatureAlgCount int
	GREASECount       int
	TLSVersion        int
	ALPNHTTP2         bool
	HasGREASE         bool
	HasKeyShare       bool
	HasSignatureAlgs  bool
	HasSupportedVers  bool
	CipherOrder       []int
	ExtensionOrder    []int
	PositionEntropy   float64
}

func (o *TLSObservation) ToVector() *TLSObservationVector {
	v := &TLSObservationVector{
		CipherCount:       len(o.CipherOrder),
		ExtensionCount:    len(o.ExtensionOrder),
		KeyShareCount:     len(o.KeyShareGroups),
		SignatureAlgCount: len(o.SignatureAlgs),
		GREASECount:       0,
		TLSVersion:        int(o.TLSVersion),
		ALPNHTTP2:         o.ALPN == "h2",
		HasGREASE:         o.GREASEFound,
		HasKeyShare:       len(o.KeyShareGroups) > 0,
		HasSignatureAlgs:  len(o.SignatureAlgs) > 0,
		HasSupportedVers:  len(o.SupportedVers) > 0,
		CipherOrder:       orderToInts(o.CipherOrder),
		ExtensionOrder:    orderToInts(o.ExtensionOrder),
		PositionEntropy:   calculateEntropy(o.CipherOrder, o.ExtensionOrder),
	}
	if o.GREASEFound {
		v.GREASECount = 1
	}
	return v
}

func orderToInts(order []uint16) []int {
	result := make([]int, len(order))
	for i, v := range order {
		result[i] = int(v)
	}
	return result
}

func calculateEntropy(ciphers, extensions []uint16) float64 {
	var all []uint16
	all = append(all, ciphers...)
	all = append(all, extensions...)

	if len(all) == 0 {
		return 0
	}

	freq := make(map[uint16]int)
	for _, v := range all {
		freq[v]++
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(len(all))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

type MLTrainingData struct {
	Features        [][]float64       `json:"features"`
	Labels          []string          `json:"labels"`
	JA4Fingerprints []string          `json:"ja4_fingerprints"`
	Metadata        *TrainingMetadata `json:"metadata"`
}

type TrainingMetadata struct {
	TotalSamples   int            `json:"total_samples"`
	UniqueBrowsers int            `json:"unique_browsers"`
	FeatureCount   int            `json:"feature_count"`
	BrowserCounts  map[string]int `json:"browser_counts"`
}

func (o *TLSObserver) GenerateTrainingData() *MLTrainingData {
	obs := o.GetObservations()

	features := make([][]float64, len(obs))
	labels := make([]string, len(obs))
	ja4s := make([]string, len(obs))

	browserCounts := make(map[string]int)

	for i, ob := range obs {
		v := ob.ToVector()
		features[i] = vectorToFeatures(v)
		labels[i] = ""
		ja4s[i] = ob.ToJA4()

		if ob.Metadata != nil {
			if b, ok := ob.Metadata["browser"].(string); ok {
				labels[i] = b
				browserCounts[b]++
			}
		}
	}

	return &MLTrainingData{
		Features:        features,
		Labels:          labels,
		JA4Fingerprints: ja4s,
		Metadata: &TrainingMetadata{
			TotalSamples:  len(obs),
			FeatureCount:  len(features[0]),
			BrowserCounts: browserCounts,
		},
	}
}

func vectorToFeatures(v *TLSObservationVector) []float64 {
	return []float64{
		float64(v.CipherCount),
		float64(v.ExtensionCount),
		float64(v.KeyShareCount),
		float64(v.SignatureAlgCount),
		float64(v.GREASECount),
		float64(v.TLSVersion),
		obsBoolToFloat(v.ALPNHTTP2),
		obsBoolToFloat(v.HasGREASE),
		obsBoolToFloat(v.HasKeyShare),
		obsBoolToFloat(v.HasSignatureAlgs),
		obsBoolToFloat(v.HasSupportedVers),
		v.PositionEntropy,
	}
}

func obsBoolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func (d *MLTrainingData) ExportJSON(path string) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (d *MLTrainingData) ExportArff(path, relationName string) error {
	file, err := os.Create(path) //nolint:gosec // Path is controlled by caller
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	_, _ = fmt.Fprintf(file, "@relation %s\n\n", relationName)

	featureNames := []string{
		"cipher_count", "extension_count", "keyshare_count", "sigalg_count",
		"grease_count", "tls_version", "alpn_http2", "has_grease",
		"has_keyshare", "has_sigalg", "has_supported_vers", "position_entropy",
	}

	for _, name := range featureNames {
		_, _ = fmt.Fprintf(file, "@attribute %s numeric\n", name)
	}

	browsers := uniqueStrings(d.Labels)
	_, _ = fmt.Fprintf(file, "@attribute browser {%s}\n\n", joinStrings(browsers, ","))

	_, _ = fmt.Fprintln(file, "@data")
	for i, f := range d.Features {
		row := make([]string, len(f)+1)
		for j, v := range f {
			row[j] = fmt.Sprintf("%.4f", v)
		}
		row[len(f)] = d.Labels[i]
		_, _ = fmt.Fprintln(file, joinStrings(row, ","))
	}

	return nil
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, str := range s {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

type FingerprintComparator struct {
	observed *TLSObservation
	expected *TLSObservation
	diffs    []Difference
}

type Difference struct {
	Field    string  `json:"field"`
	Observed string  `json:"observed"`
	Expected string  `json:"expected"`
	Score    float64 `json:"score"`
}

func NewFingerprintComparator(observed, expected *TLSObservation) *FingerprintComparator {
	return &FingerprintComparator{
		observed: observed,
		expected: expected,
		diffs:    make([]Difference, 0),
	}
}

func (c *FingerprintComparator) Compare() []Difference {
	c.compareInts("TLS Version", c.observed.TLSVersion, c.expected.TLSVersion)
	c.compareInts("Cipher Suite", c.observed.CipherSuite, c.expected.CipherSuite)
	c.compareStrings("ALPN", c.observed.ALPN, c.expected.ALPN)
	c.compareSlices("Cipher Order", c.observed.CipherOrder, c.expected.CipherOrder)
	c.compareSlices("Extension Order", c.observed.ExtensionOrder, c.expected.ExtensionOrder)
	c.compareBools("GREASE Found", c.observed.GREASEFound, c.expected.GREASEFound)

	return c.diffs
}

func (c *FingerprintComparator) compareInts(name string, obs, exp uint16) {
	if obs != exp {
		c.diffs = append(c.diffs, Difference{
			Field:    name,
			Observed: fmt.Sprintf("%d", obs),
			Expected: fmt.Sprintf("%d", exp),
			Score:    1.0,
		})
	}
}

func (c *FingerprintComparator) compareStrings(name, obs, exp string) {
	if obs != exp {
		c.diffs = append(c.diffs, Difference{
			Field:    name,
			Observed: obs,
			Expected: exp,
			Score:    1.0,
		})
	}
}

func (c *FingerprintComparator) compareBools(name string, obs, exp bool) {
	if obs != exp {
		c.diffs = append(c.diffs, Difference{
			Field:    name,
			Observed: fmt.Sprintf("%t", obs),
			Expected: fmt.Sprintf("%t", exp),
			Score:    1.0,
		})
	}
}

func (c *FingerprintComparator) compareSlices(name string, obs, exp []uint16) {
	obsStr := fmt.Sprintf("%v", obs)
	expStr := fmt.Sprintf("%v", exp)
	if obsStr != expStr {
		score := 1.0
		if len(obs) == len(exp) {
			matches := 0
			for i := range obs {
				if obs[i] == exp[i] {
					matches++
				}
			}
			score = 1.0 - float64(matches)/float64(len(obs))
		}

		c.diffs = append(c.diffs, Difference{
			Field:    name,
			Observed: obsStr,
			Expected: expStr,
			Score:    score,
		})
	}
}

func (c *FingerprintComparator) TotalScore() float64 {
	var total float64
	for _, d := range c.diffs {
		total += d.Score
	}
	if len(c.diffs) > 0 {
		total /= float64(len(c.diffs))
	}
	return total
}

type ExtensionPermutator struct {
	rng *rand.Rand
}

func NewExtensionPermutator(seed int64) *ExtensionPermutator {
	return &ExtensionPermutator{
		rng: rand.New(rand.NewSource(seed)), //nolint:gosec // G404: math/rand is sufficient for extension permutation
	}
}

func (p *ExtensionPermutator) PermuteChrome(extensions []uint16) []uint16 {
	greaseExts := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a}

	var chromeExts, grease []uint16
	for _, e := range extensions {
		isGREASE := false
		for _, g := range greaseExts {
			if e >= g && e <= g+0x0f {
				isGREASE = true
				break
			}
		}
		if isGREASE {
			grease = append(grease, e)
		} else {
			chromeExts = append(chromeExts, e)
		}
	}

	p.rng.Shuffle(len(chromeExts), func(i, j int) {
		chromeExts[i], chromeExts[j] = chromeExts[j], chromeExts[i]
	})

	result := append(grease, chromeExts...)
	return result
}

func (p *ExtensionPermutator) PermuteFirefox(extensions []uint16) []uint16 {
	p.rng.Shuffle(len(extensions), func(i, j int) {
		extensions[i], extensions[j] = extensions[j], extensions[i]
	})
	return extensions
}

type TimingAnalyzer struct {
	observations []time.Duration
}

func NewTimingAnalyzer() *TimingAnalyzer {
	return &TimingAnalyzer{
		observations: make([]time.Duration, 0),
	}
}

func (t *TimingAnalyzer) Record(d time.Duration) {
	t.observations = append(t.observations, d)
}

func (t *TimingAnalyzer) GetStats() *TimingStats {
	if len(t.observations) == 0 {
		return &TimingStats{}
	}

	var sum time.Duration
	minVal, maxVal := t.observations[0], t.observations[0]
	sorted := make([]time.Duration, len(t.observations))
	copy(sorted, t.observations)

	for _, d := range t.observations {
		sum += d
		if d < minVal {
			minVal = d
		}
		if d > maxVal {
			maxVal = d
		}
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	var median, p95, p99 time.Duration
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		median = (sorted[mid-1] + sorted[mid]) / 2
	} else {
		median = sorted[mid]
	}

	if len(sorted) >= 20 {
		p95 = sorted[len(sorted)*95/100]
		p99 = sorted[len(sorted)*99/100]
	}

	return &TimingStats{
		Count:  len(t.observations),
		Mean:   sum / time.Duration(len(t.observations)),
		Median: median,
		Min:    minVal,
		Max:    maxVal,
		P95:    p95,
		P99:    p99,
	}
}

type TimingStats struct {
	Count  int           `json:"count"`
	Mean   time.Duration `json:"mean"`
	Median time.Duration `json:"median"`
	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	P95    time.Duration `json:"p95"`
	P99    time.Duration `json:"p99"`
}

type HandshakeCapture struct {
	Observation *TLSObservation
	RawData     []byte
	ParseError  error
}

type CaptureStore struct {
	mu       sync.RWMutex
	captures map[string]*HandshakeCapture
	maxSize  int
}

func NewCaptureStore(maxSize int) *CaptureStore {
	if maxSize == 0 {
		maxSize = 1000
	}
	return &CaptureStore{
		captures: make(map[string]*HandshakeCapture),
		maxSize:  maxSize,
	}
}

func (s *CaptureStore) Store(id string, capture *HandshakeCapture) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.captures) >= s.maxSize {
		var oldest string
		var oldestTime time.Time
		for k, v := range s.captures {
			if oldestTime.IsZero() || v.Observation.Timestamp.Before(oldestTime) {
				oldest = k
				oldestTime = v.Observation.Timestamp
			}
		}
		delete(s.captures, oldest)
	}

	s.captures[id] = capture
}

func (s *CaptureStore) Get(id string) *HandshakeCapture {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.captures[id]
}

func (s *CaptureStore) GetAll() []*HandshakeCapture {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*HandshakeCapture, 0, len(s.captures))
	for _, c := range s.captures {
		result = append(result, c)
	}
	return result
}

func (s *CaptureStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captures = make(map[string]*HandshakeCapture)
}
