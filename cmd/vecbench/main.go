package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type VectorBackend interface {
	Name() string
	Insert(id string, embedding []float32, metadata map[string]string) error
	Search(query []float32, k int) ([]SearchResult, error)
	Stats() BackendStats
	Close() error
}

type SearchResult struct {
	ID       string
	Score    float32
	Metadata map[string]string
}

type BackendStats struct {
	TotalVectors int
	Dimension     int
	IndexSize    int64
}

type InMemoryIndex struct {
	vectors  []*vectorEntry
	dim      int
	mu       sync.RWMutex
}

type vectorEntry struct {
	id       string
	vector   []float32
	metadata map[string]string
}

func NewInMemoryIndex(dim int) *InMemoryIndex {
	return &InMemoryIndex{
		vectors: make([]*vectorEntry, 0),
		dim:     dim,
	}
}

func (idx *InMemoryIndex) Name() string { return "InMemory" }

func (idx *InMemoryIndex) Insert(id string, embedding []float32, metadata map[string]string) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.vectors = append(idx.vectors, &vectorEntry{
		id:       id,
		vector:   embedding,
		metadata: metadata,
	})
	return nil
}

func (idx *InMemoryIndex) Search(query []float32, k int) ([]SearchResult, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	type scored struct {
		entry *vectorEntry
		score float32
	}

	scores := make([]scored, 0, len(idx.vectors))
	for _, entry := range idx.vectors {
		score := cosineSim(query, entry.vector)
		scores = append(scores, scored{entry: entry, score: score})
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	if k > len(scores) {
		k = len(scores)
	}

	results := make([]SearchResult, k)
	for i := 0; i < k; i++ {
		results[i] = SearchResult{
			ID:       scores[i].entry.id,
			Score:    scores[i].score,
			Metadata: scores[i].entry.metadata,
		}
	}
	return results, nil
}

func (idx *InMemoryIndex) Stats() BackendStats {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return BackendStats{
		TotalVectors: len(idx.vectors),
		Dimension:    idx.dim,
		IndexSize:    int64(len(idx.vectors) * idx.dim * 4),
	}
}

func (idx *InMemoryIndex) Close() error { return nil }

type SQLiteBackend struct {
	db   *sql.DB
	dim  int
	path string
}

func NewSQLiteBackend(path string, dim int) (*SQLiteBackend, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vectors (
			id TEXT PRIMARY KEY,
			embedding BLOB NOT NULL,
			metadata TEXT,
			created_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_vectors_created ON vectors(created_at);
	`)
	if err != nil {
		return nil, err
	}

	return &SQLiteBackend{db: db, dim: dim, path: path}, nil
}

func (s *SQLiteBackend) Name() string { return "SQLite" }

func (s *SQLiteBackend) Insert(id string, embedding []float32, metadata map[string]string) error {
	embBytes := floatsToBytes(embedding)
	metaJSON, _ := json.Marshal(metadata)

	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO vectors (id, embedding, metadata, created_at) VALUES (?, ?, ?, ?)",
		id, embBytes, metaJSON, time.Now().Unix(),
	)
	return err
}

func (s *SQLiteBackend) Search(query []float32, k int) ([]SearchResult, error) {
	rows, err := s.db.Query("SELECT id, embedding, metadata FROM vectors")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type scored struct {
		id       string
		score    float32
		metadata map[string]string
	}

	var candidates []scored
	for rows.Next() {
		var id string
		var embBytes []byte
		var metaBytes []byte
		if err := rows.Scan(&id, &embBytes, &metaBytes); err != nil {
			continue
		}

		embedding := bytesToFloats(embBytes)
		score := cosineSim(query, embedding)

		var metadata map[string]string
		json.Unmarshal(metaBytes, &metadata)

		candidates = append(candidates, scored{id: id, score: score, metadata: metadata})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	if k > len(candidates) {
		k = len(candidates)
	}

	results := make([]SearchResult, k)
	for i := 0; i < k; i++ {
		results[i] = SearchResult{
			ID:       candidates[i].id,
			Score:    candidates[i].score,
			Metadata: candidates[i].metadata,
		}
	}
	return results, nil
}

func (s *SQLiteBackend) Stats() BackendStats {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM vectors").Scan(&count)

	var size int64
	s.db.QueryRow("SELECT SUM(LENGTH(embedding) + LENGTH(metadata)) FROM vectors").Scan(&size)

	return BackendStats{
		TotalVectors: count,
		Dimension:    s.dim,
		IndexSize:    size,
	}
}

func (s *SQLiteBackend) Close() error {
	return s.db.Close()
}

func floatsToBytes(floats []float32) []byte {
	bytes := make([]byte, len(floats)*4)
	for i, f := range floats {
		bits := math.Float32bits(f)
		bytes[i*4] = byte(bits)
		bytes[i*4+1] = byte(bits >> 8)
		bytes[i*4+2] = byte(bits >> 16)
		bytes[i*4+3] = byte(bits >> 24)
	}
	return bytes
}

func bytesToFloats(bytes []byte) []float32 {
	floats := make([]float32, len(bytes)/4)
	for i := range floats {
		bits := uint32(bytes[i*4]) | uint32(bytes[i*4+1])<<8 | uint32(bytes[i*4+2])<<16 | uint32(bytes[i*4+3])<<24
		floats[i] = math.Float32frombits(bits)
	}
	return floats
}

func cosineSim(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float32
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (sqrt32(normA) * sqrt32(normB))
}

func sqrt32(x float32) float32 {
	return float32(math.Sqrt(float64(x)))
}

type BenchResult struct {
	Backend      string
	VectorCount  int
	Dimension    int
	InsertTime   time.Duration
	InsertQPS    float64
	SearchTime   time.Duration
	SearchQPS    float64
	MemorySize   int64
	LatencyP50   time.Duration
	LatencyP99   time.Duration
}

func runBenchmark(backend VectorBackend, numVectors, dim, queries int) (*BenchResult, error) {
	fmt.Printf("\n[%s] Generating %d vectors (dim=%d)...\n", backend.Name(), numVectors, dim)

	vectors := make([][]float32, numVectors)
	for i := range vectors {
		vectors[i] = randVector(dim)
	}

	queryVectors := make([][]float32, queries)
	for i := range queryVectors {
		queryVectors[i] = randVector(dim)
	}

	fmt.Printf("[%s] Inserting %d vectors...\n", backend.Name(), numVectors)
	insertStart := time.Now()
	for i, v := range vectors {
		id := fmt.Sprintf("vec_%d", i)
		if err := backend.Insert(id, v, map[string]string{"index": fmt.Sprintf("%d", i)}); err != nil {
			return nil, err
		}
		if i > 0 && i%10000 == 0 {
			fmt.Printf("  %d/%d inserted\n", i, numVectors)
		}
	}
	insertDuration := time.Since(insertStart)

	fmt.Printf("[%s] Running %d searches (k=10)...\n", backend.Name(), queries)
	latencies := make([]time.Duration, queries)
	searchStart := time.Now()
	for i, q := range queryVectors {
		start := time.Now()
		_, err := backend.Search(q, 10)
		if err != nil {
			return nil, err
		}
		latencies[i] = time.Since(start)
	}
	searchDuration := time.Since(searchStart)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	stats := backend.Stats()

	result := &BenchResult{
		Backend:     backend.Name(),
		VectorCount: numVectors,
		Dimension:   dim,
		InsertTime:  insertDuration,
		InsertQPS:   float64(numVectors) / insertDuration.Seconds(),
		SearchTime:  searchDuration,
		SearchQPS:   float64(queries) / searchDuration.Seconds(),
		MemorySize:  stats.IndexSize,
		LatencyP50:  latencies[queries/2],
		LatencyP99:  latencies[int(float64(queries)*0.99)],
	}

	return result, nil
}

func (r *BenchResult) String() string {
	return fmt.Sprintf(
		"[%s] Vectors: %d | Dim: %d | Insert: %d vectors/s | Search: %d queries/s | P50: %v | P99: %v | Size: %.2f MB",
		r.Backend, r.VectorCount, r.Dimension,
		int64(r.InsertQPS), int64(r.SearchQPS),
		r.LatencyP50, r.LatencyP99,
		float64(r.MemorySize)/1024/1024,
	)
}

func randVector(dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rand.Float32()*2 - 1
	}
	return v
}

func main() {

	sizes := []int{1000, 10000, 50000}
	dim := 384
	queries := 100

	fmt.Println("========================================")
	fmt.Println("Vector Backend Benchmark: InMemory vs SQLite")
	fmt.Println("========================================")

	for _, numVectors := range sizes {
		fmt.Printf("\n--- %d vectors ---\n", numVectors)

		memIndex := NewInMemoryIndex(dim)
		memResult, err := runBenchmark(memIndex, numVectors, dim, queries)
		if err != nil {
			fmt.Printf("Memory index error: %v\n", err)
		} else {
			fmt.Println(memResult.String())
		}
		memIndex.Close()

		tmpFile := fmt.Sprintf("/tmp/vecbench_%d.db", numVectors)
		os.Remove(tmpFile)
		sqliteBack, err := NewSQLiteBackend(tmpFile, dim)
		if err != nil {
			fmt.Printf("SQLite error: %v\n", err)
			continue
		}
		sqliteResult, err := runBenchmark(sqliteBack, numVectors, dim, queries)
		if err != nil {
			fmt.Printf("SQLite error: %v\n", err)
		} else {
			fmt.Println(sqliteResult.String())
		}
		sqliteBack.Close()
		os.Remove(tmpFile)
	}

	fmt.Println("\n========================================")
	fmt.Println("Zvec Reference (from their benchmarks):")
	fmt.Println("  - 10M vectors, 1536 dim: ~1000 QPS")
	fmt.Println("  - latency: 1-5ms P99")
	fmt.Println("  - Uses HNSW index for ANN")
	fmt.Println("========================================")

	fmt.Println("\nNote: SQLite brute-force is O(n) per query.")
	fmt.Println("Zvec uses HNSW for O(log n) approximate search.")
	fmt.Println("For production at scale, consider:")
	fmt.Println("  - Zvec (Python/C++): Best for >1M vectors")
	fmt.Println("  - pgvector: Postgres with HNSW")
	fmt.Println("  - go-vector-index: Pure Go HNSW")
}
