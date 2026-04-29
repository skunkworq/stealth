package index

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteVecIndex struct {
	mu    sync.RWMutex
	db    *sql.DB
	dim   int
	path  string
	stats IndexStats
}

func NewSQLiteVecIndex(path string, dim int) (*SQLiteVecIndex, error) {
	db, err := sql.Open("sqlite3", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vectors (
			id TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			summary TEXT,
			embedding BLOB NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_vectors_url ON vectors(url);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vector_metadata (
			id TEXT PRIMARY KEY,
			key TEXT NOT NULL,
			value TEXT,
			FOREIGN KEY (id) REFERENCES vectors(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_metadata_key ON vector_metadata(key);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create metadata table: %w", err)
	}

	return &SQLiteVecIndex{
		db:    db,
		dim:   dim,
		path:  path,
		stats: IndexStats{},
	}, nil
}

func (s *SQLiteVecIndex) Add(nodeID, url string, embedding []float32, summary string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	embBytes := floatsToBytes(embedding)

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO vectors (id, url, summary, embedding, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, nodeID, url, summary, embBytes, time.Now().Unix())

	if err == nil {
		s.stats.TotalNodes++
		if s.stats.UniqueURLs == 0 {
			s.stats.UniqueURLs = 1
		} else {
			var urlCount int
			s.db.QueryRow("SELECT COUNT(DISTINCT url) FROM vectors").Scan(&urlCount)
			s.stats.UniqueURLs = urlCount
		}
	}

	return err
}

func (s *SQLiteVecIndex) Search(ctx context.Context, queryEmbedding []float32, k int) ([]SearchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, "SELECT id, url, summary, embedding FROM vectors")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type scored struct {
		id      string
		url     string
		summary string
		score   float32
	}

	candidates := make([]scored, 0, 1000)

	for rows.Next() {
		var id, url, summary string
		var embBytes []byte

		if err := rows.Scan(&id, &url, &summary, &embBytes); err != nil {
			continue
		}

		embedding := bytesToFloats(embBytes)
		if len(embedding) != len(queryEmbedding) {
			continue
		}

		score := cosineSimilarity(queryEmbedding, embedding)
		candidates = append(candidates, scored{
			id:      id,
			url:     url,
			summary: summary,
			score:   score,
		})
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
			NodeID:  candidates[i].id,
			URL:     candidates[i].url,
			Content: candidates[i].summary,
			Score:   candidates[i].score,
		}
	}

	return results, nil
}

func (s *SQLiteVecIndex) SearchByURL(ctx context.Context, url string, queryEmbedding []float32, k int) ([]SearchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, url, summary, embedding FROM vectors WHERE url = ?",
		url,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type scored struct {
		id      string
		url     string
		summary string
		score   float32
	}

	var candidates []scored

	for rows.Next() {
		var id, url, summary string
		var embBytes []byte

		if err := rows.Scan(&id, &url, &summary, &embBytes); err != nil {
			continue
		}

		embedding := bytesToFloats(embBytes)
		score := cosineSimilarity(queryEmbedding, embedding)
		candidates = append(candidates, scored{
			id:      id,
			url:     url,
			summary: summary,
			score:   score,
		})
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
			NodeID:  candidates[i].id,
			URL:     candidates[i].url,
			Content: candidates[i].summary,
			Score:   candidates[i].score,
		}
	}

	return results, nil
}

func (s *SQLiteVecIndex) GetByURL(url string) ([]SearchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT id, url, summary, embedding FROM vectors WHERE url = ?",
		url,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SearchResult

	for rows.Next() {
		var id, url, summary string
		var embBytes []byte

		if err := rows.Scan(&id, &url, &summary, &embBytes); err != nil {
			continue
		}

		embedding := bytesToFloats(embBytes)
		results = append(results, SearchResult{
			NodeID:    id,
			URL:       url,
			Content:   summary,
			Embedding: embedding,
		})
	}

	return results, nil
}

func (s *SQLiteVecIndex) MultiHopSearch(ctx context.Context, queryEmbedding []float32, maxHops, k int) ([]MultiHopResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	visited := make(map[string]bool)
	results := make([]MultiHopResult, 0, maxHops*k)

	currentHop := queryEmbedding
	var currentURL string

	for hop := 0; hop < maxHops; hop++ {
		var candidates []SearchResult
		var err error

		if currentURL == "" {
			candidates, err = s.Search(ctx, currentHop, k)
		} else {
			candidates, err = s.SearchByURL(ctx, currentURL, currentHop, k)
		}

		if err != nil || len(candidates) == 0 {
			break
		}

		for _, c := range candidates {
			if visited[c.NodeID] {
				continue
			}
			visited[c.NodeID] = true

			results = append(results, MultiHopResult{
				Hop:    hop,
				Result: c,
			})

			if hop < maxHops-1 && len(c.Embedding) > 0 {
				currentHop = c.Embedding
				currentURL = c.URL
			}
		}
	}

	return results, nil
}

type MultiHopResult struct {
	Hop    int          `json:"hop"`
	Result SearchResult `json:"result"`
}

func (s *SQLiteVecIndex) Stats() IndexStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count, urlCount int
	s.db.QueryRow("SELECT COUNT(*) FROM vectors").Scan(&count)
	s.db.QueryRow("SELECT COUNT(DISTINCT url) FROM vectors").Scan(&urlCount)

	return IndexStats{
		TotalNodes: count,
		UniqueURLs: urlCount,
	}
}

func (s *SQLiteVecIndex) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *SQLiteVecIndex) Path() string {
	return s.path
}

func floatsToBytes(floats []float32) []byte {
	buf := make([]byte, len(floats)*4)
	for i, f := range floats {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

func bytesToFloats(buf []byte) []float32 {
	floats := make([]float32, len(buf)/4)
	for i := range floats {
		bits := binary.LittleEndian.Uint32(buf[i*4:])
		floats[i] = math.Float32frombits(bits)
	}
	return floats
}
