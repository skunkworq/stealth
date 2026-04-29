package semantic

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type CacheStore struct {
	db   *sql.DB
	path string
	mu   sync.RWMutex
}

func NewCacheStore(ctx context.Context, dbPath string) (*CacheStore, error) {
	if dbPath == "" {
		home, _ := os.UserHomeDir()
		dbPath = filepath.Join(home, ".semantic", "cache.db")
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, NewCacheError(fmt.Sprintf("failed to create cache directory: %v", err))
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, NewCacheError(fmt.Sprintf("failed to open database: %v", err))
	}

	store := &CacheStore{db: db, path: dbPath}
	if err := store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *CacheStore) ensureSchema(ctx context.Context) error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS chunk_cache (
			content_hash TEXT PRIMARY KEY,
			node_json TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			accessed_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_chunk_created ON chunk_cache(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_chunk_accessed ON chunk_cache(accessed_at)`,
		`CREATE TABLE IF NOT EXISTS image_descriptions (
			url_hash TEXT PRIMARY KEY,
			description TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS image_queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url_hash TEXT NOT NULL,
			query_embedding BLOB NOT NULL,
			answer TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_image_queries_url ON image_queries(url_hash)`,
	}

	for _, schema := range schemas {
		if _, err := s.db.ExecContext(ctx, schema); err != nil {
			return NewCacheError(fmt.Sprintf("failed to create schema: %v", err))
		}
	}

	return nil
}

func (s *CacheStore) GetChunk(ctx context.Context, contentHash string) (*SemanticNode, error) {
	s.mu.RLock()

	var nodeJSON string
	var createdAt int64

	err := s.db.QueryRowContext(ctx,
		"SELECT node_json, created_at FROM chunk_cache WHERE content_hash = ?",
		contentHash,
	).Scan(&nodeJSON, &createdAt)

	s.mu.RUnlock()

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, NewCacheError(fmt.Sprintf("failed to query chunk: %v", err))
	}

	var node SemanticNode
	if err := decodeJSON(nodeJSON, &node); err != nil {
		return nil, NewCacheError(fmt.Sprintf("failed to decode node: %v", err))
	}

	go func() {
		s.mu.Lock()
		s.db.ExecContext(context.Background(),
			"UPDATE chunk_cache SET accessed_at = ? WHERE content_hash = ?",
			time.Now().Unix(), contentHash,
		)
		s.mu.Unlock()
	}()

	return &node, nil
}

func (s *CacheStore) PutChunk(ctx context.Context, contentHash string, node *SemanticNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeJSON := encodeJSON(node)
	now := time.Now().Unix()

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO chunk_cache (content_hash, node_json, created_at, accessed_at)
		 VALUES (?, ?, ?, ?)`,
		contentHash, nodeJSON, now, now,
	)
	if err != nil {
		return NewCacheError(fmt.Sprintf("failed to store chunk: %v", err))
	}

	return nil
}

func (s *CacheStore) GetImageDescription(ctx context.Context, urlHash string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var description string
	err := s.db.QueryRowContext(ctx,
		"SELECT description FROM image_descriptions WHERE url_hash = ?",
		urlHash,
	).Scan(&description)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", NewCacheError(fmt.Sprintf("failed to query image description: %v", err))
	}

	return description, nil
}

func (s *CacheStore) PutImageDescription(ctx context.Context, urlHash, description string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO image_descriptions (url_hash, description, created_at)
		 VALUES (?, ?, ?)`,
		urlHash, description, time.Now().Unix(),
	)
	if err != nil {
		return NewCacheError(fmt.Sprintf("failed to store image description: %v", err))
	}

	return nil
}

func (s *CacheStore) GetImageQueries(ctx context.Context, urlHash string) ([]struct {
	Embedding []float32
	Answer    string
}, error,
) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT query_embedding, answer FROM image_queries WHERE url_hash = ?",
		urlHash,
	)
	if err != nil {
		return nil, NewCacheError(fmt.Sprintf("failed to query image queries: %v", err))
	}
	defer func() { _ = rows.Close() }()

	var results []struct {
		Embedding []float32
		Answer    string
	}

	for rows.Next() {
		var embeddingBytes []byte
		var answer string
		if err := rows.Scan(&embeddingBytes, &answer); err != nil {
			return nil, NewCacheError(fmt.Sprintf("failed to scan image query: %v", err))
		}

		embedding := make([]float32, len(embeddingBytes)/4)
		for i := range embedding {
			embedding[i] = float32(uint32(embeddingBytes[i*4]) |
				uint32(embeddingBytes[i*4+1])<<8 |
				uint32(embeddingBytes[i*4+2])<<16 |
				uint32(embeddingBytes[i*4+3])<<24)
		}

		results = append(results, struct {
			Embedding []float32
			Answer    string
		}{embedding, answer})
	}

	return results, nil
}

func (s *CacheStore) PutImageQuery(ctx context.Context, urlHash string, embedding []float32, answer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	embeddingBytes := make([]byte, len(embedding)*4)
	for i, v := range embedding {
		bits := uint32(v)
		embeddingBytes[i*4] = byte(bits)
		embeddingBytes[i*4+1] = byte(bits >> 8)
		embeddingBytes[i*4+2] = byte(bits >> 16)
		embeddingBytes[i*4+3] = byte(bits >> 24)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO image_queries (url_hash, query_embedding, answer, created_at)
		 VALUES (?, ?, ?, ?)`,
		urlHash, embeddingBytes, answer, time.Now().Unix(),
	)
	if err != nil {
		return NewCacheError(fmt.Sprintf("failed to store image query: %v", err))
	}

	return nil
}

func (s *CacheStore) Close() error {
	return s.db.Close()
}

func (s *CacheStore) Stats(ctx context.Context) (chunks, images, queries int64, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM chunk_cache").Scan(&chunks)
	if err != nil {
		return chunks, images, queries, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM image_descriptions").Scan(&images)
	if err != nil {
		return chunks, images, queries, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM image_queries").Scan(&queries)
	return chunks, images, queries, err
}

func (s *CacheStore) PruneOld(ctx context.Context, maxAge time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge).Unix()

	result, err := s.db.ExecContext(ctx,
		"DELETE FROM chunk_cache WHERE accessed_at < ?",
		cutoff,
	)
	if err != nil {
		return 0, NewCacheError(fmt.Sprintf("failed to prune: %v", err))
	}

	affected, _ := result.RowsAffected()
	return affected, nil
}
