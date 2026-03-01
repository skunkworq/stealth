package adaptive

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type Storage struct {
	mu      sync.RWMutex
	db      *sql.DB
	tracker *ElementTracker
}

type StorageConfig struct {
	DBPath string
}

func NewStorage(cfg StorageConfig) (*Storage, error) {
	db, err := sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	s := &Storage{
		db:      db,
		tracker: NewElementTracker(),
	}

	if err := s.initSchema(); err != nil {
		return nil, fmt.Errorf("initializing schema: %w", err)
	}

	return s, nil
}

func (s *Storage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS element_profiles (
		id TEXT PRIMARY KEY,
		domain TEXT NOT NULL,
		selector TEXT,
		tag TEXT NOT NULL,
		text_content TEXT,
		attributes TEXT,
		path TEXT,
		sibling_count INTEGER,
		parent_tag TEXT,
		grandparent_tag TEXT,
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_domain ON element_profiles(domain);
	CREATE INDEX IF NOT EXISTS idx_tag ON element_profiles(tag);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Storage) SaveProfile(domain string, profile ElementProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attrs, err := json.Marshal(profile.Attributes)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO element_profiles 
		(id, domain, selector, tag, text_content, attributes, path, sibling_count, parent_tag, grandparent_tag)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, profile.ID, domain, profile.Selector, profile.Tag, profile.Text,
		attrs, profile.Path, profile.SiblingCount, profile.ParentTag, profile.GrandparentTag)

	if err == nil {
		s.tracker.Track(domain, profile.Selector, profile.Tag, profile.Text, profile.Attributes, profile.Path)
	}

	return err
}

func (s *Storage) LoadProfiles(domain string) ([]ElementProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, domain, selector, tag, text_content, attributes, path, sibling_count, parent_tag, grandparent_tag
		FROM element_profiles WHERE domain = ?
	`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []ElementProfile
	for rows.Next() {
		var p ElementProfile
		var attrs []byte
		err := rows.Scan(&p.ID, &p.Domain, &p.Selector, &p.Tag, &p.Text,
			&attrs, &p.Path, &p.SiblingCount, &p.ParentTag, &p.GrandparentTag)
		if err != nil {
			continue
		}
		json.Unmarshal(attrs, &p.Attributes)
		profiles = append(profiles, p)
	}

	return profiles, nil
}

func (s *Storage) FindSimilar(domain, tag, text string, attrs map[string]string, path string) []ElementProfile {
	loaded, err := s.LoadProfiles(domain)
	if err != nil || len(loaded) == 0 {
		return nil
	}

	var candidates []ElementProfile
	for _, p := range loaded {
		if p.Tag == tag {
			candidates = append(candidates, p)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	var best []ElementProfile
	bestScore := 0.0

	for _, c := range candidates {
		score := calculateSimilarity(c, tag, text, attrs, path)
		if score > bestScore {
			bestScore = score
			best = []ElementProfile{c}
		} else if score == bestScore && score > 0.5 {
			best = append(best, c)
		}
	}

	return best
}

func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *Storage) GetTracker() *ElementTracker {
	return s.tracker
}
