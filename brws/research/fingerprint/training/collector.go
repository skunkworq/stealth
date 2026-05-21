package training

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Collector manages structured ML training data collection via SQLite
type Collector struct {
	db *sql.DB
	mu sync.RWMutex
}

// TrainingEpisode represents a complete training episode
type TrainingEpisode struct {
	EpisodeID     string                `json:"episode_id"`
	Timestamp     time.Time             `json:"timestamp"`
	SessionID     string                `json:"session_id"`
	TargetURL     string                `json:"target_url"`
	EngineName    string                `json:"engine_name"`
	StealthConfig StealthConfigSnapshot `json:"stealth_config"`
	Detection     DetectionSnapshot     `json:"detection"`
	FSMState      FSMSnapshot           `json:"fsm_state"`
	Captcha       *CaptchaSnapshot      `json:"captcha,omitempty"`
	Behavioral    *BehavioralSnapshot   `json:"behavioral,omitempty"`
	Outcome       RequestOutcome        `json:"outcome"`
	BotScore      float64               `json:"bot_score"`
	Reward        float64               `json:"reward"`
	ModelVersion  string                `json:"model_version"`
}

// RequestOutcome represents the outcome of a stealth request
type RequestOutcome struct {
	StatusCode   int    `json:"status_code"`
	Blocked      bool   `json:"blocked"`
	Challenged   bool   `json:"challenged"`
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// EpisodeFilters defines query filters for episodes
type EpisodeFilters struct {
	EngineName  string
	MinBotScore float64
	MaxBotScore float64
	Outcome     string // "success", "blocked", "challenged"
	Limit       int
	Offset      int
}

// CollectionStats holds aggregate statistics about collected data
type CollectionStats struct {
	TotalEpisodes int            `json:"total_episodes"`
	ByEngine      map[string]int `json:"by_engine"`
	ByOutcome     map[string]int `json:"by_outcome"`
	AvgBotScore   float64        `json:"avg_bot_score"`
	AvgReward     float64        `json:"avg_reward"`
	DateRange     [2]string      `json:"date_range"`
}

// NewCollector creates a new ML data collector backed by SQLite
func NewCollector(dbPath string) (*Collector, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	c := &Collector{db: db}
	if err := c.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return c, nil
}

func (c *Collector) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS episodes (
		episode_id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		session_id TEXT NOT NULL,
		target_url TEXT NOT NULL,
		engine_name TEXT NOT NULL,
		stealth_config TEXT NOT NULL,
		detection TEXT NOT NULL,
		fsm_state TEXT NOT NULL,
		captcha TEXT,
		behavioral TEXT,
		outcome TEXT NOT NULL,
		bot_score REAL NOT NULL,
		reward REAL NOT NULL,
		model_version TEXT NOT NULL,
		feature_vector TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_episodes_engine ON episodes(engine_name);
	CREATE INDEX IF NOT EXISTS idx_episodes_score ON episodes(bot_score);
	CREATE INDEX IF NOT EXISTS idx_episodes_timestamp ON episodes(timestamp);
	`
	_, err := c.db.Exec(schema)
	return err
}

// RecordEpisode stores a training episode in the database
func (c *Collector) RecordEpisode(ctx context.Context, ep *TrainingEpisode) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	stealthJSON, _ := json.Marshal(ep.StealthConfig)
	detectionJSON, _ := json.Marshal(ep.Detection)
	fsmJSON, _ := json.Marshal(ep.FSMState)
	outcomeJSON, _ := json.Marshal(ep.Outcome)

	var captchaJSON, behavioralJSON []byte
	if ep.Captcha != nil {
		captchaJSON, _ = json.Marshal(ep.Captcha)
	}
	if ep.Behavioral != nil {
		behavioralJSON, _ = json.Marshal(ep.Behavioral)
	}

	featureVec := ToFeatureVector(ep)
	featureJSON, _ := json.Marshal(featureVec)

	_, err := c.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO episodes
		(episode_id, timestamp, session_id, target_url, engine_name,
		 stealth_config, detection, fsm_state, captcha, behavioral,
		 outcome, bot_score, reward, model_version, feature_vector)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.EpisodeID, ep.Timestamp.Format(time.RFC3339), ep.SessionID,
		ep.TargetURL, ep.EngineName,
		string(stealthJSON), string(detectionJSON), string(fsmJSON),
		nullString(captchaJSON), nullString(behavioralJSON),
		string(outcomeJSON), ep.BotScore, ep.Reward, ep.ModelVersion,
		string(featureJSON),
	)
	return err
}

// Query retrieves episodes matching the given filters
func (c *Collector) Query(filters EpisodeFilters) ([]TrainingEpisode, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	query := "SELECT episode_id, timestamp, session_id, target_url, engine_name, stealth_config, detection, fsm_state, captcha, behavioral, outcome, bot_score, reward, model_version FROM episodes WHERE 1=1"
	args := make([]interface{}, 0)

	if filters.EngineName != "" {
		query += " AND engine_name = ?"
		args = append(args, filters.EngineName)
	}
	if filters.MinBotScore > 0 {
		query += " AND bot_score >= ?"
		args = append(args, filters.MinBotScore)
	}
	if filters.MaxBotScore > 0 {
		query += " AND bot_score <= ?"
		args = append(args, filters.MaxBotScore)
	}

	query += " ORDER BY timestamp DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filters.Limit)
	} else {
		query += " LIMIT 1000"
	}
	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filters.Offset)
	}

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var episodes []TrainingEpisode
	for rows.Next() {
		var ep TrainingEpisode
		var ts, stealthJSON, detectionJSON, fsmJSON, outcomeJSON string
		var captchaJSON, behavioralJSON sql.NullString

		if err := rows.Scan(&ep.EpisodeID, &ts, &ep.SessionID, &ep.TargetURL,
			&ep.EngineName, &stealthJSON, &detectionJSON, &fsmJSON,
			&captchaJSON, &behavioralJSON, &outcomeJSON,
			&ep.BotScore, &ep.Reward, &ep.ModelVersion); err != nil {
			return nil, err
		}

		ep.Timestamp, _ = time.Parse(time.RFC3339, ts)
		_ = json.Unmarshal([]byte(stealthJSON), &ep.StealthConfig)
		_ = json.Unmarshal([]byte(detectionJSON), &ep.Detection)
		_ = json.Unmarshal([]byte(fsmJSON), &ep.FSMState)
		_ = json.Unmarshal([]byte(outcomeJSON), &ep.Outcome)

		if captchaJSON.Valid {
			ep.Captcha = &CaptchaSnapshot{}
			_ = json.Unmarshal([]byte(captchaJSON.String), ep.Captcha)
		}
		if behavioralJSON.Valid {
			ep.Behavioral = &BehavioralSnapshot{}
			_ = json.Unmarshal([]byte(behavioralJSON.String), ep.Behavioral)
		}

		episodes = append(episodes, ep)
	}

	return episodes, rows.Err()
}

// Stats returns aggregate statistics about collected data
func (c *Collector) Stats() (*CollectionStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &CollectionStats{
		ByEngine:  make(map[string]int),
		ByOutcome: make(map[string]int),
	}

	// Total count
	_ = c.db.QueryRow("SELECT COUNT(*) FROM episodes").Scan(&stats.TotalEpisodes)

	// Average scores
	_ = c.db.QueryRow("SELECT COALESCE(AVG(bot_score), 0), COALESCE(AVG(reward), 0) FROM episodes").Scan(&stats.AvgBotScore, &stats.AvgReward)

	// By engine
	rows, err := c.db.Query("SELECT engine_name, COUNT(*) FROM episodes GROUP BY engine_name")
	if err == nil {
		for rows.Next() {
			var name string
			var count int
			if rows.Scan(&name, &count) == nil {
				stats.ByEngine[name] = count
			}
		}
		rows.Close()
	}

	// By outcome (outcome column is JSON; decode in Go)
	outcomeRows, err := c.db.Query("SELECT outcome FROM episodes")
	if err == nil {
		for outcomeRows.Next() {
			var outcomeJSON string
			if outcomeRows.Scan(&outcomeJSON) == nil {
				var o RequestOutcome
				if json.Unmarshal([]byte(outcomeJSON), &o) == nil {
					switch {
					case o.Success:
						stats.ByOutcome["success"]++
					case o.Blocked:
						stats.ByOutcome["blocked"]++
					case o.Challenged:
						stats.ByOutcome["challenged"]++
					default:
						stats.ByOutcome["other"]++
					}
				}
			}
		}
		outcomeRows.Close()
	}

	// Date range
	var minDate, maxDate sql.NullString
	_ = c.db.QueryRow("SELECT MIN(timestamp), MAX(timestamp) FROM episodes").Scan(&minDate, &maxDate)
	if minDate.Valid {
		stats.DateRange[0] = minDate.String
	}
	if maxDate.Valid {
		stats.DateRange[1] = maxDate.String
	}

	return stats, nil
}

// Close closes the database connection
func (c *Collector) Close() error {
	return c.db.Close()
}

func nullString(b []byte) interface{} {
	if b == nil {
		return nil
	}
	return string(b)
}
