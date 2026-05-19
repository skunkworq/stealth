package training

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Manifest describes an exported dataset
type Manifest struct {
	ExportedAt        string         `json:"exported_at"`
	RowCount          int            `json:"row_count"`
	FeatureDimension  int            `json:"feature_dimension"`
	LabelDistribution map[string]int `json:"label_distribution"`
	Columns           []string       `json:"columns"`
}

// ExportJSONL writes episodes in JSON Lines format to the writer
func (c *Collector) ExportJSONL(w io.Writer, filters EpisodeFilters) (int, error) {
	episodes, err := c.Query(filters)
	if err != nil {
		return 0, err
	}

	enc := json.NewEncoder(w)
	for _, ep := range episodes {
		if err := enc.Encode(ep); err != nil {
			return 0, fmt.Errorf("encode episode: %w", err)
		}
	}

	return len(episodes), nil
}

// ExportCSV writes episodes as CSV feature vectors to the writer
func (c *Collector) ExportCSV(w io.Writer, filters EpisodeFilters) (int, error) {
	episodes, err := c.Query(filters)
	if err != nil {
		return 0, err
	}

	csvW := csv.NewWriter(w)
	defer csvW.Flush()

	// Header
	header := make([]string, 0, 23)
	header = append(header, "episode_id", "timestamp", "engine_name", "bot_score", "reward")
	for i := 0; i < 18; i++ {
		header = append(header, fmt.Sprintf("f%d", i))
	}
	if err := csvW.Write(header); err != nil {
		return 0, err
	}

	// Data
	for _, ep := range episodes {
		vec := ToFeatureVector(&ep)
		row := make([]string, 0, 23)
		row = append(row, ep.EpisodeID, ep.Timestamp.Format(time.RFC3339),
			ep.EngineName,
			strconv.FormatFloat(ep.BotScore, 'f', 4, 64),
			strconv.FormatFloat(ep.Reward, 'f', 4, 64))
		for _, v := range vec {
			row = append(row, strconv.FormatFloat(v, 'f', 6, 64))
		}
		if err := csvW.Write(row); err != nil {
			return 0, err
		}
	}

	return len(episodes), nil
}

// ExportManifest generates a manifest for the exported data
func (c *Collector) ExportManifest(filters EpisodeFilters) (*Manifest, error) {
	episodes, err := c.Query(filters)
	if err != nil {
		return nil, err
	}

	dist := map[string]int{
		"success":    0,
		"blocked":    0,
		"challenged": 0,
	}
	for _, ep := range episodes {
		if ep.Outcome.Success {
			dist["success"]++
		} else if ep.Outcome.Blocked {
			dist["blocked"]++
		} else if ep.Outcome.Challenged {
			dist["challenged"]++
		}
	}

	columns := make([]string, 0, 23)
	columns = append(columns, "episode_id", "timestamp", "engine_name", "bot_score", "reward")
	for i := 0; i < 18; i++ {
		columns = append(columns, featureNames[i])
	}

	return &Manifest{
		ExportedAt:        time.Now().Format(time.RFC3339),
		RowCount:          len(episodes),
		FeatureDimension:  18,
		LabelDistribution: dist,
		Columns:           columns,
	}, nil
}

var featureNames = [18]string{
	"webdriver_exposed", "canvas_detected", "client_hints_issues",
	"isomorphic_issues", "hardware_mismatch", "network_mismatch",
	"plugins_detected", "geometry_mismatch", "video_detected",
	"permissions_mismatch", "timezone_mismatch",
	"captcha_presented", "captcha_solved", "captcha_difficulty",
	"mouse_velocity", "typing_speed", "straightness", "solve_time_normalized",
}
