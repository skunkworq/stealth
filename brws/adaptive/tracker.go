package adaptive

import (
	"strings"
	"sync"

	"github.com/google/uuid"
)

type ElementTracker struct {
	mu       sync.RWMutex
	elements map[string][]ElementProfile
}

type ElementProfile struct {
	ID             string
	Domain         string
	Selector       string
	Tag            string
	Text           string
	Attributes     map[string]string
	Path           string
	SiblingCount   int
	ParentTag      string
	GrandparentTag string
}

func NewElementTracker() *ElementTracker {
	return &ElementTracker{
		elements: make(map[string][]ElementProfile),
	}
}

func (t *ElementTracker) Track(domain, selector, tag, text string, attrs map[string]string, path string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	id := uuid.New().String()
	profile := ElementProfile{
		ID:             id,
		Domain:         domain,
		Selector:       selector,
		Tag:            tag,
		Text:           text,
		Attributes:     attrs,
		Path:           path,
		SiblingCount:   0,
		ParentTag:      extractParentTag(path),
		GrandparentTag: extractGrandparentTag(path),
	}

	t.elements[domain] = append(t.elements[domain], profile)
	return id
}

func (t *ElementTracker) FindSimilar(domain, tag, text string, attrs map[string]string, path string) []ElementProfile {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var candidates []ElementProfile
	for _, p := range t.elements[domain] {
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

func calculateSimilarity(profile ElementProfile, tag, text string, attrs map[string]string, path string) float64 {
	var score float64
	var weights float64 = 0

	if profile.Tag == tag {
		score += 3
	}
	weights += 3

	if profile.ParentTag == extractParentTag(path) {
		score += 2
	}
	weights += 2

	if len(profile.Text) > 0 && len(text) > 0 {
		textSim := stringSimilarity(profile.Text, text)
		score += textSim * 2
		weights += 2
	}

	attrMatch := 0
	totalAttrs := len(profile.Attributes)
	if totalAttrs > 0 {
		for k, v := range profile.Attributes {
			if attrs[k] == v {
				attrMatch++
			}
		}
		score += float64(attrMatch) * 1
		weights += float64(totalAttrs)
	}

	if weights == 0 {
		return 0
	}
	return score / weights
}

func stringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0
	}

	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if strings.Contains(s1, s2) || strings.Contains(s2, s1) {
		minLen := float64(min(len(s1), len(s2)))
		maxLen := float64(max(len(s1), len(s2)))
		return minLen / maxLen
	}

	return longestCommonSubstring(s1, s2) / float64(max(len(s1), len(s2)))
}

func longestCommonSubstring(s1, s2 string) float64 {
	m, n := len(s1), len(s2)
	if m == 0 || n == 0 {
		return 0
	}

	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	maxLen := 0
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
				if dp[i][j] > maxLen {
					maxLen = dp[i][j]
				}
			}
		}
	}

	return float64(maxLen)
}

func extractParentTag(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func extractGrandparentTag(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 3 {
		return parts[len(parts)-3]
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type AdaptiveSelector struct {
	tracker      *ElementTracker
	domain       string
	baseSelector string
	autoSave     bool
}

func NewAdaptiveSelector(domain, selector string) *AdaptiveSelector {
	return &AdaptiveSelector{
		tracker:      NewElementTracker(),
		domain:       domain,
		baseSelector: selector,
		autoSave:     false,
	}
}

func (a *AdaptiveSelector) AutoSave(enable bool) *AdaptiveSelector {
	a.autoSave = enable
	return a
}

func (a *AdaptiveSelector) TrackElement(tag, text string, attrs map[string]string, path string) string {
	return a.tracker.Track(a.domain, a.baseSelector, tag, text, attrs, path)
}

func (a *AdaptiveSelector) FindAdaptive(tag, text string, attrs map[string]string, path string) []ElementProfile {
	return a.tracker.FindSimilar(a.domain, tag, text, attrs, path)
}
