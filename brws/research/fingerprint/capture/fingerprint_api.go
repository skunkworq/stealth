package capture

import (
	"encoding/json"
	"net/http"
)

// handleFingerprintCompare handles POST /api/fingerprints/compare
func (s *EnhancedServer) handleFingerprintCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		BaselineID string `json:"baseline_id"`
		TestID     string `json:"test_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	baseline, ok := s.capture.GetCapture(req.BaselineID)
	if !ok {
		http.Error(w, `{"error":"baseline capture not found"}`, http.StatusNotFound)
		return
	}

	test, ok := s.capture.GetCapture(req.TestID)
	if !ok {
		http.Error(w, `{"error":"test capture not found"}`, http.StatusNotFound)
		return
	}

	diff := CompareFingerprints(baseline, test)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(diff)
}
