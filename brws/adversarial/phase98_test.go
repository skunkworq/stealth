package adversarial_test

import (
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

// TestPhase98_AcceptDestConsistency verifies the sword's detection of missing HTML Accept for document,
// or static document Accept for XHR/Fetch, and the shield's evasion.
func TestPhase98_AcceptDestConsistency(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	t.Run("Sword catches static document Accept on XHR", func(t *testing.T) {
		config := behavior.MaxEvasionConfig(behavior.ChromeWindowsProfile())
		config.EvadeAcceptDestConsistency = false
		config.EvasionStrategy = nil
		config.EvadeRequestProvenance = false
		// Simulate XHR/Fetch
		config.Profile.SecFetchDest = "empty"
		
		generator := behavior.NewRequestGenerator(config)
		req := generator.GenerateRequest("https://example.com/api/data")
		
		result := detector.AnalyzeRequest(req, nil)
		
		fired := false
		for _, vec := range result.Vectors {
			for _, ind := range vec.Indicators {
				if ind == "accept_dest_mismatch_static_document" {
					fired = true
					break
				}
			}
		}

		if !fired {
			t.Errorf("Sword failed to catch static document Accept on XHR. Accept: %s", req.Header.Get("Accept"))
		}
	})

	t.Run("Shield evades Accept Dest Mismatch", func(t *testing.T) {
		config := behavior.MaxEvasionConfig(behavior.ChromeWindowsProfile())
		config.EvadeAcceptDestConsistency = true
		config.EvasionStrategy = nil
		config.EvadeRequestProvenance = false
		config.Profile.SecFetchDest = "empty"
		
		generator := behavior.NewRequestGenerator(config)
		req := generator.GenerateRequest("https://example.com/api/data")
		
		result := detector.AnalyzeRequest(req, nil)
		
		fired := false
		for _, vec := range result.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "accept_dest_mismatch") {
					fired = true
					break
				}
			}
		}

		if fired {
			t.Errorf("Shield failed to evade Accept Dest Mismatch check. Accept: %s", req.Header.Get("Accept"))
		}
	})

	t.Run("Sword catches missing HTML on document", func(t *testing.T) {
		config := behavior.MaxEvasionConfig(behavior.ChromeWindowsProfile())
		config.EvadeAcceptDestConsistency = false
		config.EvasionStrategy = nil
		config.EvadeRequestProvenance = false
		config.Profile.SecFetchDest = "document"
		// Deliberately break the profile's accept
		config.Profile.Accept = "application/json"
		
		generator := behavior.NewRequestGenerator(config)
		req := generator.GenerateRequest("https://example.com/page")
		
		result := detector.AnalyzeRequest(req, nil)
		
		fired := false
		for _, vec := range result.Vectors {
			for _, ind := range vec.Indicators {
				if ind == "accept_dest_mismatch_missing_html" {
					fired = true
					break
				}
			}
		}

		if !fired {
			t.Errorf("Sword failed to catch missing HTML Accept on document")
		}
	})
}
