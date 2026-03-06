package main

import (
	"fmt"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func main() {
	profile := behavior.ChromeWindowsProfile()
	detector := adversarial.NewStealthDetector()
	
	// Create adaptive generator
	gen := behavior.NewAdaptiveRequestGenerator(&behavior.RequestGeneratorConfig{
		Profile: profile,
	})
	
	rounds := 5
	for i := 1; i <= rounds; i++ {
		fmt.Printf("\n--- Round %d ---\n", i)
		req := gen.GenerateRequest("http://test/api/ml/trap")
		detection := detector.AnalyzeRequest(req, nil)

		fmt.Printf("IsBot: %v, Score: %.3f\n", detection.IsBot, detection.Score)
		for _, v := range detection.Vectors {
			if v.Score > 0 {
				fmt.Printf("Vector: %s, Score: %.3f, Detected: %v, Indicators: %v\n", v.Name, v.Score, v.Detected, v.Indicators)
			}
		}

		// Convert to Report for feedback loop
		report := detection.ToDetectionReport()
		gen.ApplyFeedback(report)
		
		if !detection.IsBot {
			fmt.Println("Evaded successfully!")
			break
		}
	}
}
