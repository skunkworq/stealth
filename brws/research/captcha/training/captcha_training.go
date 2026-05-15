// Package captchatraining re-exports the canonical CAPTCHA tracing types from
// brws/stealth/challenge and adds training/ML-specific extensions on top.
package captchatraining

import (
	"github.com/skunkworq/stealth/brws/core/detection"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// Type aliases — all external callers get the same concrete types as challenge.
type (
	CaptchaEvent          = challenge.CaptchaEvent
	CaptchaTracer         = challenge.CaptchaTracer
	CaptchaTrace          = challenge.CaptchaTrace
	TraceMetrics          = challenge.TraceMetrics
	CaptchaTrainingData   = challenge.CaptchaTrainingData
	TrainingSample        = challenge.TrainingSample
	ChallengeMetrics      = challenge.ChallengeMetrics
	TrainingDataStats     = challenge.TrainingDataStats
	CaptchaChallenge      = challenge.CaptchaChallenge
	DetectionTrace        = challenge.DetectionTrace
)

var (
	NewCaptchaTracer       = challenge.NewCaptchaTracer
	NewCaptchaTrainingData = challenge.NewCaptchaTrainingData
	GetGlobalTracer        = challenge.GetGlobalTracer
)

// CreateDetectionTrace creates a detection trace from a core detection result.
func CreateDetectionTrace(dr *detection.DetectionResult) *DetectionTrace {
	if dr == nil {
		return nil
	}
	return &DetectionTrace{
		Timestamp:  dr.Timestamp,
		FinalScore: dr.Score,
		IsBot:      dr.IsBot,
	}
}
