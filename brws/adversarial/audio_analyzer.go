package adversarial

import (
	"fmt"
	"math"
)

// AudioData holds AudioContext fingerprinting data for analysis.
type AudioData struct {
	SampleRate      int     `json:"sample_rate"`
	ChannelCount    int     `json:"channel_count"`
	MaxChannelCount int     `json:"max_channel_count"`
	BaseLatency     float64 `json:"base_latency"`
	OutputLatency   float64 `json:"output_latency"`
	State           string  `json:"state"`
}

// AudioAnalyzer validates AudioContext parameters for consistency and spoofing detection.
type AudioAnalyzer struct{}

// NewAudioAnalyzer creates a new AudioAnalyzer.
func NewAudioAnalyzer() *AudioAnalyzer {
	return &AudioAnalyzer{}
}

// Analyze runs the full AudioContext analysis suite.
func (aa *AudioAnalyzer) Analyze(data *AudioData) *VectorResult {
	result := &VectorResult{
		Vector:     "Audio Analysis",
		Category:   VectorAudio,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if data == nil {
		return result
	}

	// Check 1: Invalid sample rate
	// Real AudioContext sample rates are 8000, 11025, 16000, 22050, 32000, 44100, 48000, 88200, 96000.
	validRates := map[int]bool{
		8000: true, 11025: true, 16000: true, 22050: true,
		32000: true, 44100: true, 48000: true, 88200: true, 96000: true,
	}
	if !validRates[data.SampleRate] {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "invalid_audio_sample_rate",
			Message: fmt.Sprintf("AudioContext sampleRate %d is not a standard value", data.SampleRate),
			Weight:  weight,
			Field:   "sample_rate",
			Value:   fmt.Sprintf("%d", data.SampleRate),
		})
		result.Score += weight
	}

	// Check 2: Base latency out of range
	// Real AudioContext baseLatency is typically 0.001-0.05 seconds.
	if data.BaseLatency < 0.001 || data.BaseLatency > 0.1 {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "audio_base_latency_out_of_range",
			Message: fmt.Sprintf("AudioContext baseLatency %.6f is out of normal range (0.001-0.05)", data.BaseLatency),
			Weight:  weight,
			Field:   "base_latency",
			Value:   fmt.Sprintf("%.6f", data.BaseLatency),
		})
		result.Score += weight
	}

	// Check 3: Channel count not 2
	// Most audio devices default to 2 channels (stereo).
	if data.ChannelCount != 2 {
		weight := 0.20
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "audio_channel_count_anomaly",
			Message: fmt.Sprintf("AudioContext channelCount %d (expected 2 for stereo)", data.ChannelCount),
			Weight:  weight,
			Field:   "channel_count",
			Value:   fmt.Sprintf("%d", data.ChannelCount),
		})
		result.Score += weight
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}
