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
	OutputLatency           float64 `json:"output_latency"`
	State                   string  `json:"state"`
	AudioWorkletAvailable   bool    `json:"audio_worklet_available"`
	OfflineContextHash      string  `json:"offline_context_hash"`
	CompressorAttack        float64 `json:"compressor_attack"`
	CompressorRelease       float64 `json:"compressor_release"`
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

	// Check 4: Max channel count anomaly
	// Real hardware typically reports 2, 8, or more. 0 or 1 is highly suspicious.
	if data.MaxChannelCount < 2 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "audio_max_channel_count_anomaly",
			Message: fmt.Sprintf("AudioContext maxChannelCount %d is too low for standard hardware", data.MaxChannelCount),
			Weight:  weight,
			Field:   "max_channel_count",
			Value:   fmt.Sprintf("%d", data.MaxChannelCount),
		})
		result.Score += weight
	}

	// Check 5: AudioContext state
	// Real browsers have 'suspended' (initially) or 'running'.
	// Some bots/headless report 'closed' or an empty string immediately.
	if data.State == "" || data.State == "closed" {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "audio_context_static_state",
			Message: fmt.Sprintf("AudioContext state is '%s' (expected suspended/running)", data.State),
			Weight:  weight,
			Field:   "state",
			Value:   data.State,
		})
		result.Score += weight
	}

	// Check 6: Static latency
	// Real browsers have slightly different latencies each time (or at least non-integer/non-rounded).
	// If it's exactly 0.0, it's very suspicious.
	if data.BaseLatency == 0.0 {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "audio_latency_improbable",
			Message: "AudioContext baseLatency is exactly 0.0",
			Weight:  weight,
			Field:   "base_latency",
			Value:   "0.0",
		})
		result.Score += weight
	}

	// Check 7: Missing AudioWorklet
	// Modern browsers (Chrome 66+, Firefox 76+, Safari 14.1+) all support AudioWorklet.
	// Its absence in a modern UA is a strong indicator of a restricted/headless environment.
	if !data.AudioWorkletAvailable {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_audio_worklet",
			Message: "BaseAudioContext.audioWorklet is missing, which is standard in modern browsers",
			Weight:  weight,
			Field:   "audio_worklet",
			Value:   "false",
		})
		result.Score += weight
	}

	// Check 8: OfflineContext rendering (Phase 93)
	if data.OfflineContextHash == "" || data.OfflineContextHash == "0" {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_offline_audio_context",
			Message: "OfflineAudioContext rendering output is missing or empty (constant zero)",
			Weight:  weight,
			Field:   "offline_context_hash",
			Value:   data.OfflineContextHash,
		})
		result.Score += weight
	}

	// Check 9: DynamicsCompressor parameters (Phase 93)
	// Real Chrome default attack is 0.003, release is 0.25 (often stubbed to 0 in bots)
	if data.CompressorAttack == 0 || data.CompressorRelease == 0 {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "suspicious_audio_compressor_params",
			Message: "Audio DynamicsCompressorNode parameters are zero (expected non-zero browser defaults)",
			Weight:  weight,
			Field:   "compressor_params",
			Value:   fmt.Sprintf("attack=%f, release=%f", data.CompressorAttack, data.CompressorRelease),
		})
		result.Score += weight
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}
