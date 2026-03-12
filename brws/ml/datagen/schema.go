package datagen

// StealthConfigSnapshot captures stealth config state at episode time
type StealthConfigSnapshot struct {
	RemoveWebDriver bool    `json:"remove_webdriver"`
	CanvasNoise     bool    `json:"canvas_noise"`
	WebGLSpoof      bool    `json:"webgl_spoof"`
	ClientHints     bool    `json:"client_hints"`
	FakeScreen      bool    `json:"fake_screen"`
	FakeTimezone    bool    `json:"fake_timezone"`
	RandomUA        bool    `json:"random_ua"`
	HardwareSync    bool    `json:"hardware_sync"`
	NetworkSync     bool    `json:"network_sync"`
	PluginsSync     bool    `json:"plugins_sync"`
	GeometrySync    bool    `json:"geometry_sync"`
	VideoSync       bool    `json:"video_sync"`
	PermissionsSync bool    `json:"permissions_sync"`
	TimezoneSync    bool    `json:"timezone_sync"`
	WebRTCMode      string  `json:"webrtc_mode"`
	CanvasNoiseStr  float64 `json:"canvas_noise_strength"`
}

// DetectionSnapshot captures detection state at episode time
type DetectionSnapshot struct {
	WebdriverExposed    bool    `json:"webdriver_exposed"`
	CanvasDetected      bool    `json:"canvas_detected"`
	ClientHintsIssues   bool    `json:"client_hints_issues"`
	IsomorphicIssues    bool    `json:"isomorphic_issues"`
	HardwareMismatch    bool    `json:"hardware_mismatch"`
	NetworkMismatch     bool    `json:"network_mismatch"`
	PluginsDetected     bool    `json:"plugins_detected"`
	GeometryMismatch    bool    `json:"geometry_mismatch"`
	VideoDetected       bool    `json:"video_detected"`
	PermissionsMismatch bool    `json:"permissions_mismatch"`
	TimezoneMismatch    bool    `json:"timezone_mismatch"`
	OverallScore        float64 `json:"overall_score"`
}

// FSMSnapshot captures FSM state at episode time
type FSMSnapshot struct {
	CurrentState    string `json:"current_state"`
	TransitionCount int    `json:"transition_count"`
	RetryCount      int    `json:"retry_count"`
	ChallengeCount  int    `json:"challenge_count"`
}

// CaptchaSnapshot captures CAPTCHA-related data at episode time
type CaptchaSnapshot struct {
	Presented   bool    `json:"presented"`
	Solved      bool    `json:"solved"`
	Type        string  `json:"type"`
	Difficulty  float64 `json:"difficulty"`
	SolveTimeMs int64   `json:"solve_time_ms"`
}

// BehavioralSnapshot captures behavioral data at episode time
type BehavioralSnapshot struct {
	MouseVelocity  float64 `json:"mouse_velocity"`
	TypingSpeed    float64 `json:"typing_speed"`
	Straightness   float64 `json:"straightness"`
	EventIntervals float64 `json:"event_intervals"`
	TotalEvents    int     `json:"total_events"`
	Clicks         int     `json:"clicks"`
}

// ToFeatureVector converts a TrainingEpisode to an 18-dimensional feature vector
//
// Layout:
//
//	[0-10]  Detection dimensions (webdriver, canvas, client_hints, isomorphic,
//	        hardware, network, plugins, geometry, video, permissions, timezone)
//	[11-13] CAPTCHA dimensions (presented, solved, difficulty)
//	[14]    mouse_velocity (normalized)
//	[15]    typing_speed (normalized)
//	[16]    straightness
//	[17]    solve_time_normalized
func ToFeatureVector(ep *TrainingEpisode) []float64 {
	vec := make([]float64, 18)

	// Detection dimensions [0-10]
	vec[0] = boolToFloat(ep.Detection.WebdriverExposed)
	vec[1] = boolToFloat(ep.Detection.CanvasDetected)
	vec[2] = boolToFloat(ep.Detection.ClientHintsIssues)
	vec[3] = boolToFloat(ep.Detection.IsomorphicIssues)
	vec[4] = boolToFloat(ep.Detection.HardwareMismatch)
	vec[5] = boolToFloat(ep.Detection.NetworkMismatch)
	vec[6] = boolToFloat(ep.Detection.PluginsDetected)
	vec[7] = boolToFloat(ep.Detection.GeometryMismatch)
	vec[8] = boolToFloat(ep.Detection.VideoDetected)
	vec[9] = boolToFloat(ep.Detection.PermissionsMismatch)
	vec[10] = boolToFloat(ep.Detection.TimezoneMismatch)

	// CAPTCHA dimensions [11-13]
	if ep.Captcha != nil {
		vec[11] = boolToFloat(ep.Captcha.Presented)
		vec[12] = boolToFloat(ep.Captcha.Solved)
		vec[13] = ep.Captcha.Difficulty
	}

	// Behavioral dimensions [14-17]
	if ep.Behavioral != nil {
		vec[14] = clamp(ep.Behavioral.MouseVelocity/2000.0, 0, 1) // Normalize to [0,1]
		vec[15] = clamp(ep.Behavioral.TypingSpeed/500.0, 0, 1)    // Normalize to [0,1]
		vec[16] = ep.Behavioral.Straightness                      // Already [0,1]
	}
	if ep.Captcha != nil && ep.Captcha.SolveTimeMs > 0 {
		vec[17] = clamp(float64(ep.Captcha.SolveTimeMs)/30000.0, 0, 1) // Normalize to [0,1] (30s max)
	}

	return vec
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
