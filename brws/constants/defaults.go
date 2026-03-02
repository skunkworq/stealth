package constants

import "time"

// Detection thresholds.
const (
	// DefaultThresholdBot is the score threshold above which a request is considered a bot
	DefaultThresholdBot = 0.35

	// DefaultThresholdSuspicious is the score threshold for suspicious activity
	DefaultThresholdSuspicious = 0.25

	// DefaultDetectionThreshold is the general detection threshold
	DefaultDetectionThreshold = 0.30
)

// Detection weights by category.
const (
	// WeightTLS is the weight for TLS fingerprint analysis
	WeightTLS = 0.15

	// WeightHTTP is the weight for HTTP header analysis
	WeightHTTP = 0.25

	// WeightNavigator is the weight for navigator object analysis
	WeightNavigator = 0.20

	// WeightCanvas is the weight for canvas fingerprinting analysis
	WeightCanvas = 0.15

	// WeightTiming is the weight for timing analysis
	WeightTiming = 0.15

	// WeightBehavioral is the weight for behavioral biometrics
	WeightBehavioral = 0.20

	// WeightWebGL is the weight for WebGL fingerprint analysis
	WeightWebGL = 0.15

	// WeightWebRTC is the weight for WebRTC leak analysis
	WeightWebRTC = 0.10

	// WeightIP is the weight for IP classification analysis
	WeightIP = 0.10

	// WeightHTTP2 is the weight for HTTP/2 pseudo-header analysis
	WeightHTTP2 = 0.10

	// WeightFont is the weight for font enumeration analysis
	WeightFont = 0.10

	// WeightScreen is the weight for screen geometry analysis
	WeightScreen = 0.10

	// WeightPlugin is the weight for plugin enumeration analysis
	WeightPlugin = 0.08

	// WeightAudio is the weight for AudioContext analysis
	WeightAudio = 0.12

	// WeightHeadless is the weight for headless browser detection
	WeightHeadless = 0.15

	// WeightAutomation is the weight for automation tool detection
	WeightAutomation = 0.20
)

// Severity weights for individual checks.
const (
	SeverityLow    = 0.15
	SeverityMedium = 0.25
	SeverityHigh   = 0.35
)

// Timeout values.
const (
	// DefaultTimeout is the standard timeout for HTTP operations
	DefaultTimeout = 30 * time.Second

	// ShortTimeout is a shorter timeout for quick operations
	ShortTimeout = 5 * time.Second

	// PoolRecycleTimeout is the timeout for pool recycling operations
	PoolRecycleTimeout = 30 * time.Second

	// DialTimeout is the timeout for network connections
	DialTimeout = 30 * time.Second

	// KeepAliveTimeout is the keep-alive duration for connections
	KeepAliveTimeout = 30 * time.Second

	// SolverPollRate is the polling rate for captcha solvers
	SolverPollRate = 5 * time.Second
)

// HTTP server timeouts.
const (
	// DefaultReadTimeout is the default read timeout for HTTP servers
	DefaultReadTimeout = 30 * time.Second

	// DefaultWriteTimeout is the default write timeout for HTTP servers
	DefaultWriteTimeout = 30 * time.Second
)

// Profile and fingerprinting constants.
const (
	// DefaultGreaseRatio is the maximum acceptable GREASE ratio in TLS
	DefaultGreaseRatio = 0.15

	// MaxMissingHeaders is the maximum number of missing headers before penalty
	MaxMissingHeaders = 3
)
