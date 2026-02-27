// Package constants defines common header names used throughout the brws package.
package constants

// Detection headers used for passing browser fingerprinting data.
const (
	// HeaderNavigatorData contains navigator object data (webdriver, platform, etc.)
	HeaderNavigatorData = "X-Navigator-Data"

	// HeaderCanvasFingerprint contains canvas fingerprinting data
	HeaderCanvasFingerprint = "X-Canvas-Fingerprint"

	// HeaderBehavioralData contains behavioral biometrics (mouse, keyboard)
	HeaderBehavioralData = "X-Behavioral-Data"

	// HeaderTimingData contains performance timing data
	HeaderTimingData = "X-Timing-Data"

	// HeaderWebGLData contains WebGL renderer information
	HeaderWebGLData = "X-WebGL-Data"

	// HeaderRequestID is used for request tracking
	HeaderRequestID = "X-Request-ID"

	// HeaderTLSData contains TLS fingerprinting data
	HeaderTLSData = "X-TLS-Data"
)

// Client hint headers.
const (
	HeaderSecCHUA            = "Sec-Ch-Ua"
	HeaderSecCHUAMobile      = "Sec-Ch-Ua-Mobile"
	HeaderSecCHUAPlatform    = "Sec-Ch-Ua-Platform"
	HeaderSecCHUAFullVersion = "Sec-Ch-Ua-Full-Version"
)

// Common HTTP headers used in detection.
const (
	HeaderUserAgent       = "User-Agent"
	HeaderAccept          = "Accept"
	HeaderAcceptLanguage  = "Accept-Language"
	HeaderAcceptEncoding  = "Accept-Encoding"
	HeaderContentType     = "Content-Type"
	HeaderContentLength   = "Content-Length"
	HeaderReferer         = "Referer"
	HeaderConnection      = "Connection"
	HeaderUpgrade         = "Upgrade"
	HeaderXForwardedFor   = "X-Forwarded-For"
	HeaderXRealIP         = "X-Real-Ip"
)

// Detection result headers.
const (
	HeaderXBotScore   = "X-Bot-Score"
	HeaderXIsBot      = "X-Is-Bot"
	HeaderXConfidence = "X-Confidence"
)
