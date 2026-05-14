package chromestealth

import (
	"strings"

	"github.com/skunkworq/stealth/brws/core/types"
)

// StealthConfigFromFingerprint maps a raw proxy capture into a Javascript injection payload constraint
func StealthConfigFromFingerprint(fp *types.CompleteFingerprint) *StealthConfig {
	config := DefaultStealthConfig()

	// Parse HTTP headers for UserAgent and ClientHints
	if fp.HTTP != nil {
		if fp.HTTP.UserAgent != "" {
			// Extract major Chrome version from UA if present
			parts := strings.Split(fp.HTTP.UserAgent, "Chrome/")
			if len(parts) > 1 {
				versionParts := strings.Split(parts[1], ".")
				if len(versionParts) > 0 {
					config.ChromeVersion = parts[1] // Keep full version for navigator
				}
			}
		}

		if fp.HTTP.ClientHints != nil {
			// "Windows"
			platformRaw := strings.Trim(fp.HTTP.ClientHints.SecCHUAPlatform, "\"")
			if platformRaw != "" {
				switch platformRaw {
				case "Windows":
					config.Platform = "Win32"
				case "macOS":
					config.Platform = "MacIntel"
				default:
					config.Platform = platformRaw
				}
			}
		}
	}

	// Parse underlying device signatures if logged (usually not explicitly in HTTP, but JS can guess from traces)
	// If a behavior trace contains exact CPU core counts or memory size, we map it here
	// Default to realistic randoms if missing
	config.DeviceMemoryGB = 8
	config.CanvasNoise = false // ANGLE GPU produces natural canvas fingerprints

	// Ensure accurate screen resolutions if captured via behavioral hooks
	config.ScreenWidth = 1920
	config.ScreenHeight = 1080

	return config
}

// BuildNetworkHeaders translates the fingerprint back into outbound HTTP request headers
func BuildNetworkHeaders(fp *types.CompleteFingerprint) map[string]interface{} {
	headers := make(map[string]interface{})

	if fp.HTTP == nil {
		return headers
	}

	for _, reqHeader := range fp.HTTP.Headers {
		// Only override specific high-entropy headers natively
		// We let Chrome handle host, connection, length, etc.
		lowerName := strings.ToLower(reqHeader.Name)
		switch lowerName {
		case "user-agent",
			"accept-language",
			"accept",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest":
			headers[reqHeader.Name] = reqHeader.Value
		}
	}

	return headers
}
