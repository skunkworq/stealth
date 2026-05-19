package behavior

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// setHTTPHeaders sets standard browser headers and Client Hints from the profile.
func (rg *RequestGenerator) setHTTPHeaders(h http.Header) {
	h.Set("User-Agent", rg.profile.UserAgent)
	accept := rg.profile.Accept
	if rg.config != nil && rg.config.EvadeAcceptDestConsistency {
		if rg.profile.SecFetchDest == "empty" || rg.profile.SecFetchDest == "cors" {
			accept = "*/*"
		}
	}
	h.Set("Accept", accept)
	h.Set("Accept-Language", rg.profile.AcceptLanguage)
	h.Set("Accept-Encoding", rg.profile.AcceptEncoding)
	h.Set("Connection", "keep-alive")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Cache-Control", "max-age=0")

	// Chrome 146 Priority header (RFC 9218)
	if rg.profile.Browser == "chrome" {
		h.Set("Priority", "u=0, i")
	}

	// Sec-Fetch headers
	h.Set("Sec-Fetch-Dest", rg.profile.SecFetchDest)
	h.Set("Sec-Fetch-Mode", rg.profile.SecFetchMode)
	h.Set("Sec-Fetch-Site", rg.profile.SecFetchSite)
	h.Set("Sec-Fetch-User", rg.profile.SecFetchUser)

	// Client Hints (Chrome only)
	if rg.profile.SecChUa != "" {
		h.Set("Sec-Ch-Ua", rg.profile.SecChUa)
		h.Set("Sec-Ch-Ua-Platform", rg.profile.SecChUaPlatform)
		h.Set("Sec-Ch-Ua-Mobile", rg.profile.SecChUaMobile)

		if rg.config != nil && (rg.config.EvadeUADataDeep || rg.config.EvadeClientHintsDeep) {
			// Phase 96/75: prioritize high-entropy Client Hints from profile
			if rg.profile.SecChUaFullVersionList != "" {
				h.Set("Sec-Ch-Ua-Full-Version-List", rg.profile.SecChUaFullVersionList)
			} else if rg.config.EvadeClientHintsDeep {
				// Fallback if list is missing but evasion requested
				re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
				matches := re.FindAllStringSubmatch(rg.profile.SecChUa, -1)
				fullVersions := []string{}
				for _, m := range matches {
					fullVersions = append(fullVersions, fmt.Sprintf(`"%s";v="%s.0.6998.77"`, m[1], m[2]))
				}
				h.Set("Sec-Ch-Ua-Full-Version-List", strings.Join(fullVersions, ", "))
			}

			if rg.profile.SecChUaArch != "" {
				h.Set("Sec-Ch-Ua-Arch", rg.profile.SecChUaArch)
			} else if rg.config.EvadeClientHintsDeep {
				isArm := strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
					(strings.Contains(strings.ToLower(rg.profile.UserAgent), "applewebkit") && strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh"))
				if isArm {
					h.Set("Sec-Ch-Ua-Arch", `"arm"`)
				} else {
					h.Set("Sec-Ch-Ua-Arch", `"x86"`)
				}
			}

			if rg.profile.SecChUaBitness != "" {
				h.Set("Sec-Ch-Ua-Bitness", rg.profile.SecChUaBitness)
			} else if rg.config.EvadeClientHintsDeep {
				h.Set("Sec-Ch-Ua-Bitness", `"64"`)
			}
		} else if rg.config != nil && rg.config.ForceDetections {
			// Phase 75 Fallback/Forced Detection logic
			re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
			matches := re.FindAllStringSubmatch(rg.profile.SecChUa, -1)
			fullVersions := []string{}
			for _, m := range matches {
				fullVersions = append(fullVersions, fmt.Sprintf(`"%s";v="%s.0.6998.77"`, m[1], m[2]))
			}
			h.Set("Sec-Ch-Ua-Full-Version-List", strings.Join(fullVersions, ", "))

			isArm := strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
				(strings.Contains(strings.ToLower(rg.profile.UserAgent), "applewebkit") && strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh"))
			arch := `"x86"`
			if isArm {
				arch = `"arm"`
			}
			h.Set("Sec-Ch-Ua-Arch", arch)
			h.Set("Sec-Ch-Ua-Bitness", `"64"`)
		}
	}
}

// GenerateOrderedHeaders produces headers in a deterministic order mimicking real browsers.
func (rg *RequestGenerator) GenerateOrderedHeaders() []headerPair {
	// Pick resolution and renderer once
	dims := rg.calculateSharedDimensions()
	renderer := rg.profile.WebGLRenderers[rg.rng.Intn(len(rg.profile.WebGLRenderers))]

	h := []headerPair{}

	// Helper to add if not empty
	add := func(k, v string) {
		if v != "" {
			h = append(h, headerPair{Key: k, Value: v})
		}
	}

	// Chrome 146 ordered headers.
	// The X-Stealth-Header-Order simulation header uses HTTP/1.1 title-case names.
	// The shield's header-order check expects User-Agent before Accept for Chrome,
	// and Sec-Ch-Ua before User-Agent, so we preserve that relative ordering.
	if rg.profile.SecChUa != "" {
		add("Sec-Ch-Ua", rg.profile.SecChUa)
		add("Sec-Ch-Ua-Mobile", rg.profile.SecChUaMobile)
		add("Sec-Ch-Ua-Platform", rg.profile.SecChUaPlatform)
		if (rg.config != nil && rg.config.EvadeUADataDeep) && rg.profile.SecChUaFullVersionList != "" {
			add("Sec-Ch-Ua-Full-Version-List", rg.profile.SecChUaFullVersionList)
			add("Sec-Ch-Ua-Arch", rg.profile.SecChUaArch)
			add("Sec-Ch-Ua-Bitness", rg.profile.SecChUaBitness)
		} else if (rg.config != nil && rg.config.EvadeClientHintsDeep) || (rg.config != nil && rg.config.ForceDetections) {
			re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
			matches := re.FindAllStringSubmatch(rg.profile.SecChUa, -1)
			fullVersions := []string{}
			for _, m := range matches {
				fullVersions = append(fullVersions, fmt.Sprintf(`"%s";v="%s.0.6998.77"`, m[1], m[2]))
			}
			add("Sec-Ch-Ua-Full-Version-List", strings.Join(fullVersions, ", "))

			isArm := strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
				(strings.Contains(strings.ToLower(rg.profile.UserAgent), "applewebkit") && strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh"))
			arch := `"x86"`
			if isArm {
				arch = `"arm"`
			}
			add("Sec-Ch-Ua-Arch", arch)
			add("Sec-Ch-Ua-Bitness", `"64"`)
		}
	}
	add("Upgrade-Insecure-Requests", "1")
	add("User-Agent", rg.profile.UserAgent)
	accept := rg.profile.Accept
	if rg.config != nil && rg.config.EvadeAcceptDestConsistency {
		if rg.profile.SecFetchDest == "empty" || rg.profile.SecFetchDest == "cors" {
			accept = "*/*"
		}
	}
	add("Accept", accept)
	if rg.profile.Browser == "chrome" {
		add("Priority", "u=0, i")
	}
	add("Sec-Fetch-Site", rg.profile.SecFetchSite)
	add("Sec-Fetch-Mode", rg.profile.SecFetchMode)
	add("Sec-Fetch-User", rg.profile.SecFetchUser)
	add("Sec-Fetch-Dest", rg.profile.SecFetchDest)
	add("Accept-Encoding", rg.profile.AcceptEncoding)
	add("Accept-Language", rg.profile.AcceptLanguage)

	// Stealth data headers
	add(constants.HeaderWebGLData, rg.generateWebGL(renderer))
	add(constants.HeaderFontData, rg.generateFonts())
	add(constants.HeaderScreenData, rg.generateScreen(dims))
	add(constants.HeaderPluginData, rg.generatePlugins())
	add(constants.HeaderTimingData, rg.generateTiming())
	add(constants.HeaderBehavioralData, rg.generateBehavioral())
	add(constants.HeaderNavigatorData, rg.generateNavigator(dims, renderer))
	add(constants.HeaderCanvasFingerprint, rg.generateCanvas())
	add(constants.HeaderAudioData, rg.generateAudio())

	return h
}
