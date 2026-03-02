// Package chromium provides stealth enhancements for the Chromium engine.
// This file implements WebRTC leak prevention to stop IP address disclosure.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter
package chromium

import "fmt"

// WebRTCMode controls how WebRTC is handled for leak prevention
type WebRTCMode int

const (
	// WebRTCDisable overrides RTCPeerConnection to no-op, preventing all WebRTC IP leaks
	WebRTCDisable WebRTCMode = iota
	// WebRTCRelayOnly forces iceTransportPolicy to 'relay', preventing local IP disclosure
	WebRTCRelayOnly
)

// WebRTCConfig configures WebRTC leak prevention behavior
type WebRTCConfig struct {
	// Mode controls the WebRTC prevention strategy
	Mode WebRTCMode
	// PreserveMedia keeps getUserMedia functional for sites that require camera/mic access
	PreserveMedia bool
}

// DefaultWebRTCConfig returns the default WebRTC configuration (disabled for maximum leak protection)
func DefaultWebRTCConfig() *WebRTCConfig {
	return &WebRTCConfig{
		Mode:          WebRTCDisable,
		PreserveMedia: false,
	}
}

// GenerateWebRTCScript generates JavaScript to prevent WebRTC IP leaks
func GenerateWebRTCScript(config *WebRTCConfig) string {
	if config == nil {
		config = DefaultWebRTCConfig()
	}

	switch config.Mode {
	case WebRTCRelayOnly:
		return generateRelayOnlyScript(config.PreserveMedia)
	default:
		return generateDisableScript(config.PreserveMedia)
	}
}

// generateDisableScript generates JS that completely disables WebRTC
func generateDisableScript(preserveMedia bool) string {
	mediaScript := ""
	if !preserveMedia {
		mediaScript = `
    // Hide getUserMedia to prevent media-based fingerprinting
    if (navigator.mediaDevices) {
        Object.defineProperty(navigator.mediaDevices, 'getUserMedia', {
            value: function() {
                return Promise.reject(new DOMException('Permission denied', 'NotAllowedError'));
            },
            writable: false,
            configurable: false
        });
        Object.defineProperty(navigator.mediaDevices, 'enumerateDevices', {
            value: function() {
                return Promise.resolve([]);
            },
            writable: false,
            configurable: false
        });
    }
    // Block legacy getUserMedia
    if (navigator.getUserMedia) {
        navigator.getUserMedia = function(_, _, errorCb) {
            if (errorCb) errorCb(new DOMException('Permission denied', 'NotAllowedError'));
        };
    }`
	}

	return fmt.Sprintf(`
// 23. WebRTC Leak Prevention — Disable Mode
(function() {
    'use strict';

    // Override RTCPeerConnection to prevent any WebRTC activity
    const noopRTC = function() {
        return {
            createOffer: () => Promise.reject(new DOMException('WebRTC disabled', 'NotSupportedError')),
            createAnswer: () => Promise.reject(new DOMException('WebRTC disabled', 'NotSupportedError')),
            setLocalDescription: () => Promise.reject(new DOMException('WebRTC disabled', 'NotSupportedError')),
            setRemoteDescription: () => Promise.reject(new DOMException('WebRTC disabled', 'NotSupportedError')),
            addIceCandidate: () => Promise.reject(new DOMException('WebRTC disabled', 'NotSupportedError')),
            close: () => {},
            addEventListener: () => {},
            removeEventListener: () => {},
            getStats: () => Promise.resolve(new Map()),
            getSenders: () => [],
            getReceivers: () => [],
            getTransceivers: () => [],
            addTrack: () => ({ track: null }),
            removeTrack: () => {},
            onicecandidate: null,
            ontrack: null,
            oniceconnectionstatechange: null,
            onicegatheringstatechange: null,
            onsignalingstatechange: null,
            connectionState: 'closed',
            iceConnectionState: 'closed',
            iceGatheringState: 'complete',
            signalingState: 'closed',
            localDescription: null,
            remoteDescription: null
        };
    };

    // Replace all WebRTC constructors
    if (window.RTCPeerConnection) {
        window.RTCPeerConnection = noopRTC;
    }
    if (window.webkitRTCPeerConnection) {
        window.webkitRTCPeerConnection = noopRTC;
    }
    if (window.mozRTCPeerConnection) {
        window.mozRTCPeerConnection = noopRTC;
    }
    %s
})();`, mediaScript)
}

// generateRelayOnlyScript generates JS that forces WebRTC to relay-only mode
func generateRelayOnlyScript(preserveMedia bool) string {
	_ = preserveMedia // Media is always preserved in relay-only mode

	return `
// 23. WebRTC Leak Prevention — Relay Only Mode
(function() {
    'use strict';

    // Store original constructors
    const OriginalRTCPeerConnection = window.RTCPeerConnection ||
        window.webkitRTCPeerConnection || window.mozRTCPeerConnection;

    if (!OriginalRTCPeerConnection) return;

    // Wrap RTCPeerConnection to force relay-only ICE transport
    const wrappedRTC = function(config, constraints) {
        // Ensure config exists
        config = config || {};

        // Force relay-only transport policy to prevent local IP disclosure
        config.iceTransportPolicy = 'relay';

        // Filter out any STUN servers (only keep TURN servers)
        if (config.iceServers) {
            config.iceServers = config.iceServers.filter(function(server) {
                const urls = Array.isArray(server.urls) ? server.urls : [server.urls || server.url];
                return urls.some(function(url) {
                    return url && url.toLowerCase().startsWith('turn:');
                });
            });
        }

        // Create the real connection with forced relay config
        const pc = new OriginalRTCPeerConnection(config, constraints);

        // Intercept onicecandidate to filter out non-relay candidates
        const originalAddEventListener = pc.addEventListener.bind(pc);
        pc.addEventListener = function(type, listener, options) {
            if (type === 'icecandidate') {
                const wrappedListener = function(event) {
                    if (event.candidate) {
                        // Only allow relay candidates
                        if (event.candidate.candidate &&
                            !event.candidate.candidate.includes('relay')) {
                            return; // Drop non-relay candidates
                        }
                    }
                    listener.call(this, event);
                };
                return originalAddEventListener(type, wrappedListener, options);
            }
            return originalAddEventListener(type, listener, options);
        };

        return pc;
    };

    // Preserve prototype chain
    wrappedRTC.prototype = OriginalRTCPeerConnection.prototype;

    // Replace constructors
    if (window.RTCPeerConnection) {
        window.RTCPeerConnection = wrappedRTC;
    }
    if (window.webkitRTCPeerConnection) {
        window.webkitRTCPeerConnection = wrappedRTC;
    }
})();`
}
