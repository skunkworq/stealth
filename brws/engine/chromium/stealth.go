// Package chromium provides stealth enhancements for the Chromium engine.
// This file contains advanced anti-detection techniques for browser automation.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter/randomization
package chromium

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// StealthConfig contains configuration for stealth mode
type StealthConfig struct {
	// Spoof device memory (RAM)
	DeviceMemoryGB int

	// Spoof CPU Cores
	HardwareConcurrency int

	// Spoof platform
	Platform string

	// WebGL vendor/renderer
	WebGLVendor   string
	WebGLRenderer string

	// Enable canvas fingerprint randomization
	CanvasNoise bool

	// Canvas noise strength (0.0-1.0, default 0.5)
	CanvasNoiseStrength float64

	// WebRTC leak prevention config
	WebRTC *WebRTCConfig

	// Enable human-like mouse movements
	HumanizeMouse bool

	// Random delays between actions
	MinDelay time.Duration
	MaxDelay time.Duration

	// Chrome version for client hints
	ChromeVersion string

	// Platform version
	PlatformVersion string

	// Timezone
	Timezone string

	// Screen dimensions
	ScreenWidth  int
	ScreenHeight int

	// Device pixel ratio (default 1.0, 2.0 for HiDPI/Retina)
	DevicePixelRatio float64

	// Dynamic AI Spoofer Sync Flags (passed from stealth.Client / Python RL)
	HardwareSync    bool
	NetworkSync     bool
	PluginsSync     bool
	GeometrySync    bool
	VideoSync       bool
	PermissionsSync bool
	TimezoneSync    bool
}

// DefaultStealthConfig returns a default stealth configuration
func DefaultStealthConfig() *StealthConfig {
	return &StealthConfig{
		DeviceMemoryGB:      RandomRAM(),
		HardwareConcurrency: 8,
		Platform:            "Win32",
		WebGLVendor:         randomGPUVendor(),
		WebGLRenderer:       randomGPURenderer(),
		CanvasNoise:         true,
		CanvasNoiseStrength: 0.5,
		WebRTC:              DefaultWebRTCConfig(),
		HumanizeMouse:       true,
		MinDelay:        100 * time.Millisecond,
		MaxDelay:        500 * time.Millisecond,
		ChromeVersion:   "134.0.6998.88",
		PlatformVersion: "10.0.0",
		Timezone:        "America/New_York",
		ScreenWidth:     1920,
		ScreenHeight:    1080,
	}
}

// ChromeVersions for client hints (updated to 2025-2026 era)
var ChromeVersions = []string{
	"131.0.6778.139",
	"132.0.6834.110",
	"133.0.6917.92",
	"134.0.6998.88",
	"135.0.7049.65",
}

// GenerateStealthScript generates the JavaScript to inject for stealth
func GenerateStealthScript(config *StealthConfig) string {
	if config == nil {
		config = DefaultStealthConfig()
	}

	// Generate client hints strings
	chromeVersion := config.ChromeVersion
	if chromeVersion == "" {
		chromeVersion = "134.0.6998.88"
	}

	platformVersion := config.PlatformVersion
	if platformVersion == "" {
		platformVersion = "10.0.0"
	}

	timezone := config.Timezone
	if timezone == "" {
		timezone = "America/New_York"
	}

	screenWidth := config.ScreenWidth
	screenHeight := config.ScreenHeight

	if screenWidth == 0 {
		screenWidth = 1920
		screenHeight = 1080
	}

	deviceMemory := config.DeviceMemoryGB
	if deviceMemory == 0 {
		deviceMemory = 8
	}
	
	concurrency := config.HardwareConcurrency
	if concurrency == 0 {
		concurrency = 8
	}

	canvasNoiseStrength := config.CanvasNoiseStrength
	if canvasNoiseStrength <= 0 {
		canvasNoiseStrength = 0.5
	}
	if canvasNoiseStrength > 1.0 {
		canvasNoiseStrength = 1.0
	}

	devicePixelRatio := config.DevicePixelRatio
	if devicePixelRatio <= 0 {
		devicePixelRatio = 1.0
	}

	// Slight screenY offset (0 for primary monitor, small value for realism)
	screenY := 0
	if screenHeight > 1080 {
		screenY = 24 // typical panel/dock offset on large displays
	}

	script := fmt.Sprintf(`
// ====== Anti-Detection Script ======
(function() {
    'use strict';
    
    // 1. Device Memory Spoofing
    Object.defineProperty(Navigator.prototype, 'deviceMemory', {
        get: () => %d
    });
    
    // 2. Hardware Concurrency (CPU cores)
    Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
        get: () => %d
    });
    
    // 3. Platform Spoofing
    Object.defineProperty(navigator, 'platform', {
        get: () => "%s",
        configurable: true
    });
    
    // 4. Screen Dimensions Spoofing
    Object.defineProperty(screen, 'width', { get: () => %d });
    Object.defineProperty(screen, 'height', { get: () => %d });
    Object.defineProperty(screen, 'availWidth', { get: () => %d });
    Object.defineProperty(screen, 'availHeight', { get: () => %d });
    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
    
    Object.defineProperty(window, 'innerWidth', { get: () => %d });
    Object.defineProperty(window, 'innerHeight', { get: () => %d });
    Object.defineProperty(window, 'outerWidth', { get: () => %d });
    Object.defineProperty(window, 'outerHeight', { get: () => %d });
    Object.defineProperty(window, 'devicePixelRatio', { get: () => %f });
    Object.defineProperty(window, 'screenX', { get: () => 0 });
    Object.defineProperty(window, 'screenY', { get: () => %d });
    Object.defineProperty(window, 'screenLeft', { get: () => 0 });
    Object.defineProperty(window, 'screenTop', { get: () => %d });
    
    // 5. Timezone Spoofing
    const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
    Date.prototype.getTimezoneOffset = function() {
        // Return offset for %s
        return %d;  // minutes offset from UTC
    };
    
    // Override Intl.DateTimeFormat
    const originalDateTimeFormat = Intl.DateTimeFormat;
    Intl.DateTimeFormat = function(...args) {
        const r = new originalDateTimeFormat(...args);
        const originalResolved = r.resolvedOptions;
        r.resolvedOptions = function() {
            const opts = originalResolved.call(this);
            opts.timeZone = '%s';
            return opts;
        };
        return r;
    };
    
    // 6. Client Hints Spoofing (sec-ch-ua-*)
    Object.defineProperty(navigator, 'userAgentData', {
        get: () => ({
            brands: [
                { brand: 'Not(A:Brand', version: '8' },
                { brand: 'Chromium', version: '%s' },
                { brand: 'Google Chrome', version: '%s' }
            ],
            mobile: false,
            platform: '%s',
            getHighEntropyValues: (hints) => Promise.resolve({
                platform: '%s',
                platformVersion: '%s',
                architecture: 'x86',
                bitness: '64',
                model: '',
                uaFullVersion: '%s'
            })
        })
    });
    
    // 7. Connection Spoofing (Network Information API)
    Object.defineProperty(navigator, 'connection', {
        get: () => ({
            downlink: 10,
            effectiveType: '4g',
            rtt: 50,
            saveData: false,
            onchange: null,
            addEventListener: () => {},
            removeEventListener: () => {},
        })
    });
    
    // 8. Advanced Webdriver Flag Removal (nodriver strategy)
    try {
        const defaultGetter = Object.getOwnPropertyDescriptor(
            Navigator.prototype,
            "webdriver"
        ).get;
        
        Object.defineProperty(Navigator.prototype, "webdriver", {
            set: undefined,
            enumerable: true,
            configurable: true,
            get: new Proxy(defaultGetter, {
                apply: (target, thisArg, args) => {
                    return false;
                },
            }),
        });
        
        // Hide the Proxy perfectly using Object.getOwnPropertyDescriptor bridging
        const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
        Object.getOwnPropertyDescriptor = function(obj, prop) {
            const descriptor = originalGetOwnPropertyDescriptor(obj, prop);
            if (obj === Navigator.prototype && prop === "webdriver" && descriptor && descriptor.get) {
                // Return the original raw getter instead of our proxy when inspected
                descriptor.get = defaultGetter;
            }
            return descriptor;
        };

        // Perfectly disguise .toString() to look like C++ native code
        const originalToString = Function.prototype.toString;
        Function.prototype.toString = function(...args) {
            if (this === Navigator.prototype.__lookupGetter__('webdriver') || this.name === "get webdriver") {
                return 'function get webdriver() { [native code] }';
            }
            if (this === Object.getOwnPropertyDescriptor || this === Function.prototype.toString) {
                return 'function ' + this.name + '() { [native code] }';
            }
            return originalToString.call(this, ...args);
        };
    } catch(e) {}
    
    // 9. Video Element Spoofing
    const fakeVideoElement = {
        canPlayType: (type) => {
            if (type.includes('video/mp4') && type.includes('avc1')) return 'probably';
            if (type.includes('video/webm')) return 'probably';
            if (type.includes('video/ogg')) return 'maybe';
            return '';
        },
        nodeName: 'VIDEO',
        tagName: 'VIDEO',
    };
    
    // 10. WebGL Spoofing (expanded with 25+ extensions and GL parameters)
    const webglExtensions = [
        'ANGLE_instanced_arrays', 'EXT_blend_minmax', 'EXT_color_buffer_half_float',
        'EXT_disjoint_timer_query', 'EXT_float_blend', 'EXT_frag_depth',
        'EXT_shader_texture_lod', 'EXT_texture_compression_bptc',
        'EXT_texture_compression_rgtc', 'EXT_texture_filter_anisotropic',
        'EXT_sRGB', 'KHR_parallel_shader_compile', 'OES_element_index_uint',
        'OES_fbo_render_mipmap', 'OES_standard_derivatives', 'OES_texture_float',
        'OES_texture_float_linear', 'OES_texture_half_float',
        'OES_texture_half_float_linear', 'OES_vertex_array_object',
        'WEBGL_color_buffer_float', 'WEBGL_compressed_texture_s3tc',
        'WEBGL_compressed_texture_s3tc_srgb', 'WEBGL_debug_renderer_info',
        'WEBGL_debug_shaders', 'WEBGL_depth_texture', 'WEBGL_draw_buffers',
        'WEBGL_lose_context', 'WEBGL_multi_draw'
    ];
    const fakeExtObj = { /* stub for generic extensions */ };
    const fakeWebGLContext = {
        getSupportedExtensions: () => webglExtensions,
        getExtension: (name) => {
            if (name === 'WEBGL_debug_renderer_info') {
                return {
                    UNMASKED_VENDOR_WEBGL: 0x9245,
                    UNMASKED_RENDERER_WEBGL: 0x9246,
                };
            }
            if (name === 'WEBGL_lose_context') {
                return { loseContext: () => {}, restoreContext: () => {} };
            }
            if (name === 'EXT_texture_filter_anisotropic') {
                return { MAX_TEXTURE_MAX_ANISOTROPY_EXT: 0x84FF, TEXTURE_MAX_ANISOTROPY_EXT: 0x84FE };
            }
            if (name === 'WEBGL_draw_buffers') {
                return { MAX_DRAW_BUFFERS_WEBGL: 8, MAX_COLOR_ATTACHMENTS_WEBGL: 8, drawBuffersWEBGL: () => {} };
            }
            if (webglExtensions.includes(name)) return fakeExtObj;
            return null;
        },
        getParameter: (param) => {
            if (param === 0x9245) return '%s';  // UNMASKED_VENDOR_WEBGL
            if (param === 0x9246) return '%s';  // UNMASKED_RENDERER_WEBGL
            if (param === 0x0D33) return 16384;  // MAX_TEXTURE_SIZE
            if (param === 0x8B8C) return 'WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)';  // SHADING_LANGUAGE_VERSION
            if (param === 0x1F01) return 'WebKit WebGL';  // RENDERER
            if (param === 0x1F00) return 'WebKit';  // VENDOR
            if (param === 0x8869) return 16;  // MAX_VERTEX_ATTRIBS
            if (param === 0x8DFB) return 30;  // MAX_VARYING_VECTORS
            if (param === 0x8B4D) return 1024;  // MAX_FRAGMENT_UNIFORM_VECTORS
            if (param === 0x0D32) return 16384;  // MAX_VIEWPORT_DIMS (approx)
            if (param === 0x8B4A) return 256;  // MAX_VERTEX_UNIFORM_VECTORS
            if (param === 0x851C) return 16;  // MAX_TEXTURE_IMAGE_UNITS
            if (param === 0x8872) return 16;  // MAX_VERTEX_TEXTURE_IMAGE_UNITS
            if (param === 0x8824) return 16;  // MAX_COMBINED_TEXTURE_IMAGE_UNITS
            if (param === 0x0D34) return 16384;  // MAX_CUBE_MAP_TEXTURE_SIZE
            if (param === 0x84E8) return 16;  // MAX_RENDERBUFFER_SIZE scaled
            return null;
        },
        createShader: () => ({}),
        createProgram: () => ({}),
        createBuffer: () => ({}),
    };
    
    // 11. Enhanced Canvas Fingerprint Randomization
    const rand = (min = 0, max = 1) => Math.random() * (max - min) + min;
    const noiseStrength = %f; // 0.0-1.0 configurable strength
    const pixelNoiseRate = 0.03 + (noiseStrength * 0.02); // 3-5%% of pixels

    const realCreateElement = document.createElement.bind(document);
    document.createElement = function(tagName) {
        if (tagName.toLowerCase() === 'video') {
            const realVideo = realCreateElement('video');
            realVideo.canPlayType = fakeVideoElement.canPlayType;
            return realVideo;
        } else if (tagName.toLowerCase() === 'canvas') {
            const realCanvas = realCreateElement('canvas');
            const originalGetContext = realCanvas.getContext.bind(realCanvas);

            // Patch toDataURL and toBlob at the canvas level
            const origToDataURL = realCanvas.toDataURL.bind(realCanvas);
            const origToBlob = realCanvas.toBlob?.bind(realCanvas);

            realCanvas.toDataURL = function(...args) {
                // Force a re-render pass through our noised context
                const ctx = realCanvas.getContext('2d');
                if (ctx) {
                    const w = realCanvas.width || 1;
                    const h = realCanvas.height || 1;
                    const imageData = ctx.getImageData(0, 0, w, h);
                    ctx.putImageData(imageData, 0, 0);
                }
                return origToDataURL(...args);
            };

            if (origToBlob) {
                realCanvas.toBlob = function(callback, ...args) {
                    const ctx = realCanvas.getContext('2d');
                    if (ctx) {
                        const w = realCanvas.width || 1;
                        const h = realCanvas.height || 1;
                        const imageData = ctx.getImageData(0, 0, w, h);
                        ctx.putImageData(imageData, 0, 0);
                    }
                    return origToBlob(callback, ...args);
                };
            }

            realCanvas.getContext = function(contextType, ...args) {
                const ctx = originalGetContext(contextType, ...args);

                if (contextType === 'webgl' || contextType === 'experimental-webgl') {
                    return fakeWebGLContext;
                } else if (contextType === '2d' && ctx) {
                    // Add subtle noise to canvas operations
                    const origFillText = ctx.fillText.bind(ctx);
                    const origStrokeText = ctx.strokeText?.bind(ctx);
                    const origGetImageData = ctx.getImageData.bind(ctx);
                    const origDrawImage = ctx.drawImage?.bind(ctx);

                    // Patch fillText with translation noise + subtle letter spacing
                    ctx.fillText = function(text, x, y, ...rest) {
                        const dx = rand(-0.2, 0.2) * noiseStrength;
                        const dy = rand(-0.2, 0.2) * noiseStrength;
                        // Subtle letter spacing variance
                        if (text.length > 1) {
                            ctx.letterSpacing = (rand(-0.1, 0.1) * noiseStrength) + 'px';
                        }
                        return origFillText(text, x + dx, y + dy, ...rest);
                    };

                    // Patch strokeText similarly
                    if (origStrokeText) {
                        ctx.strokeText = function(text, x, y, ...rest) {
                            const dx = rand(-0.2, 0.2) * noiseStrength;
                            const dy = rand(-0.2, 0.2) * noiseStrength;
                            return origStrokeText(text, x + dx, y + dy, ...rest);
                        };
                    }

                    // Patch getImageData to modify pixels (3-5%% across R/G/B, not alpha)
                    ctx.getImageData = function(sx, sy, sw, sh) {
                        const imageData = origGetImageData(sx, sy, sw, sh);
                        for (let i = 0; i < imageData.data.length; i += 4) {
                            if (Math.random() < pixelNoiseRate) {
                                imageData.data[i] ^= 1;     // Red LSB
                                imageData.data[i + 1] ^= 1; // Green LSB
                                imageData.data[i + 2] ^= 1; // Blue LSB
                                // Alpha (i+3) intentionally untouched
                            }
                        }
                        return imageData;
                    };

                    // Patch drawImage with slight shift
                    if (origDrawImage) {
                        ctx.drawImage = function(img, sx, sy, ...args) {
                            const dx = rand(-0.3, 0.3) * noiseStrength;
                            const dy = rand(-0.3, 0.3) * noiseStrength;
                            return origDrawImage(img, sx + dx, sy + dy, ...args);
                        };
                    }

                    // Apply rendering property noise
                    ctx.globalAlpha = rand(0.98, 1.0);
                    ctx.shadowBlur = rand(0, 0.5) * noiseStrength;

                    return ctx;
                }

                return ctx;
            };

            return realCanvas;
        }
        return realCreateElement(tagName);
    };
    
    // 12. Modernizr offsetHeight spoofing
    const elementDescriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
    Object.defineProperty(HTMLDivElement.prototype, 'offsetHeight', {
        ...elementDescriptor,
        get: function() {
            if (this.id === 'modernizr') {
                return 1;
            }
            return elementDescriptor.get.apply(this);
        },
    });
    
    // 13. Plugin spoofing (5 plugins matching real Chrome)
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const plugins = [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1, item: () => null, namedItem: () => null },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', length: 1, item: () => null, namedItem: () => null },
                { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', length: 2, item: () => null, namedItem: () => null },
                { name: 'Chromium PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1, item: () => null, namedItem: () => null },
                { name: 'Chromium PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', length: 1, item: () => null, namedItem: () => null },
            ];
            plugins.length = 5;
            return plugins;
        }
    });

    // 13b. PDF viewer enabled (present in real Chrome)
    Object.defineProperty(navigator, 'pdfViewerEnabled', {
        get: () => true
    });
    
    // 14. Languages spoofing (make configurable first)
    try {
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
            configurable: true
        });
        Object.defineProperty(navigator, 'language', {
            get: () => 'en-US',
            configurable: true
        });
    } catch(e) {
        // Already defined, ignore
    }
    
    // 15. Remove automation-related properties
    delete navigator.__proto__.webdriver;
    
    // 17. Chrome runtime spoofing
    window.chrome = {
        runtime: {
            OnInstalledReason: {
                CHROME_UPDATE: "chrome_update",
                INSTALL: "install",
                SHARED_MODULE_UPDATE: "shared_module_update",
                UPDATE: "update"
            },
            OnRestartRequiredReason: {
                APP_UPDATE: "app_update",
                OS_UPDATE: "os_update",
                PERIODIC: "periodic"
            },
            PlatformArch: {
                ARM: "arm",
                ARM64: "arm64",
                MIPS: "mips",
                MIPS64: "mips64",
                MIPS64EL: "mips64el",
                MIPSEL: "mipsel",
                X86_32: "x86-32",
                X86_64: "x86-64"
            },
            PlatformNaclArch: {
                ARM: "arm",
                MIPS: "mips",
                MIPS64: "mips64",
                MIPS64EL: "mips64el",
                MIPSEL: "mipsel",
                MIPSEL64: "mipsel64",
                X86_32: "x86-32",
                X86_64: "x86-64"
            },
            PlatformOs: {
                ANDROID: "android",
                CROS: "cros",
                LINUX: "linux",
                MAC: "mac",
                OPENBSD: "openbsd",
                WIN: "win"
            },
            RequestUpdateCheckStatus: {
                NO_UPDATE: "no_update",
                THROTTLED: "throttled",
                UPDATE_AVAILABLE: "update_available"
            }
        }
    };
    
    // 18. MaxTouchPoints spoofing
    Object.defineProperty(navigator, 'maxTouchPoints', {
        get: () => 0
    });
    
    // 19. CookieEnabled spoofing
    Object.defineProperty(navigator, 'cookieEnabled', {
        get: () => true
    });
    
    // 20. DoNotTrack spoofing
    Object.defineProperty(navigator, 'doNotTrack', {
        get: () => '1'
    });

    // 21. AudioContext Spoofing (consistent sample rate and latency)
    try {
        const OrigAudioContext = window.AudioContext || window.webkitAudioContext;
        if (OrigAudioContext) {
            const origProto = OrigAudioContext.prototype;
            const origCreateOscillator = origProto.createOscillator;
            const origCreateDynamicsCompressor = origProto.createDynamicsCompressor;
            Object.defineProperty(origProto, 'sampleRate', { get: () => 48000 });
            Object.defineProperty(origProto, 'baseLatency', { get: () => 0.005333 });
            Object.defineProperty(origProto, 'outputLatency', { get: () => 0.016 });
            // Ensure createOscillator and createDynamicsCompressor exist
            if (!origCreateOscillator) {
                origProto.createOscillator = function() { return { connect: () => {}, start: () => {}, frequency: { value: 440 } }; };
            }
            if (!origCreateDynamicsCompressor) {
                origProto.createDynamicsCompressor = function() { return { connect: () => {}, reduction: { value: 0 } }; };
            }
        }
    } catch(e) {}

    // 22. Headless Detection Mitigations
    // Realistic window dimension gaps (title bar + taskbar simulation)
    try {
        Object.defineProperty(window, 'outerHeight', {
            get: () => %d + 85  // screenHeight + title bar + taskbar
        });
        Object.defineProperty(window, 'outerWidth', {
            get: () => %d       // screenWidth (maximized window)
        });
    } catch(e) {}

    // Notification.permission — headless returns 'denied', real browsers default 'default'
    try {
        Object.defineProperty(Notification, 'permission', {
            get: () => 'default'
        });
    } catch(e) {}

    // chrome.loadTimes() — present in real Chrome, absent in headless
    if (window.chrome) {
        window.chrome.loadTimes = function() {
            return {
                commitLoadTime: Date.now() / 1000 - Math.random() * 2,
                connectionInfo: 'h2',
                finishDocumentLoadTime: Date.now() / 1000 - Math.random() * 0.5,
                finishLoadTime: Date.now() / 1000 - Math.random() * 0.3,
                firstPaintAfterLoadTime: 0,
                firstPaintTime: Date.now() / 1000 - Math.random() * 1.5,
                navigationType: 'Other',
                npnNegotiatedProtocol: 'h2',
                requestTime: Date.now() / 1000 - Math.random() * 3,
                startLoadTime: Date.now() / 1000 - Math.random() * 2.5,
                wasAlternateProtocolAvailable: false,
                wasFetchedViaSpdy: true,
                wasNpnNegotiated: true
            };
        };
        window.chrome.csi = function() {
            return {
                onloadT: Date.now(),
                pageT: Math.random() * 3000 + 500,
                startE: Date.now() - Math.random() * 5000,
                tran: 15
            };
        };
    }

    // Intl locale must match navigator.language
    try {
        const origDateTimeFormat = Intl.DateTimeFormat;
        Intl.DateTimeFormat = function(...args) {
            const instance = new origDateTimeFormat(...args);
            const origResolvedOptions = instance.resolvedOptions.bind(instance);
            instance.resolvedOptions = function() {
                const opts = origResolvedOptions();
                opts.locale = navigator.language || 'en-US';
                return opts;
            };
            return instance;
        };
        Object.setPrototypeOf(Intl.DateTimeFormat, origDateTimeFormat);
        Intl.DateTimeFormat.prototype = origDateTimeFormat.prototype;
        Intl.DateTimeFormat.supportedLocalesOf = origDateTimeFormat.supportedLocalesOf;
    } catch(e) {}

    console.log('[Stealth] Anti-detection scripts injected successfully');
})();
`,
		deviceMemory,
		concurrency,
		config.Platform,
		screenWidth, screenHeight,
		screenWidth, screenHeight-40, // minus taskbar
		screenWidth-80, screenHeight-80, // inner window
		screenWidth, screenHeight, // outer
		devicePixelRatio,    // devicePixelRatio
		screenY, screenY,    // screenY, screenTop (slight offset for realism)
		timezone,
		getTimezoneOffset(timezone),
		timezone,
		chromeVersion[:2], // major version for brands
		chromeVersion,
		config.Platform,
		config.Platform,
		platformVersion,
		chromeVersion,
		config.WebGLVendor,
		config.WebGLRenderer,
		canvasNoiseStrength,       // canvas noise strength
		screenHeight, screenWidth) // headless patches (outerHeight, outerWidth)

	// --- Phase 16: Dynamic RL Mutable Evasion Logic ---

	if config.NetworkSync {
		script = strings.Replace(script, `downlink: 10,
            effectiveType: '4g',
            rtt: 50,`, fmt.Sprintf(`downlink: %f,
            effectiveType: '4g',
            rtt: %d,`, rand.Float64()*8.5+1.5, rand.Intn(100)+50), 1)
	}

	if config.VideoSync {
		script = strings.Replace(script, `if (type.includes('video/mp4') && type.includes('avc1')) return 'probably';
            if (type.includes('video/webm')) return 'probably';`, `if (type.includes('video/mp4') && type.includes('avc1')) return 'maybe';
            if (type.includes('video/webm')) return 'maybe';`, 1)
	}

	if !config.PluginsSync {
		// Enforce penalty detectable mock if RL agent failed to mutate
		script = strings.Replace(script, `name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format'`,
			`name: 'Detectable Plugin', filename: 'detectable'`, 1)
	}

	if !config.GeometrySync {
		// Enforce penalty geometry anomaly
		script = strings.Replace(script, fmt.Sprintf(`Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
    
    Object.defineProperty(window, 'innerWidth', { get: () => %d });`, screenWidth-80),
			fmt.Sprintf(`Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
    
    Object.defineProperty(window, 'innerWidth', { get: () => %d });
    Object.defineProperty(window, 'outerWidth', { get: () => %d });`, screenWidth-80, screenWidth-80), 1)
	}

	if config.PermissionsSync {
		script += "\n" + `
// 21. Permissions API Patching Bypass
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = function(parameters) {
    if (parameters.name === 'notifications') {
        const p = Promise.resolve({ state: 'prompt' });
        p.isProxy = true; // explicitly detectable! wait, they asked for bypass on Sync = true.
        return Promise.resolve({ state: 'prompt' }); 
    }
    return originalQuery.call(this, parameters);
};`
	} else {
		script += "\n" + `
// 21. Detectable Permissions API Mock
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = function(parameters) {
    const p = Promise.resolve({ state: 'default' });
    p.isProxy = true; 
    return p;
};`
	}

	if !config.TimezoneSync {
		// Mismatch the timezone offset intentionally
		script = strings.Replace(script, fmt.Sprintf(`return %d;  // minutes offset from UTC`, getTimezoneOffset(timezone)),
			`return 0;  // mismatched default offset`, 1)
	}

	// --- Phase 23: WebRTC Leak Prevention ---
	if config.WebRTC != nil {
		script += "\n" + GenerateWebRTCScript(config.WebRTC)
	}

	return script
}

// BezierCurve represents a quadratic Bezier curve for mouse movement
type BezierCurve struct {
	StartX, StartY     float64
	ControlX, ControlY float64
	EndX, EndY         float64
}

// GenerateBezierCurve generates a curved path between two points
func GenerateBezierCurve(startX, startY, endX, endY float64) *BezierCurve {
	// Control point pulls curve off straight line
	ctrlX := (startX+endX)/2 + RandomFloat(-100, 100)
	ctrlY := (startY+endY)/2 + RandomFloat(-100, 100)

	return &BezierCurve{
		StartX:   startX,
		StartY:   startY,
		ControlX: ctrlX,
		ControlY: ctrlY,
		EndX:     endX,
		EndY:     endY,
	}
}

// GetPointAt gets a point on the curve at time t (0-1)
func (bc *BezierCurve) GetPointAt(t float64) (float64, float64) {
	x := bezier(bc.StartX, bc.ControlX, bc.EndX, t)
	y := bezier(bc.StartY, bc.ControlY, bc.EndY, t)
	return x, y
}

// MousePath represents a human-like mouse movement path
type MousePath struct {
	Curve      *BezierCurve
	Duration   time.Duration
	Steps      int
	StartDelay time.Duration
}

// GenerateMousePath creates a randomized mouse path
func GenerateMousePath(startX, startY, endX, endY float64, duration time.Duration) *MousePath {
	// Add some randomness to end position (click within target area)
	endX += RandomFloat(-5, 5)
	endY += RandomFloat(-5, 5)

	return &MousePath{
		Curve:      GenerateBezierCurve(startX, startY, endX, endY),
		Duration:   duration + time.Duration(RandomFloat(0, 500))*time.Millisecond,
		Steps:      int(60 * duration.Seconds()), // 60 FPS
		StartDelay: time.Duration(RandomFloat(50, 200)) * time.Millisecond,
	}
}

// ToJavaScript generates JavaScript code to execute the mouse movement
func (mp *MousePath) ToJavaScript() string {
	return fmt.Sprintf(`
(async () => {
    const startX = %f;
    const startY = %f;
    const ctrlX = %f;
    const ctrlY = %f;
    const endX = %f;
    const endY = %f;
    const duration = %d;
    const steps = %d;
    
    function bezier(p0, p1, p2, t) {
        return (1 - t) * (1 - t) * p0 + 2 * (1 - t) * t * p1 + t * t * p2;
    }
    
    function easeInOutCubic(t) {
        return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
    }
    
    function rand(min, max) {
        return Math.random() * (max - min) + min;
    }
    
    await new Promise(r => setTimeout(r, %d));
    
    const stepDelay = duration / steps;
    
    for (let i = 0; i <= steps; i++) {
        const linearT = i / steps;
        const easedT = easeInOutCubic(linearT);
        
        const x = bezier(startX, ctrlX, endX, easedT);
        const y = bezier(startY, ctrlY, endY, easedT);
        
        const jitterStrength = Math.max(0.5, (1 - easedT) * 3);
        const jitterX = rand(-jitterStrength, jitterStrength);
        const jitterY = rand(-jitterStrength, jitterStrength);
        
        window.dispatchEvent(new MouseEvent('mousemove', {
            clientX: x + jitterX,
            clientY: y + jitterY,
            bubbles: true
        }));
        
        await new Promise(r => setTimeout(r, stepDelay));
    }
})();
`, mp.Curve.StartX, mp.Curve.StartY, mp.Curve.ControlX, mp.Curve.ControlY,
		mp.Curve.EndX, mp.Curve.EndY,
		int(mp.Duration.Milliseconds()),
		mp.Steps,
		int(mp.StartDelay.Milliseconds()))
}

// RandomDelay returns a random delay between minDelay and maxDelay.
func RandomDelay(minDelay, maxDelay time.Duration) time.Duration {
	return minDelay + time.Duration(RandomFloat(0, float64(maxDelay-minDelay)))
}

// RandomBirthDate generates a random birth date for age gates
func RandomBirthDate() string {
	// Generate someone between 25 and 55 years old
	now := time.Now()
	years := rand.Intn(30) + 25
	month := rand.Intn(12) + 1
	day := rand.Intn(28) + 1

	birthDate := now.AddDate(-years, -rand.Intn(12), -rand.Intn(28))
	return fmt.Sprintf("%02d/%02d/%d", day, month, birthDate.Year())
}

// UserAgents for rotation (updated to 2025-2026 era)
var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.3065.82",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.99",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
}

// RandomUserAgent returns a random user agent
func RandomUserAgent() string {
	return UserAgents[rand.Intn(len(UserAgents))]
}

// Helper functions

// RandomRAM returns a random RAM size in GB.
func RandomRAM() int {
	ramOptions := []int{4, 8, 16, 32}
	return ramOptions[rand.Intn(len(ramOptions))]
}

// RandomCoreCount returns a random CPU core count.
func RandomCoreCount() int {
	coreOptions := []int{4, 8, 12, 16}
	return coreOptions[rand.Intn(len(coreOptions))]
}

// Timezone offsets (simplified)
var timezoneOffsets = map[string]int{
	"America/New_York":    300,  // EST
	"America/Chicago":     360,  // CST
	"America/Denver":      420,  // MST
	"America/Los_Angeles": 480,  // PST
	"America/Sao_Paulo":   -180, // BRT
	"Europe/London":       0,    // GMT
	"Europe/Paris":        -60,  // CET
	"Europe/Berlin":       -60,  // CET
	"Asia/Tokyo":          -540, // JST
	"Asia/Shanghai":       -480, // CST
	"Asia/Dubai":          -240, // GST
	"Asia/Singapore":      -480, // SGT
	"Australia/Sydney":    -660, // AEST
}

func getTimezoneOffset(tz string) int {
	if offset, ok := timezoneOffsets[tz]; ok {
		return offset
	}
	return 300 // Default to EST
}

func randomGPUVendor() string {
	vendors := []string{
		"Intel Inc.",
		"NVIDIA Corporation",
		"AMD",
		"Apple Inc.",
	}
	return vendors[rand.Intn(len(vendors))]
}

func randomGPURenderer() string {
	renderers := []string{
		"Intel(R) Iris(R) Xe Graphics",
		"Intel(R) UHD Graphics 770",
		"Intel(R) Arc(TM) A770",
		"NVIDIA GeForce RTX 3060",
		"NVIDIA GeForce RTX 4060",
		"NVIDIA GeForce RTX 4070",
		"AMD Radeon RX 6700 XT",
		"AMD Radeon RX 7600",
		"Apple M2",
		"Apple M3",
		"Apple M4",
	}
	return renderers[rand.Intn(len(renderers))]
}

// RandomFloat returns a random float between minVal and maxVal.
func RandomFloat(minVal, maxVal float64) float64 {
	return minVal + rand.Float64()*(maxVal-minVal)
}

// bezier calculates a point on a quadratic Bezier curve
func bezier(p0, p1, p2, t float64) float64 {
	return (1-t)*(1-t)*p0 + 2*(1-t)*t*p1 + t*t*p2
}


// Note: rand.Seed is deprecated since Go 1.20.
// The global random generator is automatically seeded.
