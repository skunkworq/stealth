// Package chromium provides stealth enhancements for the Chromium engine.
// This file contains advanced anti-detection techniques for browser automation.
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter/randomization
package chromium

import (
	"fmt"
	//nolint:gosec // math/rand is used intentionally for non-cryptographic jitter/randomization
	"math/rand"
	"time"
)

// StealthConfig contains configuration for stealth mode
type StealthConfig struct {
	// Spoof device memory (RAM)
	DeviceMemoryGB int

	// Spoof platform
	Platform string

	// WebGL vendor/renderer
	WebGLVendor   string
	WebGLRenderer string

	// Enable canvas fingerprint randomization
	CanvasNoise bool

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
}

// DefaultStealthConfig returns a default stealth configuration
func DefaultStealthConfig() *StealthConfig {
	return &StealthConfig{
		DeviceMemoryGB:  RandomRAM(),
		Platform:        "Win32",
		WebGLVendor:     randomGPUVendor(),
		WebGLRenderer:   randomGPURenderer(),
		CanvasNoise:     true,
		HumanizeMouse:   true,
		MinDelay:        100 * time.Millisecond,
		MaxDelay:        500 * time.Millisecond,
		ChromeVersion:   "120.0.6099.109",
		PlatformVersion: "10.0.0",
		Timezone:        "America/New_York",
		ScreenWidth:     1920,
		ScreenHeight:    1080,
	}
}

// ChromeVersions for client hints
var ChromeVersions = []string{
	"120.0.6099.109",
	"121.0.6167.85",
	"122.0.6266.112",
	"123.0.6312.66",
	"124.0.6360.122",
}

// GenerateStealthScript generates the JavaScript to inject for stealth
func GenerateStealthScript(config *StealthConfig) string {
	if config == nil {
		config = DefaultStealthConfig()
	}

	// Generate client hints strings
	chromeVersion := config.ChromeVersion
	if chromeVersion == "" {
		chromeVersion = "120.0.6099.109"
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

	return fmt.Sprintf(`
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
    Object.defineProperty(window, 'devicePixelRatio', { get: () => 1 });
    Object.defineProperty(window, 'screenX', { get: () => 0 });
    Object.defineProperty(window, 'screenY', { get: () => 0 });
    Object.defineProperty(window, 'screenLeft', { get: () => 0 });
    Object.defineProperty(window, 'screenTop', { get: () => 0 });
    
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
    
    // 10. WebGL Spoofing
    const fakeWebGLContext = {
        getSupportedExtensions: () => ['WEBGL_debug_renderer_info'],
        getExtension: (name) => {
            if (name === 'WEBGL_debug_renderer_info') {
                return {
                    UNMASKED_VENDOR_WEBGL: 0x9245,
                    UNMASKED_RENDERER_WEBGL: 0x9246,
                };
            }
            return null;
        },
        getParameter: (param) => {
            if (param === 0x9245) return '%s';  // UNMASKED_VENDOR_WEBGL
            if (param === 0x9246) return '%s';  // UNMASKED_RENDERER_WEBGL
            return null;
        },
    };
    
    // 11. Canvas Fingerprint Randomization
    const rand = (min = 0, max = 1) => Math.random() * (max - min) + min;
    
    const realCreateElement = document.createElement.bind(document);
    document.createElement = function(tagName) {
        if (tagName.toLowerCase() === 'video') {
            const realVideo = realCreateElement('video');
            realVideo.canPlayType = fakeVideoElement.canPlayType;
            return realVideo;
        } else if (tagName.toLowerCase() === 'canvas') {
            const realCanvas = realCreateElement('canvas');
            const originalGetContext = realCanvas.getContext.bind(realCanvas);
            
            realCanvas.getContext = function(contextType, ...args) {
                const ctx = originalGetContext(contextType, ...args);
                
                if (contextType === 'webgl' || contextType === 'experimental-webgl') {
                    return fakeWebGLContext;
                } else if (contextType === '2d' && ctx) {
                    // Add subtle noise to canvas operations
                    const origFillText = ctx.fillText.bind(ctx);
                    const origGetImageData = ctx.getImageData.bind(ctx);
                    const origDrawImage = ctx.drawImage?.bind(ctx);
                    
                    // Patch fillText to add minor translation noise
                    ctx.fillText = function(text, x, y, ...rest) {
                        const dx = rand(-0.2, 0.2);
                        const dy = rand(-0.2, 0.2);
                        return origFillText(text, x + dx, y + dy, ...rest);
                    };
                    
                    // Patch getImageData to modify pixels slightly
                    ctx.getImageData = function(sx, sy, sw, sh) {
                        const imageData = origGetImageData(sx, sy, sw, sh);
                        for (let i = 0; i < imageData.data.length; i += 4) {
                            // Flip least significant bit randomly (1-2%% of pixels)
                            if (Math.random() > 0.98) {
                                imageData.data[i] ^= 1;     // Red
                                imageData.data[i + 1] ^= 1; // Green
                            }
                        }
                        return imageData;
                    };
                    
                    // Patch drawImage with slight shift
                    if (origDrawImage) {
                        ctx.drawImage = function(img, sx, sy, ...args) {
                            const dx = rand(-0.3, 0.3);
                            const dy = rand(-0.3, 0.3);
                            return origDrawImage(img, sx + dx, sy + dy, ...args);
                        };
                    }
                    
                    // Apply rendering property noise
                    ctx.globalAlpha = rand(0.98, 1.0);
                    ctx.shadowBlur = rand(0, 0.5);
                    
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
    
    // 13. Plugin spoofing
    Object.defineProperty(navigator, 'plugins', {
        get: () => [
            {
                name: 'Chrome PDF Plugin',
                filename: 'internal-pdf-viewer',
                description: 'Portable Document Format',
                version: 'undefined',
                length: 1,
                item: () => null,
                namedItem: () => null
            }
        ]
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
    
    console.log('[Stealth] Anti-detection scripts injected successfully');
})();
`,
		config.DeviceMemoryGB,
		RandomCoreCount(),
		config.Platform,
		screenWidth, screenHeight,
		screenWidth, screenHeight-40, // minus taskbar
		screenWidth-80, screenHeight-80, // inner window
		screenWidth, screenHeight, // outer
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
		config.WebGLRenderer)
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

// RandomDelay returns a random delay between min and max
func RandomDelay(min, max time.Duration) time.Duration {
	return min + time.Duration(RandomFloat(0, float64(max-min)))
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

// UserAgents for rotation
var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.83",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.65",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.61",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

// RandomUserAgent returns a random user agent
func RandomUserAgent() string {
	return UserAgents[rand.Intn(len(UserAgents))]
}

// Helper functions

func RandomRAM() int {
	ramOptions := []int{4, 8, 16, 32}
	return ramOptions[rand.Intn(len(ramOptions))]
}

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
		"Intel(R) Iris(TM) Xe Graphics",
		"Intel(R) UHD Graphics",
		"NVIDIA GeForce GTX 1060",
		"NVIDIA GeForce RTX 3060",
		"AMD Radeon RX 580",
		"Apple M1",
		"Apple M2",
	}
	return renderers[rand.Intn(len(renderers))]
}

func RandomFloat(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}

// bezier calculates a point on a quadratic Bezier curve
func bezier(p0, p1, p2, t float64) float64 {
	return (1-t)*(1-t)*p0 + 2*(1-t)*t*p1 + t*t*p2
}

// easeInOutCubic applies easing to time t (0-1)
func easeInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	p := -2*t + 2
	return 1 - p*p*p/2
}

// Note: rand.Seed is deprecated since Go 1.20.
// The global random generator is automatically seeded.
