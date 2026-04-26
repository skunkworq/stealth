// Package chromium provides StealthPlus anti-detection enhancements.
// These features close the gap with nodriver-style stealth without adding
// tab-management or visual-CAPTCHA capabilities.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter
package chromium

import (
	"context"
	"fmt"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// --- StealthPlus: Permission Grants ---

// allPermissions is the full list of permissions nodriver proactively grants.
var allPermissions = []browser.PermissionType{
	browser.PermissionTypeAccessibilityEvents,
	browser.PermissionTypeAudioCapture,
	browser.PermissionTypeBackgroundSync,
	browser.PermissionTypeClipboardRead,
	browser.PermissionTypeClipboardSanitizedWrite,
	browser.PermissionTypeDisplayCapture,
	browser.PermissionTypeDurableStorage,
	browser.PermissionTypeFlash,
	browser.PermissionTypeGeolocation,
	browser.PermissionTypeIdleDetection,
	browser.PermissionTypeLocalFonts,
	browser.PermissionTypeMidi,
	browser.PermissionTypeMidiSysex,
	browser.PermissionTypeNotifications,
	browser.PermissionTypePaymentHandler,
	browser.PermissionTypePeriodicBackgroundSync,
	browser.PermissionTypeProtectedMediaIdentifier,
	browser.PermissionTypeSensors,
	browser.PermissionTypeStorageAccess,
	browser.PermissionTypeVideoCapture,
	browser.PermissionTypeWakeLockScreen,
	browser.PermissionTypeWindowManagement,
}

// GrantAllPermissions uses CDP Browser.grantPermissions to remove permission
// prompts that can signal automation.  This is the nodriver equivalent of
// browser.grant_all_permissions().
func (s *StealthEngine) GrantAllPermissions(ctx context.Context) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	for _, perm := range allPermissions {
		if err := browser.GrantPermissions([]browser.PermissionType{perm}).
			WithOrigin("*").Do(tabCtx); err != nil {
			// Some permissions may not be supported on all Chrome versions;
			// log and continue rather than failing entirely.
			s.logger.Debug("failed to grant permission", "permission", perm, "error", err)
		}
	}

	s.logger.Info("StealthPlus: all permissions granted")
	return nil
}

// --- StealthPlus: user_gesture evaluation ---

// EvaluateWithGesture executes JavaScript via CDP with userGesture=true.
// This unlocks APIs gated behind user interaction (autoplay, popups, etc.)
// and is the nodriver equivalent of setting user_gesture=True on evaluations.
// The caller must provide a valid chromedp context (e.g. from NewContext).
func (s *StealthEngine) EvaluateWithGesture(ctx context.Context, expression string) (interface{}, error) {
	if !s.config.StealthPlus {
		return nil, fmt.Errorf("StealthPlus is not enabled")
	}

	var result interface{}
	action := chromedp.ActionFunc(func(c context.Context) error {
		// Runtime.evaluate with userGesture=true
		evalParams := runtime.Evaluate(expression).
			WithUserGesture(true).
			WithAwaitPromise(true).
			WithReturnByValue(true)

		remoteObj, exp, err := evalParams.Do(c)
		if err != nil {
			return err
		}
		if exp != nil {
			return fmt.Errorf("js exception: %s", exp.Description)
		}
		if remoteObj != nil && remoteObj.Value != nil {
			result = remoteObj.Value
		}
		return nil
	})

	if err := chromedp.Run(ctx, action); err != nil {
		return nil, fmt.Errorf("evaluate with gesture: %w", err)
	}
	return result, nil
}

// --- StealthPlus: Raw CDP Escape Hatch ---

// SendCDP executes an arbitrary chromedp Action against a fresh tab context.
// This provides the nodriver-style raw CDP access (equivalent to
// tab.send(cdp.command(...))).
func (s *StealthEngine) SendCDP(ctx context.Context, actions ...chromedp.Action) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	return chromedp.Run(tabCtx, actions...)
}

// --- StealthPlus: Network Interception (Fetch Domain) ---

// EnableFetchIntercept enables the CDP Fetch domain so requests can be
// paused, modified, or blocked.  This is the foundation for request/response
// interception that nodriver exposes via EventRequestPaused handlers.
func (s *StealthEngine) EnableFetchIntercept(ctx context.Context, patterns []*fetch.RequestPattern) error {
	if !s.config.StealthPlus {
		return fmt.Errorf("StealthPlus is not enabled")
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	return chromedp.Run(tabCtx, fetch.Enable().WithPatterns(patterns))
}

// FetchHandler is the callback signature for paused fetch requests.
type FetchHandler func(ctx context.Context, req *fetch.EventRequestPaused) error

// ListenFetchPaused registers a handler for fetch request-paused events.
// The handler can call fetch.FulfillRequest, fetch.ContinueRequest, or
// fetch.FailRequest to control the paused request.
func (s *StealthEngine) ListenFetchPaused(ctx context.Context, handler FetchHandler) {
	if !s.config.StealthPlus {
		s.logger.Warn("StealthPlus is not enabled; ListenFetchPaused is a no-op")
		return
	}

	tabCtx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if paused, ok := ev.(*fetch.EventRequestPaused); ok {
			if err := handler(tabCtx, paused); err != nil {
				s.logger.Error("fetch handler error", "error", err)
			}
		}
	})
}

// --- StealthPlus: CDP Object Handle Resolver ---

// ResolveRemoteObject returns the serialized Value from a runtime.RemoteObject
// if available.  For complex objects without an inline value it returns nil.
// This is a lightweight equivalent to nodriver's deep JS object dumps.
func ResolveRemoteObject(_ context.Context, obj *runtime.RemoteObject) (interface{}, error) {
	if obj == nil {
		return nil, nil
	}
	if obj.Value != nil {
		return obj.Value, nil
	}
	return nil, nil
}
