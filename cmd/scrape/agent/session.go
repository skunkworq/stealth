package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

const (
	chromeStartTimeout = 15 * time.Second
	chromePollInterval = 200 * time.Millisecond
	portFileName       = "port"
)

// Session holds the state for a persistent browser session.
type Session struct {
	Dir        string
	ChromePath string
	Port       int
}

// ensureSession returns a chromedp context bound to a Chrome instance.
// If Chrome is not running for this session, it starts one.
func ensureSession(dir, chromePath string) (context.Context, context.CancelFunc, error) {
	if chromePath == "" {
		chromePath = findChrome()
	}
	if chromePath == "" {
		return nil, nil, fmt.Errorf("Chrome not found — install Chrome/Chromium or use --chrome-path")
	}

	// Ensure session directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, nil, fmt.Errorf("creating session dir: %w", err)
	}

	profileDir := filepath.Join(dir, "chrome-profile")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("creating chrome profile: %w", err)
	}

	port, err := readOrAllocatePort(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("allocating port: %w", err)
	}

	// Try connecting to existing Chrome first
	if isChromeReady(port) {
		ctx, cancel, err := connectToChrome(port)
		if err == nil {
			return ctx, cancel, nil
		}
		// Connection failed — Chrome may have died. Fall through to start.
	}

	// Start Chrome
	if err := startChrome(chromePath, port, profileDir); err != nil {
		return nil, nil, fmt.Errorf("starting Chrome: %w", err)
	}

	// Wait for Chrome to be ready
	if err := waitForChrome(port, chromeStartTimeout); err != nil {
		return nil, nil, err
	}

	// Save port for future reconnections
	if err := os.WriteFile(filepath.Join(dir, portFileName), []byte(strconv.Itoa(port)), 0644); err != nil {
		return nil, nil, fmt.Errorf("saving port: %w", err)
	}

	return connectToChrome(port)
}

// stopSession kills the Chrome process for the given session.
func stopSession(dir string) error {
	port, err := readPort(dir)
	if err != nil {
		// No port file — nothing to stop
		return nil
	}

	// Try graceful shutdown via CDP first
	ctx, cancel, connErr := connectToChrome(port)
	if connErr == nil {
		_ = chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
			// Best-effort graceful close
			return nil
		}))
		cancel()
	}

	// Kill any process listening on the port
	if err := killProcessOnPort(port); err != nil {
		// Ignore errors — process may already be gone
		_ = err
	}

	// Clean up session files
	_ = os.Remove(filepath.Join(dir, portFileName))
	_ = os.Remove(filepath.Join(dir, "state.json"))
	return nil
}

// ---------------------------------------------------------------------------
// Chrome discovery & lifecycle
// ---------------------------------------------------------------------------

func findChrome() string {
	candidates := []string{
		"google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser",
		"chrome", "brave", "brave-browser",
	}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		)
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Chromium\Application\chrome.exe`,
		)
	}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
}

func startChrome(chromePath string, port int, profileDir string) error {
	args := []string{
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-default-apps",
		"--disable-background-timer-throttling",
		"--disable-renderer-backgrounding",
		"--disable-backgrounding-occluded-windows",
		"--headless=new",
	}
	cmd := exec.Command(chromePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("exec %s: %w", chromePath, err)
	}
	return nil
}

func connectToChrome(port int) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())
	allocatorCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, fmt.Sprintf("http://localhost:%d", port))

	// Create a tab context
	tabCtx, tabCancel := chromedp.NewContext(allocatorCtx)

	// Test connection with a simple ping
	if err := chromedp.Run(tabCtx, chromedp.Navigate("about:blank")); err != nil {
		tabCancel()
		allocCancel()
		cancel()
		return nil, nil, fmt.Errorf("connecting to Chrome on port %d: %w", port, err)
	}

	// Return a combined cancel that cleans up everything
	combinedCancel := func() {
		tabCancel()
		allocCancel()
		cancel()
	}
	return tabCtx, combinedCancel, nil
}

func isChromeReady(port int) bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/json/version", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitForChrome(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isChromeReady(port) {
			return nil
		}
		time.Sleep(chromePollInterval)
	}
	return fmt.Errorf("Chrome did not become ready on port %d within %v", port, timeout)
}

// ---------------------------------------------------------------------------
// Port management
// ---------------------------------------------------------------------------

func readOrAllocatePort(dir string) (int, error) {
	if port, err := readPort(dir); err == nil {
		return port, nil
	}
	return getFreePort()
}

func readPort(dir string) (int, error) {
	data, err := os.ReadFile(filepath.Join(dir, portFileName))
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return port, nil
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

func killProcessOnPort(port int) error {
	// Platform-specific port killing
	switch runtime.GOOS {
	case "darwin", "linux":
		// Use lsof to find PID, then kill
		cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", port))
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		pid := strings.TrimSpace(string(out))
		if pid == "" {
			return nil
		}
		return exec.Command("kill", "-9", pid).Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", fmt.Sprintf("for /f \"tokens=5\" %%a in ('netstat -ano ^| findstr :%d') do taskkill /F /PID %%a", port))
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
