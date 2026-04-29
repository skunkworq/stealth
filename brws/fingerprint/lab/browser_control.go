package lab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// BrowserController manages Chrome/browser process lifecycle
type BrowserController struct {
	cmd        *exec.Cmd
	chromePath string
	tmpDir     string
	running    bool
}

// findChrome attempts to find Chrome executable on the system
func findChrome() string {
	var candidates []string

	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chrome.app/Contents/MacOS/Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "linux":
		candidates = []string{
			"google-chrome",
			"google-chrome-stable",
			"chromium",
			"chromium-browser",
			"/usr/bin/google-chrome",
			"/usr/bin/chromium",
		}
	case "windows":
		candidates = []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		}
	}

	for _, path := range candidates {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Try PATH lookup
	if path, err := exec.LookPath("google-chrome"); err == nil {
		return path
	}
	if path, err := exec.LookPath("chromium"); err == nil {
		return path
	}

	return ""
}

// LaunchChrome starts a Chrome instance configured to use the proxy
func (s *EnhancedServer) LaunchChrome(targetURL string, headless bool) error {
	s.browserMu.Lock()
	defer s.browserMu.Unlock()

	if s.browser != nil && s.browser.running {
		return fmt.Errorf("chrome is already running")
	}

	chromePath := findChrome()
	if chromePath == "" {
		return fmt.Errorf("chrome not found: install Chrome or set chrome-path")
	}

	// Create temp user data dir
	tmpDir, err := os.MkdirTemp("", "labd-chrome-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}

	proxyAddr := fmt.Sprintf("localhost:%d", s.config.ProxyPort)
	labURL := targetURL
	if labURL == "" {
		labURL = fmt.Sprintf("http://localhost:%d/", s.config.HTTPPort)
	}

	args := []string{
		"--proxy-server=" + proxyAddr,
		"--ignore-certificate-errors",
		"--ignore-urlfetcher-cert-requests",
		"--test-type",
		"--user-data-dir=" + tmpDir,
	}

	if headless {
		args = append(args,
			"--headless",
			"--disable-blink-features=AutomationControlled",
			"--window-size=1920,1080",
			"--disable-infobars",
			"--no-default-browser-check",
		)
	}

	args = append(args, labURL)

	s.logger.Info("Launching Chrome",
		"path", chromePath,
		"proxy", proxyAddr,
		"profile", tmpDir,
	)

	//nolint:gosec // Browser execution is intentional design
	cmd := exec.Command(chromePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("starting Chrome: %w", err)
	}

	s.browser = &BrowserController{
		cmd:        cmd,
		chromePath: chromePath,
		tmpDir:     tmpDir,
		running:    true,
	}

	// Monitor process exit
	go func() {
		_ = cmd.Wait()
		s.browserMu.Lock()
		if s.browser != nil {
			s.browser.running = false
		}
		s.browserMu.Unlock()
		s.logger.Info("Chrome process exited")
		// Cleanup temp dir
		_ = os.RemoveAll(tmpDir)
	}()

	return nil
}

// StopChrome terminates the running Chrome instance
func (s *EnhancedServer) StopChrome() error {
	s.browserMu.Lock()
	defer s.browserMu.Unlock()

	if s.browser == nil || !s.browser.running {
		return fmt.Errorf("chrome is not running")
	}

	s.logger.Info("Stopping Chrome")
	// If the process has already crashed/stopped, this might return an error, handle gracefully
	if s.browser.cmd.Process != nil {
		_ = s.browser.cmd.Process.Kill()
	}

	s.browser.running = false
	return nil
}

// StatusResponse is the JSON response for /api/status
type StatusResponse struct {
	Proxy  ProxyStatus  `json:"proxy"`
	Chrome ChromeStatus `json:"chrome"`
	Server ServerStatus `json:"server"`
}

// ProxyStatus represents the status of a proxy connection.
type ProxyStatus struct {
	Running bool   `json:"running"`
	Address string `json:"address,omitempty"`
	PACUrl  string `json:"pac_url,omitempty"`
}

// ChromeStatus represents the status of a Chrome browser instance.
type ChromeStatus struct {
	Running    bool   `json:"running"`
	ChromePath string `json:"chrome_path,omitempty"`
	PID        int    `json:"pid,omitempty"`
}

// ServerStatus represents the overall server status.
type ServerStatus struct {
	HTTPPort     int  `json:"http_port"`
	HTTPSPort    int  `json:"https_port"`
	ProxyPort    int  `json:"proxy_port"`
	ProxyEnabled bool `json:"proxy_enabled"`
}

// handleAPIStatus returns the current status of proxy, Chrome, and server
func (s *EnhancedServer) handleAPIStatus(w http.ResponseWriter, _ *http.Request) {
	s.browserMu.Lock()
	chromeStatus := ChromeStatus{}
	if s.browser != nil && s.browser.running {
		chromeStatus.Running = true
		chromeStatus.ChromePath = s.browser.chromePath
		chromeStatus.PID = s.browser.cmd.Process.Pid
	}
	s.browserMu.Unlock()

	proxyStatus := ProxyStatus{
		Running: s.proxy != nil,
	}
	if s.proxy != nil && s.proxyConfig != nil {
		proxyStatus.Address = s.proxyConfig.ListenAddr
		proxyStatus.PACUrl = fmt.Sprintf("http://localhost:%d/proxy.pac", s.config.HTTPPort)
	}

	status := StatusResponse{
		Proxy:  proxyStatus,
		Chrome: chromeStatus,
		Server: ServerStatus{
			HTTPPort:     s.config.HTTPPort,
			HTTPSPort:    s.config.HTTPSPort,
			ProxyPort:    s.config.ProxyPort,
			ProxyEnabled: s.config.EnableProxy,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleAPIProxyStart starts the MITM proxy
func (s *EnhancedServer) handleAPIProxyStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.proxy != nil {
		writeJSON(w, map[string]interface{}{"ok": true, "message": "Proxy already running"})
		return
	}

	// Enable proxy in config if not already
	s.config.EnableProxy = true
	if err := s.StartProxy(); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"message": "Proxy started",
		"address": s.proxyConfig.ListenAddr,
	})
}

// handleAPIProxyStop stops the MITM proxy
func (s *EnhancedServer) handleAPIProxyStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.proxy == nil {
		writeJSON(w, map[string]interface{}{"ok": true, "message": "Proxy not running"})
		return
	}

	if err := s.StopProxy(); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	s.proxy = nil
	writeJSON(w, map[string]interface{}{"ok": true, "message": "Proxy stopped"})
}

// LaunchChromeRequest represents a request to launch Chrome.
type LaunchChromeRequest struct {
	URL        string `json:"url"`
	Headless   bool   `json:"headless"`
	CloseAfter int    `json:"close_after"`
}

// handleAPIChromeLaunch launches Chrome with proxy configured
func (s *EnhancedServer) handleAPIChromeLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LaunchChromeRequest
	if r.Body != nil {
		// Ignore decode errors, fallback to empty defaults (e.g if empty body passed)
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	if err := s.LaunchChrome(req.URL, req.Headless); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	if req.CloseAfter > 0 {
		go func(duration int) {
			s.logger.Info("Scheduled auto-close for Chrome", "seconds", duration)
			time.Sleep(time.Duration(duration) * time.Second)
			_ = s.StopChrome()
		}(req.CloseAfter)
	}

	writeJSON(w, map[string]interface{}{"ok": true, "message": "Chrome launched"})
}

// handleAPIChromeStop stops the running Chrome instance
func (s *EnhancedServer) handleAPIChromeStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.StopChrome(); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{"ok": true, "message": "Chrome stopped"})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}
