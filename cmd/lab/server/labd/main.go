// labd - Browser fingerprint capture lab server
// Captures complete browser signatures across TLS, HTTP/2, and HTTP layers
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	lab "github.com/skunkworq/stealth/brws/research/fingerprint/capture"
)

func main() {
	var (
		bindAddr     = flag.String("bind", "0.0.0.0", "Bind address")
		httpPort     = flag.Int("http-port", 8080, "HTTP port")
		httpsPort    = flag.Int("https-port", 8443, "HTTPS port")
		proxyPort    = flag.Int("proxy-port", 8081, "MITM proxy port (0 to disable)")
		proxyMode    = flag.String("proxy-mode", "mitm", "Proxy mode: mitm or transparent")
		tlsCert      = flag.String("tls-cert", "", "TLS certificate file")
		tlsKey       = flag.String("tls-key", "", "TLS private key file")
		autoCerts    = flag.Bool("auto-certs", true, "Auto-generate certificates if not provided")
		storeDir     = flag.String("store", "", "Directory to store captures")
		launchChrome = flag.Bool("chrome", false, "Launch Chrome with proxy configured")
		chromePath   = flag.String("chrome-path", "", "Path to Chrome executable (auto-detected if empty)")
		verbose      = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	// Setup logging
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	// Handle auto-cert generation
	certFile := *tlsCert
	keyFile := *tlsKey

	if (certFile == "" || keyFile == "") && *autoCerts {
		cacheDir, _ := os.UserCacheDir()
		if cacheDir == "" {
			cacheDir = "/tmp"
		}
		certDir := filepath.Join(cacheDir, "labd")
		_ = os.MkdirAll(certDir, 0o750)

		certFile = filepath.Join(certDir, "labd.crt")
		keyFile = filepath.Join(certDir, "labd.key")

		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			logger.Info("Generating self-signed certificates...")
			if err := generateCerts(certFile, keyFile); err != nil {
				logger.Error("Failed to generate certificates", "error", err)
				os.Exit(1)
			}
			logger.Info("Certificates generated", "cert", certFile, "key", keyFile)
		}
	}

	logger.Info("Starting Browser Fingerprint Capture Lab",
		"version", "0.2.0",
		"http_port", *httpPort,
		"https_port", *httpsPort,
		"proxy_port", *proxyPort,
		"proxy_enabled", *proxyPort > 0,
	)

	if *proxyPort > 0 {
		logger.Info("Proxy configuration",
			"pac_url", fmt.Sprintf("http://localhost:%d/proxy.pac", *httpPort),
			"proxy_addr", fmt.Sprintf("localhost:%d", *proxyPort),
		)
	}

	// Create config
	config := &lab.ServerConfig{
		BindAddr:        *bindAddr,
		HTTPPort:        *httpPort,
		HTTPSPort:       *httpsPort,
		ProxyPort:       *proxyPort,
		ProxyMode:       *proxyMode,
		TLSCert:         certFile,
		TLSKey:          keyFile,
		CaptureRawBytes: true,
		CaptureTiming:   true,
		StoreCaptures:   *storeDir != "",
		CaptureDir:      *storeDir,
		EnableProxy:     *proxyPort > 0,
	}

	// Create server
	server := lab.NewEnhancedServer(config, logger)

	// Handle shutdown gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("Shutting down...")
		if err := server.Stop(ctx); err != nil {
			logger.Error("Error during shutdown", "error", err)
		}
		os.Exit(0)
	}()

	// Launch Chrome if requested
	if *launchChrome && *proxyPort > 0 {
		go func() {
			// Give server time to start
			time.Sleep(500 * time.Millisecond)
			if err := launchChromeWithProxy(*chromePath, *proxyPort, *httpPort, logger); err != nil {
				logger.Error("Failed to launch Chrome", "error", err)
			}
		}()
	}

	// Start server (blocks until error or signal)
	if err := server.Start(); err != nil {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}

// launchChromeWithProxy launches Chrome configured to use the proxy
func launchChromeWithProxy(chromePath string, proxyPort, httpPort int, logger *slog.Logger) error {
	if chromePath == "" {
		chromePath = findChrome()
	}
	if chromePath == "" {
		return fmt.Errorf("chrome not found: install Chrome or specify -chrome-path")
	}

	// Create temp user data dir
	tmpDir, err := os.MkdirTemp("", "labd-chrome-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}

	args := []string{
		"--proxy-server=" + fmt.Sprintf("localhost:%d", proxyPort),
		"--ignore-certificate-errors",
		"--ignore-urlfetcher-cert-requests",
		"--test-type", // Suppress cert warnings
		"--user-data-dir=" + tmpDir,
		fmt.Sprintf("http://localhost:%d/", httpPort),
	}

	logger.Info("Launching Chrome",
		"path", chromePath,
		"proxy", fmt.Sprintf("localhost:%d", proxyPort),
		"profile", tmpDir,
	)

	//nolint:gosec // Chrome browser execution is intentional
	cmd := exec.Command(chromePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

// findChrome attempts to find Chrome executable
func findChrome() string {
	candidates := []string{}

	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chrome.app/Contents/MacOS/Chrome",
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

// generateCerts creates self-signed certificates for HTTPS
// sanitizePath validates and cleans a file path to prevent directory traversal
func sanitizePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid path contains directory traversal: %s", path)
	}
	return cleanPath, nil
}

func generateCerts(certFile, keyFile string) error {
	safeCertFile, err := sanitizePath(certFile)
	if err != nil {
		return err
	}
	safeKeyFile, err := sanitizePath(keyFile)
	if err != nil {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LabD"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "*.localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certOut, err := os.Create(safeCertFile) //nolint:gosec // Path already sanitized above
	if err != nil {
		return fmt.Errorf("creating cert file: %w", err)
	}
	defer certOut.Close()
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.Create(safeKeyFile) //nolint:gosec // Path already sanitized above
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer keyOut.Close()
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}
