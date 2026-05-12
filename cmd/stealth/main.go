package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
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

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
	"github.com/skunkworq/stealth/brws/fingerprint/lab"
	"github.com/skunkworq/stealth/brws/content/semantic"
	"github.com/skunkworq/stealth/brws/crawl/spider"
)

var (
	version   = "0.1.0"
	revision  = "dev"
	goVersion = "go"

	spiderName  = flag.String("s", "", "Spider name to run")
	engineName  = flag.String("e", "native", "Engine to use")
	depthLimit  = flag.Int("d", 5, "Max crawl depth")
	timeout     = flag.Duration("t", 30*time.Second, "Request timeout")
	maxRequests = flag.Int("c", 16, "Max concurrent requests")
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "crawl", "run":
		if err := runCrawl(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := listSpiders(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "shell":
		if err := runShell(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "fetch":
		if err := runFetch(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "lab":
		if err := runLab(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "train":
		if err := runTrain(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		printVersion()
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Stealth Spider Framework v%s

Usage: stealth <command> [options]

Commands:
  crawl, run    Run a spider
  list          List available spiders
  shell         Open interactive shell
  fetch         Fetch URL and extract semantic tree
  lab           Start fingerprint capture lab with proxy
  train         Automated browser fingerprint training capture
  version       Show version info

Run 'stealth <command> --help' for more information on a command.

Available engines: %s
`, version, engine.Available())
}

func printVersion() {
	fmt.Printf("Stealth Spider Framework v%s (revision: %s, %s)\n", version, revision, goVersion)
}

func runFetch(args []string) error {
	// Simple flags
	engName := "native"
	jsonOutput := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-e":
			if i+1 < len(args) {
				engName = args[i+1]
				i++
			}
		case "-j":
			jsonOutput = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				break
			}
		}
	}

	url := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && a != "fetch" {
			url = a
			break
		}
	}

	if url == "" {
		return fmt.Errorf("URL required: stealth fetch <url>")
	}

	// Create engine
	eng, err := engine.New(engName, engine.Options{
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
		Timeout:     30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}
	defer eng.Close()

	// Make request with retry
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var resp *engine.Response
	retries := 3
	for i := 0; i < retries; i++ {
		resp, err = eng.Do(ctx, &engine.Request{
			URL:               url,
			Timeout:           30 * time.Second,
			WaitForNavigation: engName == "chromium",
		})
		if err == nil {
			break
		}
		log.Printf("Attempt %d failed: %v", i+1, err)
		if i < retries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}
	if err != nil {
		return fmt.Errorf("request failed after %d retries: %w", retries, err)
	}

	// Extract semantic tree
	config := &semantic.PipelineConfig{
		MaxChunks:        50,
		MaxConcurrentLLM: 0,
	}

	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, string(resp.Body), url, config)
	if err != nil {
		return fmt.Errorf("extract semantic: %w", err)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(tree, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Print summary
	fmt.Printf("Status: %d\n", resp.Status)
	fmt.Printf("Size: %d bytes\n", len(resp.Body))

	if tree != nil {
		fmt.Printf("\n=== Semantic Tree ===\n")
		fmt.Printf("Title: %s\n", tree.Title)
		fmt.Printf("Domain: %s\n", tree.Domain)

		allNodes := tree.AllNodes()
		fmt.Printf("Nodes: %d\n", len(allNodes))

		actionCount := 0
		for _, n := range allNodes {
			actionCount += len(n.Actions)
		}
		fmt.Printf("Actions: %d\n", actionCount)

		if stats != nil && stats.FullTreeTokens > 0 {
			ratio := float64(stats.CompressedTokens) / float64(stats.FullTreeTokens) * 100
			fmt.Printf("Tokens: %d -> %d (%.1f%% compression)\n",
				stats.FullTreeTokens, stats.CompressedTokens, ratio)
		}
	}

	return nil
}

func runCrawl(args []string) error {
	_ = flag.CommandLine.Parse(args)

	if *spiderName == "" {
		return fmt.Errorf("spider name is required (-s flag)")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	settings := spider.NewSettings()
	settings.Set("ENGINE", *engineName)
	settings.Set("MAX_DEPTH", *depthLimit)
	settings.Set("DOWNLOAD_TIMEOUT", *timeout)
	settings.Set("CONCURRENT_REQUESTS", *maxRequests)

	spiderObj := spider.NewSpider(*spiderName, []*spider.Request{
		spider.NewRequest("http://example.com", nil),
	}, func(resp spider.Response) []*spider.Request {
		return nil
	})

	c := spider.NewCrawler(spiderObj,
		spider.WithSettings(settings),
		spider.WithEngine(*engineName),
		spider.WithConcurrentRequests(*maxRequests),
		spider.WithMaxDepth(*depthLimit),
	)

	c.Pipelines().AddPipeline(spider.PipelineFromFunc(func(resp *spider.Response) error {
		fmt.Printf("[%d] %s (%d bytes)\n", resp.Status, resp.URL, len(resp.Body))
		return nil
	}))

	fmt.Printf("Starting crawl: %s\n", *spiderName)
	fmt.Printf("Engine: %s\n", *engineName)
	fmt.Printf("Max depth: %d\n", *depthLimit)

	return c.Run()
}

func listSpiders(args []string) error {
	_ = flag.CommandLine.Parse(args)

	fmt.Println("Available spiders:")
	fmt.Println("  (no spiders found)")
	fmt.Println()

	fmt.Println("Available engines:")
	engines := engine.Available()
	for _, e := range engines {
		fmt.Printf("  - %s\n", e)
	}

	return nil
}

func runShell(args []string) error {
	_ = flag.CommandLine.Parse(args)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nExiting shell...")
		os.Exit(0)
	}()

	eng, err := engine.New(*engineName, engine.Options{
		Stealth: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	defer func() { _ = eng.Close() }()

	fmt.Println("Stealth Shell v0.1.0")
	fmt.Println("Type 'help' for available commands, 'exit' to quit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}
		if line == "help" {
			printShellHelp()
			continue
		}
		if strings.HasPrefix(line, "get ") {
			url := strings.TrimPrefix(line, "get ")
			resp, err := eng.Do(ctx, &engine.Request{
				Method: "GET",
				URL:    url,
			})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			fmt.Printf("Status: %d %s\n", resp.Status, resp.StatusText)
			fmt.Printf("Body: %d bytes\n", len(resp.Body))
			continue
		}
		fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", line)
	}

	return nil
}

func printShellHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  get <url>     Fetch a URL")
	fmt.Println("  help          Show this help")
	fmt.Println("  exit, quit    Exit the shell")
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [command] [options]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
}

// runLab starts the fingerprint capture lab server with MITM proxy.
func runLab(args []string) error {
	fs := flag.NewFlagSet("lab", flag.ExitOnError)
	httpPort := fs.Int("port", 8080, "HTTP server port")
	httpsPort := fs.Int("https-port", 8443, "HTTPS server port")
	proxyPort := fs.Int("proxy-port", 8081, "MITM proxy port (0 to disable)")
	proxyMode := fs.String("proxy-mode", "mitm", "Proxy mode: mitm or transparent")
	chrome := fs.Bool("chrome", false, "Auto-launch Chrome with proxy configured")
	chromePath := fs.String("chrome-path", "", "Path to Chrome executable")
	storeDir := fs.String("store", "", "Directory to persist captured fingerprints")
	verbose := fs.Bool("v", false, "Verbose logging")
	transparent := fs.Bool("transparent", false, "Use transparent proxy (preserves browser TLS)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `stealth lab — Start the fingerprint capture lab

Starts an HTTP server, HTTPS server, and MITM proxy for capturing
real browser fingerprints (TLS, HTTP/2, HTTP headers).

Usage:
  stealth lab [flags]

Examples:
  stealth lab                    # Start lab + MITM proxy
  stealth lab --chrome           # Start lab + auto-launch Chrome
  stealth lab --transparent      # Transparent proxy (preserves TLS)
  stealth lab --store ./captures # Persist fingerprints to disk

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Once running:
  Dashboard:    http://localhost:8080/
  Captures:     http://localhost:8080/captures
  Proxy PAC:    http://localhost:8080/proxy.pac
  Export JSON:  http://localhost:8080/capture/json`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *transparent {
		*proxyMode = "transparent"
	}

	// Setup logging
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	// Auto-generate TLS certs
	certFile, keyFile, err := ensureLabCerts(logger)
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}

	enableProxy := *proxyPort > 0

	fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║              Stealth Fingerprint Lab                          ║
╚═══════════════════════════════════════════════════════════════╝

  HTTP:       http://localhost:%d/
  HTTPS:      https://localhost:%d/
  Proxy:      %s
  Mode:       %s
  Store:      %s

  Configure browser proxy → localhost:%d
  Or use PAC:  http://localhost:%d/proxy.pac

  Press Ctrl+C to stop

`, *httpPort, *httpsPort,
		func() string {
			if enableProxy {
				return fmt.Sprintf("localhost:%d", *proxyPort)
			}
			return "disabled"
		}(),
		*proxyMode,
		func() string {
			if *storeDir != "" {
				return *storeDir
			}
			return "(in-memory)"
		}(),
		*proxyPort, *httpPort)

	config := &lab.ServerConfig{
		BindAddr:        "0.0.0.0",
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
		EnableProxy:     enableProxy,
	}

	server := lab.NewEnhancedServer(config, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nShutting down lab...")
		if stopErr := server.Stop(ctx); stopErr != nil {
			logger.Error("Shutdown error", "error", stopErr)
		}
		os.Exit(0)
	}()

	// Launch Chrome if requested
	if *chrome && enableProxy {
		go func() {
			time.Sleep(500 * time.Millisecond)
			if launchErr := labLaunchChrome(*chromePath, *proxyPort, *httpPort, logger); launchErr != nil {
				logger.Error("Failed to launch Chrome", "error", launchErr)
			}
		}()
	}

	return server.Start()
}

// ensureLabCerts generates self-signed TLS certs if they don't exist.
func ensureLabCerts(logger *slog.Logger) (certFile, keyFile string, err error) {
	cacheDir, _ := os.UserCacheDir()
	if cacheDir == "" {
		cacheDir = "/tmp"
	}
	certDir := filepath.Join(cacheDir, "stealth-lab")
	_ = os.MkdirAll(certDir, 0o750)

	certFile = filepath.Join(certDir, "lab.crt")
	keyFile = filepath.Join(certDir, "lab.key")

	if _, statErr := os.Stat(certFile); statErr == nil {
		return certFile, keyFile, nil
	}

	logger.Info("Generating self-signed TLS certificates...")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Stealth Lab"},
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
		return "", "", fmt.Errorf("creating certificate: %w", err)
	}

	certOut, err := os.Create(certFile) //nolint:gosec
	if err != nil {
		return "", "", fmt.Errorf("writing cert: %w", err)
	}
	defer certOut.Close()
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.Create(keyFile) //nolint:gosec
	if err != nil {
		return "", "", fmt.Errorf("writing key: %w", err)
	}
	defer keyOut.Close()
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	logger.Info("Certificates generated", "cert", certFile, "key", keyFile)
	return certFile, keyFile, nil
}

// labLaunchChrome launches Chrome configured to use the lab proxy.
func labLaunchChrome(chromePath string, proxyPort, httpPort int, logger *slog.Logger) error {
	if chromePath == "" {
		chromePath = labFindChrome()
	}
	if chromePath == "" {
		return fmt.Errorf("chrome not found — install Chrome or use --chrome-path")
	}

	tmpDir, err := os.MkdirTemp("", "stealth-lab-chrome-*")
	if err != nil {
		return fmt.Errorf("creating temp profile: %w", err)
	}

	chromeArgs := []string{
		fmt.Sprintf("--proxy-server=localhost:%d", proxyPort),
		"--ignore-certificate-errors",
		"--ignore-urlfetcher-cert-requests",
		"--test-type",
		"--user-data-dir=" + tmpDir,
		fmt.Sprintf("http://localhost:%d/", httpPort),
	}

	logger.Info("Launching Chrome",
		"path", chromePath,
		"proxy", fmt.Sprintf("localhost:%d", proxyPort),
		"profile", tmpDir,
	)

	//nolint:gosec
	cmd := exec.Command(chromePath, chromeArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

// runTrain starts an automated training session that launches Chrome,
// navigates to specified URLs, and captures complete browser fingerprints.
func runTrain(args []string) error {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	urls := fs.String("urls", "", "Comma-separated list of URLs to capture")
	outputDir := fs.String("output", "", "Directory to save training data (default: ./training-data/<timestamp>)")
	proxyPort := fs.Int("proxy-port", 18081, "MITM proxy port for TLS capture")
	chromePath := fs.String("chrome-path", "", "Path to Chrome executable")
	pageWait := fs.Duration("page-wait", 5*time.Second, "Wait time after page load for network settle")
	noScroll := fs.Bool("no-scroll", false, "Disable page scrolling")
	verbose := fs.Bool("v", false, "Verbose logging")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `stealth train — Automated browser fingerprint training

Launches Chrome via CDP, navigates to each URL, and captures complete
browser fingerprints (TLS via MITM proxy + HTTP headers via CDP).

Usage:
  stealth train --urls <url1,url2,...> [flags]

Examples:
  stealth train --urls coles.com.au,afterpay.com
  stealth train --urls afterpay.com --output ./my-captures -v
  stealth train --urls google.com,github.com --page-wait 10s

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Output:
  training_report.json     Full report with all captures
  capture_01_<host>.json   Per-page capture data
  header_patterns.json     Aggregated header ordering patterns`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *urls == "" {
		return fmt.Errorf("--urls is required: stealth train --urls coles.com.au,afterpay.com")
	}

	// Parse URL list
	urlList := strings.Split(*urls, ",")
	for i := range urlList {
		urlList[i] = strings.TrimSpace(urlList[i])
	}

	// Default output directory
	if *outputDir == "" {
		ts := time.Now().Format("20060102-150405")
		*outputDir = filepath.Join("training-data", ts)
	}

	// Setup logging
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	// Generate certs for MITM proxy
	certFile, keyFile, err := ensureLabCerts(logger)
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}

	fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║              Stealth Training Session                         ║
╚═══════════════════════════════════════════════════════════════╝

  URLs:         %s
  Output:       %s
  Proxy:        localhost:%d (MITM for TLS capture)
  CDP:          Chrome DevTools Protocol (header capture)
  Page wait:    %s
  Scroll:       %v

  Starting...

`, strings.Join(urlList, ", "), *outputDir, *proxyPort, *pageWait, !*noScroll)

	config := &lab.TrainerConfig{
		URLs:         urlList,
		OutputDir:    *outputDir,
		ProxyPort:    *proxyPort,
		ChromePath:   *chromePath,
		PageLoadWait: *pageWait,
		ScrollPage:   !*noScroll,
		Verbose:      *verbose,
		CACertFile:   certFile,
		CAKeyFile:    keyFile,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nAborting training session...")
		cancel()
	}()

	trainer := lab.NewTrainer(config, logger)
	report, err := trainer.Run(ctx)
	if err != nil {
		return fmt.Errorf("training failed: %w", err)
	}

	// Print summary
	fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║              Training Complete                                ║
╚═══════════════════════════════════════════════════════════════╝

  Duration:     %s
  Pages:        %d

`, report.Duration, report.PagesCount)

	for _, page := range report.Pages {
		navHeaders := 0
		if page.NavigationRequest != nil {
			navHeaders = len(page.NavigationRequest.Headers)
		}
		fmt.Fprintf(os.Stderr, "  %-40s title=%q nav_headers=%d sub_requests=%d tls=%d\n",
			page.URL, truncate(page.Title, 30), navHeaders, len(page.SubRequests), len(page.TLSCaptures))
	}

	if report.HeaderPatterns != nil && len(report.HeaderPatterns.NavigationHeaderOrder) > 0 {
		fmt.Fprintf(os.Stderr, "\n  Navigation header order (Chrome native):\n")
		for i, h := range report.HeaderPatterns.NavigationHeaderOrder {
			fmt.Fprintf(os.Stderr, "    %2d. %s\n", i+1, h)
		}
	}

	fmt.Fprintf(os.Stderr, "\n  Output:       %s\n\n", *outputDir)

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// labFindChrome locates the Chrome executable on the system.
func labFindChrome() string {
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		}
	case "linux":
		candidates = []string{
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
		}
	case "windows":
		candidates = []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		}
	}

	for _, p := range candidates {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("google-chrome"); err == nil {
		return p
	}
	return ""
}
