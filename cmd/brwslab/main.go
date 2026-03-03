// brwslab is the CLI for browser network fingerprint testing.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/skunkworq/stealth/brws/config"
	"github.com/skunkworq/stealth/brws/engine"
	_ "github.com/skunkworq/stealth/brws/engine/chromium"
	_ "github.com/skunkworq/stealth/brws/engine/firefox"
	_ "github.com/skunkworq/stealth/brws/engine/native"
	_ "github.com/skunkworq/stealth/brws/engine/webkit"
	"github.com/skunkworq/stealth/brws/lab"
	"github.com/skunkworq/stealth/brws/session"
)

var (
	// Global flags
	engineName   string
	proxy        string
	timeout      time.Duration
	profileDir   string
	traceFormat  string
	outputFormat string
	labURL       string

	// Session flags
	sessionID   string
	sessionName string

	// Fetch flags
	method         string
	headers        []string
	body           string
	followRedirect bool

	// Diff flags
	diffEngines []string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "brwslab",
		Short: "Browser network fingerprint testing tool",
		Long: `brwslab provides browser-grade network fidelity for legitimate testing
and deep fingerprint observability. It supports multiple engines:
native (Go net/http), chromium (CDP), firefox, and webkit (Playwright).`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&engineName, "engine", "native", "Engine: native|chromium|firefox|webkit")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "Proxy URL")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "Request timeout")
	rootCmd.PersistentFlags().StringVar(&profileDir, "profile-dir", "", "Persistent profile directory")
	rootCmd.PersistentFlags().StringVar(&traceFormat, "trace", "", "Trace format: har|json|none")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "pretty", "Output format: pretty|json|raw")
	rootCmd.PersistentFlags().StringVar(&labURL, "lab", "", "Lab server URL for fingerprint capture")

	// Add commands
	rootCmd.AddCommand(fetchCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(fingerprintCmd())
	rootCmd.AddCommand(diffCmd())
	rootCmd.AddCommand(traceCmd())
	rootCmd.AddCommand(listEnginesCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(replCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func fetchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <url>",
		Short: "Fetch a URL using the specified engine",
		Args:  cobra.ExactArgs(1),
		RunE:  runFetch,
	}

	cmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "HTTP headers")
	cmd.Flags().StringVarP(&body, "data", "d", "", "Request body")
	cmd.Flags().BoolVarP(&followRedirect, "location", "L", true, "Follow redirects")
	cmd.Flags().StringVar(&sessionID, "session", "", "Use existing session")

	return cmd
}

func runFetch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	urlStr := args[0]

	// Validate URL
	if _, err := url.Parse(urlStr); err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Create engine
	eng, err := engine.New(engineName, engine.Options{
		Proxy:      proxy,
		Timeout:    timeout,
		ProfileDir: profileDir,
		Headless:   true,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}
	_ = eng.Close()

	// Build request
	headerMap := make(map[string][]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headerMap[key] = append(headerMap[key], value)
		}
	}

	req := &engine.Request{
		Method:          method,
		URL:             urlStr,
		Headers:         headerMap,
		Body:            []byte(body),
		FollowRedirects: followRedirect,
		Timeout:         timeout,
		SessionID:       sessionID,
	}

	// Execute request
	resp, err := eng.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("fetching: %w", err)
	}

	// Output response
	switch outputFormat {
	case "json":
		return outputJSON(resp)
	case "raw":
		return outputRaw(resp)
	default:
		return outputPretty(resp)
	}
}

func outputJSON(resp *engine.Response) error {
	output := struct {
		Status   int                 `json:"status"`
		Headers  map[string][]string `json:"headers"`
		Body     string              `json:"body"`
		FinalURL string              `json:"final_url"`
		Protocol string              `json:"protocol"`
		Timing   engine.TimingInfo   `json:"timing"`
		Trace    engine.Trace        `json:"trace,omitempty"`
	}{
		Status:   resp.Status,
		Headers:  resp.Headers,
		Body:     string(resp.Body),
		FinalURL: resp.FinalURL,
		Protocol: resp.Protocol,
		Timing:   resp.Timing,
	}

	if traceFormat != "" {
		output.Trace = resp.Trace
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputRaw(resp *engine.Response) error {
	// HTTP-style output
	_, _ = fmt.Fprintf(os.Stdout, "HTTP/1.1 %d %s\n", resp.Status, resp.StatusText)
	for key, values := range resp.Headers {
		for _, value := range values {
			_, _ = fmt.Fprintf(os.Stdout, "%s: %s\n", key, value)
		}
	}
	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, string(resp.Body))
	return nil
}

func outputPretty(resp *engine.Response) error {
	_, _ = fmt.Fprintf(os.Stdout, "Status: %d %s\n", resp.Status, resp.StatusText)
	_, _ = fmt.Fprintf(os.Stdout, "Protocol: %s\n", resp.Protocol)
	_, _ = fmt.Fprintf(os.Stdout, "Final URL: %s\n", resp.FinalURL)
	_, _ = fmt.Fprintf(os.Stdout, "Timing: %v\n", resp.Timing.Total)
	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, "Headers:")
	for key, values := range resp.Headers {
		for _, value := range values {
			_, _ = fmt.Fprintf(os.Stdout, "  %s: %s\n", key, value)
		}
	}
	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, "Body:")
	bodyStr := string(resp.Body)
	if len(bodyStr) > 2000 {
		_, _ = fmt.Fprintln(os.Stdout, bodyStr[:2000] + "...")
	} else {
		_, _ = fmt.Fprintln(os.Stdout, bodyStr)
	}

	if traceFormat != "" {
		_, _ = fmt.Fprintln(os.Stdout)
		_, _ = fmt.Fprintln(os.Stdout, "Trace:")
		data, err := json.MarshalIndent(resp.Trace, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal trace: %w", err)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(data))
	}

	return nil
}

func sessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage browser sessions",
	}

	// session new
	newCmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new session",
		RunE:  runSessionNew,
	}
	newCmd.Flags().StringVar(&sessionName, "name", "", "Session name")
	newCmd.Flags().StringVar(&engineName, "engine", "chromium", "Engine for session")

	// session list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE:  runSessionList,
	}

	// session delete
	deleteCmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a session",
		Args:  cobra.ExactArgs(1),
		RunE:  runSessionDelete,
	}

	// session export-cookies
	exportCmd := &cobra.Command{
		Use:   "export-cookies <session-id> <output-file>",
		Short: "Export session cookies",
		Args:  cobra.ExactArgs(2),
		RunE:  runSessionExportCookies,
	}

	// session import-cookies
	importCmd := &cobra.Command{
		Use:   "import-cookies <session-id> <input-file>",
		Short: "Import cookies into session",
		Args:  cobra.ExactArgs(2),
		RunE:  runSessionImportCookies,
	}

	cmd.AddCommand(newCmd, listCmd, deleteCmd, exportCmd, importCmd)
	return cmd
}

func runSessionNew(cmd *cobra.Command, args []string) error {
	sessionsDir := getSessionsDir()
	mgr, err := session.NewManager(sessionsDir)
	if err != nil {
		return fmt.Errorf("creating session manager: %w", err)
	}

	sess, err := mgr.Create(sessionName, engineName)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "Created session: %s\n", sess.ID)
	_, _ = fmt.Fprintf(os.Stdout, "Engine: %s\n", sess.Engine)
	_, _ = fmt.Fprintf(os.Stdout, "Profile: %s\n", sess.ProfileDir)
	return nil
}

func runSessionList(cmd *cobra.Command, args []string) error {
	sessionsDir := getSessionsDir()

	mgr, err := session.NewManager(sessionsDir)
	if err != nil {
		return fmt.Errorf("creating session manager: %w", err)
	}

	sessions := mgr.List()
	if len(sessions) == 0 {
		_, _ = fmt.Fprintln(os.Stdout, "No sessions found")
		return nil
	}

	_, _ = fmt.Fprintf(os.Stdout, "%-36s %-20s %-12s %-20s\n", "ID", "Name", "Engine", "Created")
	for _, s := range sessions {
		name := s.Name
		if name == "" {
			name = "(unnamed)"
		}
		_, _ = fmt.Fprintf(os.Stdout, "%-36s %-20s %-12s %-20s\n", s.ID, name, s.Engine, s.CreatedAt.Format("2006-01-02 15:04"))
	}
	return nil
}

func runSessionDelete(cmd *cobra.Command, args []string) error {
	sessionsDir := getSessionsDir()
	mgr, err := session.NewManager(sessionsDir)
	if err != nil {
		return fmt.Errorf("creating session manager: %w", err)
	}

	if err := mgr.Delete(args[0]); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(os.Stdout, "Session deleted")
	return nil
}

func runSessionExportCookies(cmd *cobra.Command, args []string) error {
	sessionsDir := getSessionsDir()
	mgr, err := session.NewManager(sessionsDir)
	if err != nil {
		return fmt.Errorf("creating session manager: %w", err)
	}

	sess, err := mgr.Get(args[0])
	if err != nil {
		return err
	}

	if err := sess.ExportCookies(args[1]); err != nil {
		return fmt.Errorf("exporting cookies: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "Cookies exported to %s\n", args[1])
	return nil
}

func runSessionImportCookies(cmd *cobra.Command, args []string) error {
	sessionsDir := getSessionsDir()
	mgr, err := session.NewManager(sessionsDir)
	if err != nil {
		return fmt.Errorf("creating session manager: %w", err)
	}

	sess, err := mgr.Get(args[0])
	if err != nil {
		return err
	}

	if err := sess.ImportCookies(args[1]); err != nil {
		return fmt.Errorf("importing cookies: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "Cookies imported from %s\n", args[1])
	return nil
}

func fingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Capture and display your network fingerprint",
		RunE:  runFingerprint,
	}
}

func runFingerprint(cmd *cobra.Command, args []string) error {
	labServerURL := labURL
	if labServerURL == "" {
		// Use public lab or start local
		return fmt.Errorf("--lab URL required (set to your labd instance)")
	}

	// Create engine
	eng, err := engine.New(engineName, engine.Options{
		Proxy:   proxy,
		Timeout: timeout,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}
	_ = eng.Close()

	// Request fingerprint from lab
	fpURL := labServerURL + "/fp/json"
	req := &engine.Request{
		Method:  "GET",
		URL:     fpURL,
		Timeout: timeout,
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("requesting fingerprint: %w", err)
	}

	// Parse and display
	var report lab.CompleteFingerprint
	if err := json.Unmarshal(resp.Body, &report); err != nil {
		return fmt.Errorf("parsing fingerprint: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "Engine: %s\n", engineName)
	_, _ = fmt.Fprintf(os.Stdout, "Timestamp: %s\n", report.Timestamp.Format(time.RFC3339))
	_, _ = fmt.Fprintf(os.Stdout, "Fingerprint ID: %s\n", report.ID)
	_, _ = fmt.Fprintln(os.Stdout)

	if report.TLS != nil {
		_, _ = fmt.Fprintln(os.Stdout, "TLS Fingerprint:")
		_, _ = fmt.Fprintf(os.Stdout, "  Version: %s\n", report.TLS.VersionName)
		_, _ = fmt.Fprintf(os.Stdout, "  JA3 Hash: %s\n", report.TLS.JA3Hash)
		_, _ = fmt.Fprintf(os.Stdout, "  JA4: %s\n", report.TLS.JA4)
		_, _ = fmt.Fprintln(os.Stdout)
	}

	if report.HTTP2 != nil {
		_, _ = fmt.Fprintln(os.Stdout, "HTTP/2 Fingerprint:")

		_, _ = fmt.Fprintf(os.Stdout, "  Settings:\n")
		for _, s := range report.HTTP2.Settings {
			_, _ = fmt.Fprintf(os.Stdout, "    %s=%d\n", s.Name, s.Value)
		}
		_, _ = fmt.Fprintf(os.Stdout, "  Pseudo-Headers: %v\n", report.HTTP2.PseudoHeaders)
		_, _ = fmt.Fprintln(os.Stdout)
	}

	if report.HTTP != nil {
		_, _ = fmt.Fprintln(os.Stdout, "HTTP Headers:")
		for _, h := range report.HTTP.Headers {
			_, _ = fmt.Fprintf(os.Stdout, "  %s: %s\n", h.Name, h.Value)
		}
	}

	return nil
}

func diffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare fingerprints between engines",
		RunE:  runDiff,
	}

	cmd.Flags().StringArrayVar(&diffEngines, "engine", []string{"native", "chromium"}, "Engines to compare (use multiple times)")
	cmd.Flags().StringVar(&labURL, "lab", "", "Lab server URL")

	return cmd
}

func runDiff(cmd *cobra.Command, args []string) error {
	if labURL == "" {
		return fmt.Errorf("--lab URL required")
	}

	engines := diffEngines
	if len(engines) == 0 {
		engines = []string{"native", "chromium"}
	}

	reports := make(map[string]*lab.CompleteFingerprint)
	fpURL := labURL + "/capture/json"

	for _, engName := range engines {
		eng, err := engine.New(engName, engine.Options{
			Timeout: timeout,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create %s engine: %v\n", engName, err)
			continue
		}

		req := &engine.Request{
			Method:  "GET",
			URL:     fpURL,
			Timeout: timeout,
		}

		ctx := context.Background()
		resp, err := eng.Do(ctx, req)
		_ = eng.Close()

		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s fetch failed: %v\n", engName, err)
			continue
		}

		var report lab.CompleteFingerprint
		if err := json.Unmarshal(resp.Body, &report); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse %s response: %v\n", engName, err)
			continue
		}

		reports[engName] = &report
	}

	// Display comparison
	_, _ = fmt.Fprintln(os.Stdout, "Fingerprint Comparison")
	_, _ = fmt.Fprintln(os.Stdout, "=====================")
	_, _ = fmt.Fprintln(os.Stdout)

	for name, report := range reports {
		_, _ = fmt.Fprintf(os.Stdout, "Engine: %s\n", name)
		if report.TLS != nil {
			_, _ = fmt.Fprintf(os.Stdout, "  JA3: %s\n", report.TLS.JA3Hash)
		}
		if report.HTTP2 != nil {
			_, _ = fmt.Fprintf(os.Stdout, "  HTTP/2 Settings:\n")
			for _, s := range report.HTTP2.Settings {
				_, _ = fmt.Fprintf(os.Stdout, "    %s=%d\n", s.Name, s.Value)
			}
		}
		_, _ = fmt.Fprintln(os.Stdout)
	}

	// TODO: Show detailed diffs
	return nil
}

func traceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trace <url>",
		Short: "Trace a request and output HAR-like data",
		Args:  cobra.ExactArgs(1),
		RunE:  runTrace,
	}
}

func runTrace(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	urlStr := args[0]

	eng, err := engine.New(engineName, engine.Options{
		Proxy:   proxy,
		Timeout: timeout,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}
	_ = eng.Close()

	req := &engine.Request{
		Method:  "GET",
		URL:     urlStr,
		Timeout: timeout,
	}

	resp, err := eng.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("fetching: %w", err)
	}

	// Output full trace
	output := struct {
		URL      string            `json:"url"`
		Status   int               `json:"status"`
		Protocol string            `json:"protocol"`
		Timing   engine.TimingInfo `json:"timing"`
		Trace    engine.Trace      `json:"trace"`
	}{
		URL:      urlStr,
		Status:   resp.Status,
		Protocol: resp.Protocol,
		Timing:   resp.Timing,
		Trace:    resp.Trace,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func listEnginesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "engines",
		Short: "List available engines",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintln(os.Stdout, "Available engines:")
			for _, name := range engine.Available() {
				_, _ = fmt.Fprintf(os.Stdout, "  - %s\n", name)
			}
		},
	}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage fingerprint configurations",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available fingerprint presets",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintln(os.Stdout, "Available fingerprint presets:")
			for _, name := range config.ListPresets() {
				_, _ = fmt.Fprintf(os.Stdout, "  - %s\n", name)
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show <preset>",
		Short: "Show fingerprint configuration details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.GetPreset(args[0])
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(os.Stdout, "Configuration: %s\n", cfg.Name)
			_, _ = fmt.Fprintf(os.Stdout, "Description: %s\n", cfg.Description)
			_, _ = fmt.Fprintf(os.Stdout, "Browser: %s %s\n", cfg.Browser.Name, cfg.Browser.Version)
			_, _ = fmt.Fprintf(os.Stdout, "OS: %s\n", cfg.OS.Name)
			_, _ = fmt.Fprintln(os.Stdout)

			if cfg.TLS != nil {
				_, _ = fmt.Fprintln(os.Stdout, "TLS Configuration:")
				_, _ = fmt.Fprintf(os.Stdout, "  Version: %d - %d\n", cfg.TLS.Version.Min, cfg.TLS.Version.Max)
				_, _ = fmt.Fprintf(os.Stdout, "  Cipher Suites: %d\n", len(cfg.TLS.CipherSuites))
				_, _ = fmt.Fprintf(os.Stdout, "  Extensions: %d\n", len(cfg.TLS.Extensions))
				_, _ = fmt.Fprintf(os.Stdout, "  ALPN: %v\n", cfg.TLS.ALPN)
				if cfg.TLS.ALPS != "" {
					_, _ = fmt.Fprintf(os.Stdout, "  ALPS: %s\n", cfg.TLS.ALPS)
				}
				_, _ = fmt.Fprintln(os.Stdout)
			}

			if cfg.HTTP2 != nil {
				_, _ = fmt.Fprintln(os.Stdout, "HTTP/2 Configuration:")
				_, _ = fmt.Fprintf(os.Stdout, "  Header Table Size: %d\n", cfg.HTTP2.Settings.HeaderTableSize)
				_, _ = fmt.Fprintf(os.Stdout, "  Initial Window Size: %d\n", cfg.HTTP2.Settings.InitialWindowSize)
				_, _ = fmt.Fprintf(os.Stdout, "  Pseudo-Headers: %v\n", cfg.HTTP2.PseudoHeaderOrder)
				_, _ = fmt.Fprintln(os.Stdout)
			}

			if cfg.HTTP != nil {
				_, _ = fmt.Fprintln(os.Stdout, "HTTP Configuration:")
				_, _ = fmt.Fprintf(os.Stdout, "  Version: %s\n", cfg.HTTP.Version)
				_, _ = fmt.Fprintf(os.Stdout, "  User-Agent: %s\n", cfg.HTTP.UserAgent)
			}

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "export <preset>",
		Short: "Export fingerprint configuration to JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.GetPreset(args[0])
			if err != nil {
				return err
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		},
	})

	return cmd
}

func getSessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return home + "/.brwslab/sessions"
}
func replCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repl",
		Short: "Start an interactive REPL session",
		Long:  "Start an interactive browser session with command history and auto-complete",
		RunE:  runRepl,
	}

	cmd.Flags().StringVar(&sessionName, "session", "", "Session name to use")
	cmd.Flags().BoolVarP(&useStealth, "stealth", "s", true, "Use stealth mode")
	return cmd
}

var useStealth bool

func runRepl(cmd *cobra.Command, args []string) error {
	_, _ = fmt.Fprintln(os.Stdout, "Browser REPL - Type 'help' for commands")
	_, _ = fmt.Fprintln(os.Stdout, "----------------------------------------")

	engineName := "chromium-stealth"
	if !useStealth {
		engineName = "chromium"
	}

	eng, err := engine.New(engineName, engine.Options{
		Timeout:    timeout,
		ProfileDir: profileDir,
		Headless:   false,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}
	_ = eng.Close()

	rl := NewReadline()
	_ = rl.Close()

	currentURL := ""
	ctx := context.Background()

	for {
		prompt := "> "
		if currentURL != "" {
			prompt = fmt.Sprintf("[%s]> ", truncateURL(currentURL))
		}

		line, err := rl.Readline(prompt)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			_, _ = fmt.Fprintf(os.Stdout, "Error: %v\n", err)

			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "help", "?":
			printReplHelp()
		case "get", "goto":
			if len(parts) < 2 {
				_, _ = fmt.Fprintln(os.Stdout, "Usage: get <url>")
				continue
			}
			url := parts[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}
			currentURL = url
			resp, err := eng.Do(ctx, &engine.Request{URL: url, Timeout: timeout})
			if err != nil {
				_, _ = fmt.Fprintf(os.Stdout, "Error: %v\n", err)
				continue
			}
			_, _ = fmt.Fprintf(os.Stdout, "Status: %d, Size: %d bytes\n", resp.Status, len(resp.Body))
			if outputFormat == "json" {
				_ = outputJSON(resp)
			}
		case "post":
			if len(parts) < 3 {
				_, _ = fmt.Fprintln(os.Stdout, "Usage: post <url> <body>")
				continue
			}
			url := parts[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}
			currentURL = url
			resp, err := eng.Do(ctx, &engine.Request{
				Method:  "POST",
				URL:     url,
				Body:    []byte(strings.Join(parts[2:], " ")),
				Timeout: timeout,
			})
			if err != nil {
				_, _ = fmt.Fprintf(os.Stdout, "Error: %v\n", err)
				continue
			}
			_, _ = fmt.Fprintf(os.Stdout, "Status: %d, Size: %d bytes\n", resp.Status, len(resp.Body))
		case "back":
			_, _ = fmt.Fprintln(os.Stdout, "Not implemented - browser doesn't support back in fetch mode")
		case "source", "html":
			if currentURL == "" {
				_, _ = fmt.Fprintln(os.Stdout, "No page loaded")
				continue
			}
			resp, err := eng.Do(ctx, &engine.Request{URL: currentURL, Timeout: timeout})
			if err != nil {
				_, _ = fmt.Fprintf(os.Stdout, "Error: %v\n", err)
				continue
			}
			_, _ = fmt.Fprintln(os.Stdout, string(resp.Body))
		case "quit", "exit", "q":
			_, _ = fmt.Fprintln(os.Stdout, "Goodbye!")
			return nil
		case "cookies":
			_, _ = fmt.Fprintln(os.Stdout, "Session cookies - use session export-cookies command")
		default:
			_, _ = fmt.Fprintf(os.Stdout, "Unknown command: %s\nType 'help' for available commands\n", parts[0])
		}
	}

	return nil
}

func printReplHelp() {
	_, _ = fmt.Fprintln(os.Stdout, "Available commands:")
	_, _ = fmt.Fprintln(os.Stdout, "  get <url>     - Navigate to URL")
	_, _ = fmt.Fprintln(os.Stdout, "  post <url> <body> - POST request")
	_, _ = fmt.Fprintln(os.Stdout, "  source        - Show page source")
	_, _ = fmt.Fprintln(os.Stdout, "  html          - Show page source (alias)")
	_, _ = fmt.Fprintln(os.Stdout, "  back          - Go back (not implemented)")
	_, _ = fmt.Fprintln(os.Stdout, "  cookies       - Show cookies")
	_, _ = fmt.Fprintln(os.Stdout, "  quit/exit/q   - Exit REPL")
	_, _ = fmt.Fprintln(os.Stdout, "  help          - Show this help")
}

func truncateURL(url string) string {
	if len(url) > 40 {
		return url[:37] + "..."
	}
	return url
}

type Readline struct {
	reader  *bufio.Reader
	history []string
}

func NewReadline() *Readline {
	return &Readline{
		reader:  bufio.NewReader(os.Stdin),
		history: make([]string, 0),
	}
}

func (r *Readline) Readline(prompt string) (string, error) {
	_, _ = fmt.Fprint(os.Stdout, prompt)
	line, err := r.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line != "" {
		r.history = append(r.history, line)
	}
	return line, nil
}

func (r *Readline) Close() error {
	return nil
}
