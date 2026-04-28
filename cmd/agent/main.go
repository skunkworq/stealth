// agent — CLI bridge for the brws/agent browser automation package.
//
// Provides subprocess-friendly commands so Python (and other languages) can
// drive the agent loop without writing Go code.
//
// Usage:
//
//	agent observe --session-dir /tmp/sess --url https://example.com --format json
//	agent execute --session-dir /tmp/sess --action '{"type":"click","id":"E1_click"}'
//	agent step --session-dir /tmp/sess --url https://example.com --decision click_E1
//	agent session-stop --session-dir /tmp/sess
package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	version   = "0.1.0"
	revision  = "dev"
	goVersion = "go"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "observe":
		if err := runObserve(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "execute":
		if err := runExecute(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "step":
		if err := runStep(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "session-stop":
		if err := runSessionStop(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("agent %s (%s %s)\n", version, revision, goVersion)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `agent %s — Browser automation agent CLI

Usage:
  agent <command> [flags]

Commands:
  observe        Capture page state + action space (JSON output)
  execute        Run a single action in the session
  step           Observe + optionally execute a decision
  session-stop   Kill the Chrome process and clean up
  version        Print version
  help           Print this help

Global flags (per command):
  --session-dir <path>   Session directory for persistent browser state
  --chrome-path <path>   Path to Chrome/Chromium executable (auto-detected if omitted)

Examples:
  agent observe --session-dir /tmp/sess --url https://example.com --format compact
  agent execute --session-dir /tmp/sess --action '{"type":"click","id":"E1_click"}'
  agent step --session-dir /tmp/sess --url https://example.com --decision scroll_down
  agent session-stop --session-dir /tmp/sess
`, version)
}

// commonFlags parses flags shared across most commands.
type commonFlags struct {
	SessionDir string
	ChromePath string
}

func parseCommonFlags(fs *flag.FlagSet, args []string) (*commonFlags, error) {
	cf := &commonFlags{}
	fs.StringVar(&cf.SessionDir, "session-dir", "", "Session directory for persistent browser state (required)")
	fs.StringVar(&cf.ChromePath, "chrome-path", "", "Path to Chrome executable (auto-detected if omitted)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if cf.SessionDir == "" {
		return nil, fmt.Errorf("--session-dir is required")
	}
	return cf, nil
}
