package main

import (
	"fmt"
	"os"

	"github.com/stealth/brwslab/brws/engine"
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
  version       Show version info

Run 'stealth <command> --help' for more information on a command.

Available engines: %s
`, version, engine.Available())
}

func printVersion() {
	fmt.Printf("Stealth Spider Framework v%s (revision: %s, %s)\n", version, revision, goVersion)
}
