package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/stealth/brwslab/brws/engine"
	_ "github.com/stealth/brwslab/brws/engine/native"
	"github.com/stealth/brwslab/brws/spider"
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
