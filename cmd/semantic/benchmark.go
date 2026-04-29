package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skunkworq/stealth/brws/content/semantic"
	"github.com/skunkworq/stealth/brws/content/semantic/bench"
)

func runBenchmark(urls []string, outputFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	config, err := semantic.NewConfigFromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	cache, err := semantic.NewCacheStore(ctx, "")
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	defer func() { _ = cache.Close() }()

	suite := bench.NewSuite(config, cache)

	fmt.Printf("Running benchmark on %d URLs...\n", len(urls))
	start := time.Now()

	results := suite.RunBatch(ctx, urls)

	summary := suite.Summary(results)
	fmt.Printf("\n%s\n", summary)
	fmt.Printf("Total time: %v\n", time.Since(start).Round(time.Millisecond))

	if outputFile != "" {
		if err := bench.WriteReport(results, outputFile); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		fmt.Printf("Results written to: %s\n", outputFile)
	}

	return nil
}

func printDetailedResult(result *bench.Result) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
}
