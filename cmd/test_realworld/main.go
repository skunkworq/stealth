//go:build ignore
// +build ignore

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/stealth/brwslab/brws/semantic"
)

func main() {
	urls := []string{
		"https://httpbin.org/html",
		"https://httpbin.org/links/10",
		"https://en.wikipedia.org/wiki/Go_(programming_language)",
		"https://example.com",
	}

	results := make(chan *Result, len(urls))

	for _, url := range urls {
		go func(u string) {
			r := testURL(u)
			results <- r
		}(url)
	}

	var allResults []*Result
	for i := 0; i < len(urls); i++ {
		allResults = append(allResults, <-results)
	}
	close(results)

	fmt.Println("\n=== SUMMARY ===")
	fmt.Printf("%-40s %10s %10s %10s %10s\n", "URL", "HTML Size", "Tokens In", "Tokens Out", "Ratio")
	fmt.Println(strings.Repeat("-", 85))

	var totalHTML, totalIn, totalOut int
	for _, r := range allResults {
		if r.Err != nil {
			fmt.Printf("%-40s ERROR: %v\n", r.URL, r.Err)
			continue
		}
		fmt.Printf("%-40s %10d %10d %10d %9.1f%%\n",
			truncateURL(r.URL),
			r.HTMLSize,
			r.TokensIn,
			r.TokensOut,
			r.Ratio*100)
		totalHTML += r.HTMLSize
		totalIn += r.TokensIn
		totalOut += r.TokensOut
	}

	if totalIn > 0 {
		fmt.Println(strings.Repeat("-", 85))
		fmt.Printf("%-40s %10d %10d %10d %9.1f%%\n",
			"TOTAL",
			totalHTML,
			totalIn,
			totalOut,
			float64(totalOut)/float64(totalIn)*100)
	}
}

type Result struct {
	URL       string
	HTMLSize  int
	TokensIn  int
	TokensOut int
	Ratio     float64
	Err       error
}

func testURL(url string) *Result {
	r := &Result{URL: url}

	start := time.Now()
	log.Printf("Testing: %s", url)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		r.Err = err
		return r
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		r.Err = err
		return r
	}
	defer resp.Body.Close()

	htmlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		r.Err = err
		return r
	}

	r.HTMLSize = len(htmlBytes)
	log.Printf("  Fetched %d bytes in %v", r.HTMLSize, time.Since(start))

	pipelineStart := time.Now()

	config := &semantic.PipelineConfig{
		MaxChunks:        50,
		MaxConcurrentLLM: 0, // No LLM for pure compression test
	}

	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, string(htmlBytes), url, config)
	if err != nil {
		r.Err = err
		log.Printf("  ERROR: %v", err)
		return r
	}

	r.TokensIn = int(stats.FullTreeTokens)
	r.TokensOut = int(stats.CompressedTokens)
	if r.TokensIn > 0 {
		r.Ratio = float64(r.TokensOut) / float64(r.TokensIn)
	}

	log.Printf("  Semantic: %d -> %d tokens (%.1f%%) in %v",
		r.TokensIn, r.TokensOut, r.Ratio*100, time.Since(pipelineStart))

	if tree != nil {
		log.Printf("  Title: %s", tree.Title)
		log.Printf("  Root nodes: %d", len(tree.RootNodes))
		allNodes := tree.AllNodes()
		log.Printf("  Total nodes: %d", len(allNodes))

		var actionCount int
		for _, n := range allNodes {
			actionCount += len(n.Actions)
		}
		log.Printf("  Actions: %d", actionCount)
	}

	return r
}

func truncateURL(url string) string {
	if len(url) > 40 {
		return url[:37] + "..."
	}
	return url
}
