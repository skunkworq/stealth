//go:build ignore
// +build ignore

package main

import (
	"context"
	"encoding/json"
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
		// example.com requires Chrome - uncomment when Chrome is installed
		// "https://example.com",
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

	// Use plain HTTP for all URLs
	// Note: For Cloudflare-protected sites (example.com), use stealth browser with Chrome installed
	htmlBytes, err := fetchWithHTTP(url)

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

	tree, stats, err := semantic.HTMLToSemanticTreeCached(context.Background(), string(htmlBytes), url, config)
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

		// === TRAVERSAL TEST ===
		log.Printf("\n  === TREE TRAVERSAL TEST ===")

		// Test 1: Find specific nodes
		log.Printf("  Finding nodes with 'Go' in summary...")
		found := 0
		for _, n := range allNodes {
			if strings.Contains(n.Summary, "Go") || strings.Contains(n.Summary, "programming") {
				found++
				if found <= 3 {
					log.Printf("    Node[%d]: %s", n.ID, truncate(n.Summary, 60))
				}
			}
		}
		log.Printf("  Found %d nodes with 'Go' or 'programming'", found)

		// Test 2: Find by selector
		log.Printf("  Finding nodes by selector patterns...")
		selectorCounts := make(map[string]int)
		for _, n := range allNodes {
			if n.DOMSelector != "" {
				tag := "unknown"
				if idx := strings.Index(n.DOMSelector, ">"); idx > 0 {
					tag = n.DOMSelector[strings.LastIndex(n.DOMSelector, "<")+1 : idx]
					tag = strings.Trim(tag, " ")
				}
				selectorCounts[tag]++
			}
		}
		log.Printf("  Selector tag distribution: %v", selectorCounts)

		// Test 3: Traverse tree hierarchy
		log.Printf("  Tree hierarchy traversal:")
		for i, root := range tree.RootNodes {
			if i >= 2 {
				log.Printf("    ... and %d more root nodes", len(tree.RootNodes)-i)
				break
			}
			log.Printf("    Root[%d]: %s (children: %d)", root.ID, truncate(root.Summary, 40), len(root.Children))
			for j, child := range root.Children {
				if j >= 3 {
					log.Printf("      ... and %d more children", len(root.Children)-j)
					break
				}
				log.Printf("        Child[%d]: %s", child.ID, truncate(child.Summary, 40))
			}
		}

		// Test 4: Extract actions
		log.Printf("  Action extraction:")
		actionTypes := make(map[semantic.ActionType]int)
		for _, n := range allNodes {
			for _, a := range n.Actions {
				actionTypes[a.Type]++
			}
		}
		log.Printf("    Action types: %v", actionTypes)

		// Show some click actions
		clickCount := 0
		for _, n := range allNodes {
			for _, a := range n.Actions {
				if a.Type == semantic.ActionClick && clickCount < 3 {
					log.Printf("    Click action: %s -> %s", a.Selector, truncate(a.Description, 40))
					clickCount++
				}
			}
		}

		// Test 5: JSON serialization
		log.Printf("  JSON serialization test...")
		jsonBytes, err := json.Marshal(tree)
		if err != nil {
			log.Printf("    ERROR: %v", err)
		} else {
			log.Printf("    Serialized to %d bytes", len(jsonBytes))
		}

		// Test 6: Find node by ID
		log.Printf("  FindNode by ID test...")
		if len(allNodes) > 5 {
			targetID := allNodes[5].ID
			foundNode := tree.FindNode(targetID)
			if foundNode != nil {
				log.Printf("    Found node %s: %s", targetID, truncate(foundNode.Summary, 40))
			} else {
				log.Printf("    ERROR: Could not find node %s", targetID)
			}
		}

		log.Printf("  === TRAVERSAL COMPLETE ===\n")
	}

	return r
}

func fetchWithHTTP(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func truncateURL(url string) string {
	if len(url) > 40 {
		return url[:37] + "..."
	}
	return url
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
