package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
)

var (
	url         = flag.String("url", "", "URL to extract from (required)")
	cssSelector = flag.String("css", "", "CSS selector to extract")
	xpath       = flag.String("xpath", "", "XPath selector to extract")
	extract     = flag.String("extract", "", "Comma-separated extractions (e.g., title,h1,links)")
	engineName  = flag.String("engine", "native", "Engine to use")
	output      = flag.String("output", "", "Output file")
	jsonOutput  = flag.Bool("json", false, "Output as JSON")
	markdown    = flag.Bool("markdown", false, "Output as markdown")
	textOnly    = flag.Bool("text", false, "Output only text content")
	attribute   = flag.String("attr", "", "Extract specific attribute (e.g., href, src)")
	timeout     = flag.Duration("t", 30*time.Second, "Request timeout")
	stealth     = flag.Bool("stealth", true, "Enable stealth mode")
)

func main() {
	flag.Parse()

	if *url == "" {
		fmt.Fprintf(os.Stderr, "Error: --url is required\n")
		os.Exit(1)
	}

	if *cssSelector == "" && *xpath == "" && *extract == "" {
		fmt.Fprintf(os.Stderr, "Error: specify --css, --xpath, or --extract\n")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	eng, err := engine.New(*engineName, engine.Options{
		Stealth: *stealth,
		Timeout: *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	resp, err := eng.Do(ctx, &engine.Request{
		Method:  "GET",
		URL:     *url,
		Timeout: *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching URL: %v\n", err)
		os.Exit(1)
	}

	htmlResp := engine.NewHtmlResponse(resp)

	var results interface{}

	if *extract != "" {
		results = extractMultiple(htmlResp, *extract)
	} else if *cssSelector != "" {
		results = extractCSS(htmlResp, *cssSelector)
	} else if *xpath != "" {
		results = extractXPath(htmlResp, *xpath)
	}

	writeOutput(results)
}

func extractMultiple(resp *engine.HtmlResponse, extractions string) map[string]interface{} {
	result := make(map[string]interface{})
	parts := strings.Split(extractions, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "title":
			result["title"] = resp.GetTitle()
		case "links":
			result["links"] = resp.GetLinks()
		case "images":
			result["images"] = resp.GetImages()
		case "meta":
			result["meta"] = resp.GetMeta()
		case "forms":
			result["forms"] = resp.GetForms()
		default:
			els := resp.CSS(part)
			if len(els) > 1 {
				var texts []string
				for _, el := range els {
					texts = append(texts, el.Text())
				}
				result[part] = texts
			} else if len(els) == 1 {
				if *attribute != "" {
					result[part] = els[0].Attr(*attribute)
				} else {
					result[part] = els[0].Text()
				}
			}
		}
	}

	return result
}

func extractCSS(resp *engine.HtmlResponse, selector string) interface{} {
	els := resp.CSS(selector)

	if len(els) == 0 {
		return nil
	}

	if *textOnly {
		if len(els) == 1 {
			return els[0].Text()
		}
		var texts []string
		for _, el := range els {
			texts = append(texts, el.Text())
		}
		return texts
	}

	if *attribute != "" {
		if len(els) == 1 {
			return els[0].Attr(*attribute)
		}
		var attrs []string
		for _, el := range els {
			attrs = append(attrs, el.Attr(*attribute))
		}
		return attrs
	}

	if len(els) == 1 {
		return map[string]string{
			"text":  els[0].Text(),
			"attrs": els[0].AllAttr()[""],
		}
	}

	var items []map[string]interface{}
	for _, el := range els {
		items = append(items, map[string]interface{}{
			"text":  el.Text(),
			"attrs": el.AllAttr(),
		})
	}
	return items
}

func extractXPath(resp *engine.HtmlResponse, xpath string) interface{} {
	els := resp.XPath(xpath)

	if len(els) == 0 {
		return nil
	}

	if *textOnly {
		if len(els) == 1 {
			return els[0].Text()
		}
		var texts []string
		for _, el := range els {
			texts = append(texts, el.Text())
		}
		return texts
	}

	if *attribute != "" {
		if len(els) == 1 {
			return els[0].Attr(*attribute)
		}
		var attrs []string
		for _, el := range els {
			attrs = append(attrs, el.Attr(*attribute))
		}
		return attrs
	}

	if len(els) == 1 {
		return els[0].Text()
	}

	var texts []string
	for _, el := range els {
		texts = append(texts, el.Text())
	}
	return texts
}

func writeOutput(data interface{}) {
	var out *os.File
	if *output != "" {
		var err error
		out, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(data)
	} else if *markdown {
		writeMarkdown(out, data)
	} else {
		writeText(out, data)
	}
}

func writeText(w *os.File, data interface{}) {
	switch v := data.(type) {
	case string:
		fmt.Fprintln(w, v)
	case []string:
		for _, s := range v {
			fmt.Fprintln(w, s)
		}
	case map[string]interface{}:
		for k, v := range v {
			fmt.Fprintf(w, "%s: %v\n", k, v)
		}
	case []map[string]interface{}:
		for _, item := range v {
			for k, v := range item {
				fmt.Fprintf(w, "%s: %v\n", k, v)
			}
			fmt.Fprintln(w)
		}
	default:
		fmt.Fprintln(w, data)
	}
}

func writeMarkdown(w *os.File, data interface{}) {
	switch v := data.(type) {
	case string:
		fmt.Fprintln(w, v)
	case []string:
		for i, s := range v {
			fmt.Fprintf(w, "## Item %d\n\n%s\n\n", i+1, s)
		}
	case map[string]interface{}:
		for k, v := range v {
			fmt.Fprintf(w, "## %s\n\n%v\n\n", k, v)
		}
	default:
		fmt.Fprintln(w, data)
	}
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: extract [options]

No-code extraction tool for fetching URLs and extracting data using CSS selectors.

Examples:
  # Extract page title
  extract --url https://example.com --css title

  # Extract all links
  extract --url https://example.com --css a --attr href --json

  # Extract multiple elements at once
  extract --url https://example.com --extract "title,links,images"

  # Use XPath
  extract --url https://example.com --xpath "//h1"

Options:
`)
		flag.PrintDefaults()
	}
}
