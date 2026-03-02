# Semantic MCP Server

Model Context Protocol (MCP) server that exposes semantic web extraction capabilities to LLM clients like Claude Desktop.

## Features

### Extraction Tools
- `extract_semantic_tree` - Extract compressed semantic tree from URL/HTML
- `extract_forms` - Extract form schemas (fields, types, validation)
- `extract_actions` - Extract interactive elements (clickable, fillable)

### Crawling Tools
- `crawl_urls` - Crawl multiple URLs concurrently
- `get_crawl_status` - Check crawl job progress

### Search Tools
- `search_content` - Semantic search across crawled content
- `find_similar_pages` - Find pages similar to a URL

### Analysis Tools
- `analyze_page` - Comprehensive page analysis (tree, forms, actions, links)
- `compare_pages` - Diff two pages for changes

### Serialization Tools
- `serialize_for_llm` - Output page in [WEBFURL] format for LLM context

## Installation

```bash
go build -o semantic-server ./cmd/semantic-server
```

## Configuration

### Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "semantic": {
      "command": "/path/to/semantic-server",
      "env": {
        "OPENROUTER_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Environment Variables

- `OPENROUTER_API_KEY` - API key for LLM compression (optional, falls back to structural extraction)

## Usage Examples

### Extract Semantic Tree

```
User: Extract the semantic tree from https://example.com

Claude: [Uses extract_semantic_tree tool]

Result:
- Title: Example Domain
- Tokens: 1,234 → 45 (96% compression)
- Root nodes: 3
- LLM calls: 2
- Cache hits: 5
```

### Analyze a Page

```
User: Analyze the page https://httpbin.org/forms/post

Claude: [Uses analyze_page tool]

Result:
- 1 form with 12 fields
- 3 text inputs, 2 radio groups, 4 checkboxes
- Required fields: custname, custtel
- CSRF token: None detected
```

### Crawl Multiple Pages

```
User: Crawl https://en.wikipedia.org/wiki/Go_programming_language 
      and https://en.wikipedia.org/wiki/Python_programming_language

Claude: [Uses crawl_urls tool, returns job_id]

User: What's the status?

Claude: [Uses get_crawl_status tool]

Job completed:
- 2 pages processed
- 115,458 → 189 tokens (611x reduction)
- Cache hit rate: 99.8%
```

### Find Similar Content

```
User: Find pages similar to the Go programming language article

Claude: [Uses find_similar_pages tool]

Similar pages:
1. Rust programming language (score: 0.89)
2. C++ programming language (score: 0.85)
3. Programming language comparison (score: 0.82)
```

### Compare Page Changes

```
User: What changed between these two versions of the page?

Claude: [Uses compare_pages tool]

Differences:
- Added: 3 new sections
- Removed: 1 deprecated section
- Modified: 5 sections with content updates
- Change percentage: 12%
```

## Tool Reference

### extract_semantic_tree

Extract a compressed semantic tree from a URL.

**Parameters:**
- `url` (required): URL to extract from
- `html` (optional): Direct HTML content
- `include_forms` (optional): Extract form schemas
- `include_actions` (optional): Extract interactive elements

**Returns:**
- Compressed token count
- Original token count
- Compression ratio
- Number of root nodes
- LLM calls and cache hits

### crawl_urls

Crawl multiple URLs concurrently.

**Parameters:**
- `urls` (required): Comma-separated URLs
- `concurrency` (optional): Number of workers (default: 4)

**Returns:**
- Job ID for status tracking

### search_content

Search crawled content semantically.

**Parameters:**
- `query` (required): Description to search for
- `limit` (optional): Maximum results (default: 10)

**Returns:**
- Matching URLs with scores
- Token counts for each result

### analyze_page

Comprehensive page analysis.

**Parameters:**
- `url` (required): URL to analyze

**Returns:**
- Semantic tree statistics
- Form schemas
- Interactive actions
- Navigation links

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude Desktop                           │
│                   (MCP Client)                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ MCP Protocol
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 semantic-server                            │
│                  (MCP Server)                              │
├─────────────────────────────────────────────────────────────┤
│                                                            │
│  Tools:                                                    │
│  ├─ extract_semantic_tree  ──┐                           │
│  ├─ crawl_urls               │  brws/pipeline            │
│  ├─ search_content          ├──►  ├─ fetch               │
│  ├─ analyze_page            │   ├─ extract              │
│  └─ compare_pages          ──┘   └─ embed               │
│                                                            │
│  Storage:                                                  │
│  ├─ trees map[string]*SemanticTree                       │
│  ├─ index *HNSWIndex (vector search)                      │
│  └─ cache *CacheStore (SQLite)                           │
│                                                            │
└─────────────────────────────────────────────────────────────┘
```

## Performance

Typical results on production sites:

| Site | HTML Size | Duration | Compression |
|------|-----------|----------|-------------|
| Wikipedia (Go) | 438KB | 0.9s | 582x |
| Wikipedia (Python) | 614KB | 50s | 560x |
| GitHub | 561KB | 40s | 270x |
| Hacker News | 34KB | 59s | 679x |

## Benefits for LLM Context

1. **Token Reduction**: ~99% reduction means more pages fit in context
2. **Cross-Page Caching**: Similar chunks shared across pages
3. **Structured Output**: Easy for LLM to understand and navigate
4. **Actionable Intelligence**: Interactive elements identified
5. **Change Detection**: Track page modifications

## Development

```bash
# Build
go build ./cmd/semantic-server

# Test
go test ./brws/semantic/... ./brws/pipeline/...

# Run manually
export OPENROUTER_API_KEY="your-key"
./semantic-server
```

## License

Part of the stealth/brwslab project.
