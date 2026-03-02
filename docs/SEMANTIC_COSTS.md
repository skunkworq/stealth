# Semantic Extraction Architecture

## Token Cost Analysis (GitHub.com example)

### Input
- HTML: 561KB (~140,335 raw tokens)

### LLM Path
| Component | Tokens | Notes |
|-----------|--------|-------|
| LLM Compression | ~10,500 | 6 calls × ~1,750 tokens each |
| Embeddings | ~900 | 18 summaries × 50 tokens |
| **Total spent** | **~11,400** | One-time cost |

### Output
- Compressed tree: **18 tokens** (99.99% reduction)
- Break-even: After **0.1 queries** to an LLM using this context

### Cost Comparison

| Scenario | Tokens Used |
|----------|-------------|
| Feed raw HTML to Claude | 140,335 |
| Feed compressed tree to Claude | 18 |
| **Savings per query** | **140,317 tokens** |

**Break-even analysis:**
- Spent: 11,400 tokens compressing
- Save: 140,317 tokens per query
- Payback: After 0.1 queries (immediate)

## When to Use LLM vs No-LLM

### No-LLM Mode (`pipeline_nollm.go`)
```
HTML → DOM chunking → Raw text extraction → Tree structure
```
- **Cost:** $0
- **Output:** Structural tree with raw text snippets
- **Use case:** 
  - One-time extraction (no repeated queries)
  - Simple pages where structure is enough
  - Budget-constrained scenarios

### LLM Mode
```
HTML → DOM chunking → LLM summarization → Semantic tree → Embeddings
```
- **Cost:** ~$0.10-0.20 per page (OpenRouter rates)
- **Output:** Semantic tree with actionable summaries
- **Use case:**
  - Repeated queries against same page
  - Multi-page crawling and search
  - Complex pages with dynamic content

## Vector DB Role

**NOT used in compression**, used AFTER for retrieval:

```
┌─────────────────────────────────────────────────────┐
│  Crawling Phase                                     │
│                                                     │
│  Page 1 → Semantic Tree → Embeddings → HNSW Index  │
│  Page 2 → Semantic Tree → Embeddings → HNSW Index  │
│  Page N → Semantic Tree → Embeddings → HNSW Index  │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  Query Phase                                        │
│                                                     │
│  Query → Embedding → HNSW Search → Top-K Pages    │
│                      ↓                              │
│              Load compressed trees                  │
│                      ↓                              │
│              Feed 18 tokens each to LLM            │
└─────────────────────────────────────────────────────┘
```

### When Vector DB Helps
1. **Multi-page crawling:** Search across 1000s of pages
2. **Semantic search:** "Find pages with login forms"
3. **Unfolding:** Expand relevant nodes based on query similarity
4. **MCP server:** `find_similar_nodes` tool

### Without Vector DB
- You'd need to scan all pages linearly
- No similarity-based retrieval
- Can't do semantic search across crawled content

## Recommendations

### Use No-LLM when:
- ✅ Extracting 1-2 pages, one-time
- ✅ Only need structure (forms, links, buttons)
- ✅ Zero budget

### Use LLM when:
- ✅ Crawling multiple pages
- ✅ Repeated queries against same content
- ✅ Need semantic understanding
- ✅ Building a knowledge base

### Use Vector DB when:
- ✅ Crawling 100+ pages
- ✅ Need semantic search
- ✅ Building RAG pipeline
- ✅ Long-term knowledge storage
