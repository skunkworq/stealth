# Battle Testing & Advanced Use Cases Roadmap

## Phase 1: Production Hardening (Week 1-2)

### 1.1 Critical Fixes
- [ ] Add context cancellation to `compressChunksParallel()` 
- [ ] Implement HNSW container/heap optimization (5-10x search speedup)
- [ ] Add LLM retry with exponential backoff
- [ ] Add circuit breaker for LLM API calls

### 1.2 Concurrency Testing
```go
// Add to cache_test.go
func TestCacheConcurrentReadWrite(t *testing.T) {
    // 100 goroutines parallel GetChunk/PutChunk
    // Verify no deadlocks, no data races
}

// Add to pipeline_test.go
func TestPipelineCancellation(t *testing.T) {
    // Cancel mid-processing, verify goroutines don't hang
}

// Add to hnsw_test.go
func TestHNSWConcurrentSearchDuringAdd(t *testing.T) {
    // Parallel Search while Adding new vectors
}
```

### 1.3 Chaos Testing
- Kill LLM API mid-request, verify clean recovery
- Simulate network partitions for cache layer
- Memory pressure testing (crawl 1000 pages, verify no OOM)
- Timeout boundary testing (LLM timeout = compression timeout)

## Phase 2: Advanced Integration Layer (Week 2-3)

### 2.1 Semantic Form Filling (P0)
Enables: login flows, checkout, signup automation

```go
type SemanticFormFiller struct {
    client   *stealth.Client
    navigator *SemanticNavigator
}

func (f *SemanticFormFiller) FillForm(ctx context.Context, 
    formSchema *FormSchema, values map[string]string) error {
    
    // 1. Find form in semantic tree
    form := f.findFormBySchema(formSchema)
    
    // 2. Group fields by type (email, password, etc)
    fieldGroups := groupFieldsByType(form.Fields)
    
    // 3. Fill with humanized delays
    for field, value := range values {
        delay := f.calculateHumanDelay(field.Type)
        f.client.ClickSelector(ctx, field.Selector)
        time.Sleep(delay)
        f.client.Type(value) // Humanized typing speed
    }
    
    // 4. Detect CAPTCHA before submit
    if f.detectCaptchaInTree() {
        return f.handleCaptcha(ctx)
    }
    
    return f.submitForm(ctx, form)
}
```

### 2.2 Smart Link Following (P0)
Reduces selector fragility by finding actions semantically

```go
func (n *SemanticNavigator) ClickSemanticAction(ctx context.Context, 
    intent string) error {
    
    // 1. Generate embedding for intent
    intentVec := n.embedIntent(intent)
    
    // 2. Search action index for best match
    candidates := n.searchActions(intentVec, topK=5)
    
    // 3. Rank by action type + semantic similarity
    best := n.rankActions(candidates, intent)
    
    // 4. Click with RL-guided decision if available
    if n.policyLoader != nil {
        action := n.selectActionWithRL(best, ctx)
    }
    
    return n.client.ClickSelector(ctx, best.Selector)
}
```

### 2.3 Session State Management (P1)
Persist auth across multi-step flows

```go
type SessionState struct {
    Cookies     []http.Cookie
    LocalStorage map[string]string
    AuthToken   string
    CSRFToken   string
}

func (n *SemanticNavigator) GetSessionState() *SessionState
func (n *SemanticNavigator) RestoreSession(state *SessionState)
func (n *SemanticNavigator) IsAuthenticated() bool
```

### 2.4 Challenge Detection in Semantic Tree
Detect CAPTCHA without relying on HTTP headers

```go
func DetectChallengeInTree(tree *SemanticTree) *ChallengeInfo {
    // Scan actions for:
    // - "recaptcha", "hcaptcha", "cloudflare"
    // - iframe with captcha domain
    // - Button text "verify", "I'm not a robot"
    
    for _, node := range tree.AllNodes() {
        for _, action := range node.Actions {
            if isCaptchaSelector(action.Selector) {
                return &ChallengeInfo{
                    Type:     detectCaptchaType(node),
                    Selector: action.Selector,
                }
            }
        }
    }
    return nil
}
```

## Phase 3: Advanced Use Cases (Week 3-4)

### 3.1 Self-Improving Crawler
Learns from failures, adapts strategies

```go
type AdaptiveCrawler struct {
    navigator *SemanticNavigator
    history   *CrawlHistory
    policy    *ml.PolicyLoader
}

func (c *AdaptiveCrawler) Crawl(ctx context.Context, url string) error {
    // 1. Check history for similar pages
    similar := c.history.FindSimilar(url)
    
    // 2. Use learned strategy if available
    if strategy := c.predictStrategy(similar); strategy != nil {
        return c.executeStrategy(ctx, url, strategy)
    }
    
    // 3. Fall back to exploration
    result := c.explore(ctx, url)
    
    // 4. Learn from outcome
    c.updatePolicy(result)
    
    return result.Error
}
```

### 3.2 Distributed Semantic Deduplication
Scale to millions of pages without re-processing

```go
type DistributedCrawlCoordinator struct {
    vectorIndex *HNSWIndex
    bloomFilter *BloomFilter  // Fast negative check
    queue      *WorkQueue
}

func (d *DistributedCrawlCoordinator) ShouldCrawl(url string, 
    structuralHash string) bool {
    
    // 1. Bloom filter (fast negative)
    if d.bloomFilter.Contains(structuralHash) {
        return false // Already processed
    }
    
    // 2. Check vector similarity (semantic dupes)
    existing := d.vectorIndex.Search(hash, k=1)
    if existing[0].Score > 0.95 {
        return false // Semantically dupe
    }
    
    // 3. Add to queue
    d.queue.Enqueue(url)
    return true
}
```

### 3.3 Real-Time Page Change Detection
Detect meaningful content changes, ignore noise

```go
type ChangeDetector struct {
    previous  map[string]*SemanticTree
    threshold float32
}

func (d *ChangeDetector) DetectChanges(url string, 
    newTree *SemanticTree) []Change {
    
    oldTree := d.previous[url]
    if oldTree == nil {
        d.previous[url] = newTree
        return nil
    }
    
    // Compare structural hashes (instant)
    if oldTree.StructuralHash == newTree.StructuralHash {
        return nil // No change
    }
    
    // Find changed nodes (semantic diff)
    changes := d.findChangedNodes(oldTree, newTree)
    
    // Filter significant changes (content > ads)
    significant := d.filterSignificant(changes)
    
    d.previous[url] = newTree
    return significant
}
```

### 3.4 Price Monitoring Agent
Semantic understanding of product pages

```go
type PriceMonitor struct {
    navigator *SemanticNavigator
    db        *PriceDB
}

func (p *PriceMonitor) MonitorProduct(url string) (*PriceInfo, error) {
    result, err := p.navigator.NavigateWithIntent(ctx, url, "price")
    if err != nil {
        return nil, err
    }
    
    // Find price in semantic tree
    priceNode := p.findPriceNode(result.SemanticTree)
    
    // Extract structured data
    info := &PriceInfo{
        Price:    p.parsePrice(priceNode.Summary),
        Currency: p.detectCurrency(priceNode),
        InStock:  p.checkAvailability(result.SemanticTree),
        Variants: p.extractVariants(result.SemanticTree),
    }
    
    // Track change
    previous := p.db.GetLatest(url)
    if previous != nil && previous.Price != info.Price {
        p.alertPriceChange(previous, info)
    }
    
    p.db.Save(url, info)
    return info, nil
}
```

### 3.5 A/B Testing Detector
Identify experimental variants on pages

```go
type ABTestDetector struct {
    cache map[string][]*SemanticTree
}

func (a *ABTestDetector) Detect(url string, 
    tree *SemanticTree) *ABTestVariant {
    
    // 1. Collect multiple samples
    samples := a.cache[url]
    if len(samples) < 10 {
        a.cache[url] = append(samples, tree)
        return nil // Need more samples
    }
    
    // 2. Cluster by structural similarity
    clusters := a.clusterSamples(samples)
    
    // 3. If >1 distinct cluster, A/B test detected
    if len(clusters) > 1 {
        return &ABTestVariant{
            Variants:   len(clusters),
            Confidence: a.calculateConfidence(clusters),
        }
    }
    
    return nil
}
```

## Phase 4: Scale Testing (Week 4-5)

### 4.1 Stress Tests

```bash
# Crawl 10,000 pages
go run ./cmd/crawl --urls=urls_10k.txt --concurrency=100

# Large pages (GitHub, Reddit)
go test -run=XXX -bench="BenchmarkLargePages"

# Memory pressure
go test -run=XXX -bench="BenchmarkMemoryPressure"
```

### 4.2 Real-World Validation

**Test Sites (increasing difficulty):**

| Site | Challenge | Test Goal |
|------|-----------|-----------|
| httpbin.org | None | Baseline extraction |
| wikipedia.org | Large pages | 500KB+ handling |
| amazon.com | Rate limiting | Stealth effectiveness |
| cloudflare.com | Bot detection | WAF bypass |
| recaptcha-demo | CAPTCHA | Auto-solving |
| github.com | Complex DOM | 361KB handling |

### 4.3 Metrics Collection

```yaml
# Add to prometheus
- semantic_pages_processed_total
- semantic_extraction_errors_total{type="llm|parse|cache"}
- semantic_llm_latency_seconds{quantile="0.5,0.9,0.99"}
- semantic_cache_hit_ratio
- semantic_compression_ratio
- semantic_actions_found_total
- semantic_captcha_solved_total
```

## Phase 5: Advanced Capabilities (Week 5-6)

### 5.1 Multi-Agent Orchestration

```go
type AgentOrchestrator struct {
    agents []*SemanticAgent
    coord  *Coordinator
}

func (o *AgentOrchestrator) ParallelCrawl(urls []string) map[string]*Result {
    // Distribute URLs across agents
    // Each agent has its own browser context
    // Coordinate to avoid overlap
    // Aggregate results
}
```

### 5.2 Learning from Failures

```go
type FailureLearner struct {
    failures []FailureCase
    policy   *ml.PolicyLoader
}

func (l *FailureLearner) LearnFromFailure(failure FailureCase) {
    // 1. Classify failure type
    // 2. Extract features
    // 3. Update policy
    // 4. Retrain model
}
```

### 5.3 Autonomous Data Extraction

```go
type DataExtractor struct {
    navigator *SemanticNavigator
    schema    *ExtractionSchema
}

func (e *DataExtractor) Extract(url string) (map[string]interface{}, error) {
    // 1. Navigate and extract tree
    // 2. Match against schema (JSON-LD, Microdata, heuristics)
    // 3. Auto-detect lists, tables, grids
    // 4. Return structured data
}
```

## Testing Matrix

| Test Type | Coverage | Tools |
|-----------|-----------|-------|
| Unit Tests | Core functions | go test |
| Integration Tests | Pipeline end-to-end | go test |
| Concurrency Tests | Race conditions | go test -race |
| Chaos Tests | Failure modes | custom harness |
| Stress Tests | Performance | bench |
| Fuzz Tests | Edge cases | go-fuzz |
| Real-World Tests | Production | crawl cmd |

## Success Criteria

### Phase 1 Complete When:
- [ ] All concurrency tests pass with `-race`
- [ ] No goroutine leaks under chaos
- [ ] 99th percentile LLM latency < 60s

### Phase 2 Complete When:
- [ ] Can login to 3 test sites (GitHub, Reddit, Twitter)
- [ ] Can complete checkout flow on 2 e-commerce sites
- [ ] Detects and solves reCAPTCHA v2 on demo site

### Phase 3 Complete When:
- [ ] Crawl 1000 pages with <5% error rate
- [ ] Detect changes on monitored pages
- [ ] Extract structured data from 5 product pages

### Phase 4 Complete When:
- [ ] Process 10,000 pages without OOM
- [ ] Sustained 10 pages/second throughput
- [ ] <1% cache corruption under stress

### Production Ready When:
- [ ] All above criteria met
- [ ] Prometheus metrics integrated
- [ ] Runbook documented
- [ ] On-call alerting configured

## Estimated Timeline

| Phase | Duration | Effort |
|-------|----------|--------|
| Phase 1 (Hardening) | 1-2 weeks | 40h |
| Phase 2 (Integration) | 1-2 weeks | 40h |
| Phase 3 (Advanced) | 1-2 weeks | 40h |
| Phase 4 (Scale) | 1 week | 20h |
| Phase 5 (Capabilities) | 1-2 weeks | 30h |
| **Total** | **5-9 weeks** | **170h** |

## Next Immediate Steps

1. **Today:** Implement context cancellation + HNSW heap
2. **Tomorrow:** Add concurrency tests for cache + pipeline
3. **This Week:** Implement semantic form filling
4. **Next Week:** Real-world validation on 5 test sites
