# Go Concepts Used in This Project

> A catalog of Go language features, idioms, and patterns you need to know to read and contribute to this codebase.
>
> **New to Go?** Start with Sections 0.1–0.10 for a syntax primer, then read 1+ for project-specific patterns.

---

## Table of Contents

### Go Syntax Primer (for beginners)
0.1. [Variables, Types & Constants](#01-variables-types--constants)
0.2. [Functions](#02-functions)
0.3. [Control Flow](#03-control-flow)
0.4. [Structs & Methods](#04-structs--methods)
0.5. [Pointers](#05-pointers)
0.6. [Slices, Arrays & Maps](#06-slices-arrays--maps)
0.7. [Packages & Imports](#07-packages--imports)
0.8. [Interfaces (Basics)](#08-interfaces-basics)
0.9. [Goroutines & Channels (Basics)](#09-goroutines--channels-basics)
0.10. [defer (Basics)](#010-defer-basics)
0.11. [Error Handling (Basics)](#011-error-handling-basics)

### Project Patterns
1. [Interfaces & Duck Typing](#1-interfaces--duck-typing)
2. [Struct Embedding & Composition](#2-struct-embedding--composition)
3. [Context Propagation](#3-context-propagation)
4. [Concurrency: Goroutines, Channels, sync](#4-concurrency-goroutines-channels-sync)
5. [Error Handling & Wrapping](#5-error-handling--wrapping)
6. [Type Assertions & Type Switches](#6-type-assertions--type-switches)
7. [Method Chaining (Fluent API)](#7-method-chaining-fluent-api)
8. [defer](#8-defer)
9. [Factory & Registry Patterns](#9-factory--registry-patterns)
10. [Parsing: Recursive Descent & go/ast](#10-parsing-recursive-descent--goast)
11. [CGO](#11-cgo)
12. [Idioms & Conventions](#12-idioms--conventions)
13. [Build Tags & Directives](#13-build-tags--directives)

---

## 0.1. Variables, Types & Constants

### Variable Declaration

Go is **statically typed** — every variable has a type that cannot change.

```go
// Explicit type
var count int = 42

// Type inference (compiler figures it out)
name := "stealth"          // string
active := true             // bool
ratio := 3.14              // float64

// Multiple variables
var a, b, c int = 1, 2, 3
x, y := 10, "hello"

// Zero values (variables are always initialized)
var n int       // 0
var s string    // ""
var ok bool     // false
var p *int      // nil
```

### Basic Types

| Type | Example | Description |
|------|---------|-------------|
| `bool` | `true`, `false` | Boolean |
| `string` | `"hello"` | UTF-8 text (immutable) |
| `int` | `42` | Signed integer (32 or 64 bit) |
| `int64` | `int64(42)` | 64-bit signed integer |
| `uint` | `uint(42)` | Unsigned integer |
| `float64` | `3.14` | 64-bit floating point |
| `byte` | `byte('A')` | Alias for `uint8` |
| `rune` | `rune('中')` | Alias for `int32` (Unicode code point) |

### Constants

```go
const MaxRetries = 3
const (
    StatusOK       = 200
    StatusNotFound = 404
)

// iota generates incrementing constants
const (
    Sunday = iota    // 0
    Monday           // 1
    Tuesday          // 2
)
```

### Type Conversion

Go **never** converts types implicitly. You must cast explicitly:

```go
var i int = 42
var f float64 = float64(i)    // Required!
var s string = strconv.Itoa(i) // int → string
```

---

## 0.2. Functions

### Declaration

```go
// Simple function
func add(a int, b int) int {
    return a + b
}

// Same type parameters can be grouped
func multiply(a, b int) int {
    return a * b
}

// Multiple return values (very common in Go!)
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("cannot divide by zero")
    }
    return a / b, nil
}
```

### Named Return Values

```go
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // "naked return" — returns the named variables
}
```

### Variadic Functions

```go
func sum(nums ...int) int {
    total := 0
    for _, n := range nums {
        total += n
    }
    return total
}

// Call with any number of arguments
result := sum(1, 2, 3, 4)
```

### First-Class Functions

Functions can be passed as arguments and returned:

```go
func apply(a, b int, op func(int, int) int) int {
    return op(a, b)
}

result := apply(3, 4, func(x, y int) int { return x + y })
```

---

## 0.3. Control Flow

### if / else

```go
if err != nil {
    return err
}

// if with initialization (scope limited to the if block)
if resp, err := client.Get(url); err != nil {
    return err
} else {
    defer resp.Body.Close()
}
```

### for Loops

Go has only one loop keyword: `for`.

```go
// Classic for
for i := 0; i < 10; i++ {
    fmt.Println(i)
}

// While-style
for condition {
    // ...
}

// Infinite loop
for {
    // ...
}

// Iterate over a slice (range)
items := []string{"a", "b", "c"}
for index, value := range items {
    fmt.Printf("%d: %s\n", index, value)
}

// If you only need the value, use _ for the index
for _, value := range items {
    fmt.Println(value)
}

// Iterate over a map
scores := map[string]int{"alice": 90, "bob": 85}
for name, score := range scores {
    fmt.Printf("%s: %d\n", name, score)
}
```

### switch

```go
// Switch on value
switch engine {
case "chromium":
    return newChromiumEngine()
case "firefox", "webkit":
    return newPlaywrightEngine(engine)
default:
    return newNativeEngine()
}

// Switch without value (cleaner if/else chain)
switch {
case score > 90:
    return "A"
case score > 80:
    return "B"
default:
    return "C"
}

// Type switch (see also Section 6)
switch v := state["key"].(type) {
case string:
    // v is a string here
    fmt.Println(v)
case int:
    // v is an int here
    fmt.Println(v * 2)
}
```

### select (Channels)

See Section 0.9 for the basics, and Section 4 for advanced usage.

---

## 0.4. Structs & Methods

### Structs

A struct is a collection of fields:

```go
type ProxyConfig struct {
    ListenAddr      string
    EnableMITM      bool
    EnableHTTPTrace bool
}

// Create a struct
cfg := ProxyConfig{
    ListenAddr:      ":8081",
    EnableMITM:      true,
    EnableHTTPTrace: false,
}

// Or use field names (order doesn't matter)
cfg2 := ProxyConfig{ListenAddr: ":8081", EnableMITM: true}

// Or positional (not recommended — breaks when fields change)
cfg3 := ProxyConfig{":8081", true, false}
```

### Methods

A method is a function with a **receiver** — the type it operates on:

```go
func (p *Proxy) Start() error {
    // p is the receiver (like "this" in other languages)
    listener, err := net.Listen("tcp", p.config.ListenAddr)
    if err != nil {
        return err
    }
    p.listener = listener
    return nil
}
```

**Pointer receiver (`*Proxy`)** vs **Value receiver (`Proxy`)**:
- Use **pointer receivers** when you need to modify the struct or the struct is large
- Use **value receivers** for small, immutable structs

```go
// Pointer receiver — modifies the original
func (p *Proxy) SetAddr(addr string) {
    p.config.ListenAddr = addr
}

// Value receiver — receives a copy (can't modify original)
func (p Proxy) Addr() string {
    return p.config.ListenAddr
}
```

---

## 0.5. Pointers

A pointer holds the **memory address** of a value.

```go
var x int = 42
var p *int = &x    // & gets the address

fmt.Println(*p)    // * dereferences — prints 42
*p = 100           // Modifies x through the pointer
fmt.Println(x)     // Prints 100
```

### Common Patterns

```go
// new() allocates and returns a pointer
node := new(baseNode)    // *baseNode, zero-initialized

// & before a composite literal creates a pointer
cfg := &ProxyConfig{
    ListenAddr: ":8081",
}

// nil pointer check
if p == nil {
    return errors.New("proxy is nil")
}
```

---

## 0.6. Slices, Arrays & Maps

### Arrays

Fixed-size, rarely used directly:

```go
var arr [3]int = [3]int{1, 2, 3}
```

### Slices

Slices are **dynamic views** into arrays. They are used everywhere.

```go
// Declare
var nums []int                    // nil slice
items := []string{"a", "b"}       // literal

// append adds elements
items = append(items, "c")

// make creates a slice with length and capacity
results := make([]string, 0, 10)  // len=0, cap=10

// Slice of a slice (shares underlying array!)
sub := items[1:3]   // elements 1 and 2

// Length and capacity
fmt.Println(len(items))  // 3
fmt.Println(cap(items))  // 3 or more

// Copy to avoid shared backing array
dst := make([]string, len(items))
copy(dst, items)
```

### Maps

Key-value hash tables:

```go
// Declare
var scores map[string]int

// Initialize
scores = make(map[string]int)

// Literal
cfg := map[string]interface{}{
    "reasoning": true,
    "reattempt": true,
}

// Get value
val := cfg["reasoning"]        // returns interface{} (zero value if missing)

// Check if key exists
val, ok := cfg["missing"]      // ok is false if key doesn't exist
if !ok {
    // handle missing key
}

// Delete
delete(cfg, "reasoning")

// Iterate
for k, v := range cfg {
    fmt.Printf("%s = %v\n", k, v)
}
```

---

## 0.7. Packages & Imports

### Package Declaration

Every Go file starts with a package:

```go
package agentic    // Package name (usually same as directory)
```

### Importing

```go
import (
    "context"                           // Standard library
    "fmt"
    "net/http"

    "github.com/skunkworq/stealth/brws/content/semantic"  // Project package
    "github.com/chromedp/chromedp"     // External dependency
)
```

### Blank Import

Import for side effects (e.g., registering engines):

```go
import _ "github.com/skunkworq/stealth/brws/browser/engine/native"
```

### Dot Import (rarely used)

```go
import . "fmt"
// Now you can call Println() without fmt.
```

### Aliased Import

```go
import utls "github.com/refraction-networking/utls"
```

---

## 0.8. Interfaces (Basics)

An interface defines a set of methods. A type satisfies an interface by implementing all its methods — **no explicit declaration needed**.

```go
// Define an interface
type Engine interface {
    Name() string
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}

// Any type that has these methods is an Engine automatically
type nativeEngine struct{}

func (e *nativeEngine) Name() string { return "native" }
func (e *nativeEngine) Do(ctx context.Context, req *Request) (*Response, error) {
    // ...
}
func (e *nativeEngine) Close() error { return nil }

// nativeEngine satisfies Engine without ever saying so
```

### The Empty Interface

`interface{}` (or `any` in Go 1.18+) means "any type":

```go
func printAnything(v interface{}) {
    fmt.Printf("value: %v, type: %T\n", v, v)
}

printAnything(42)
printAnything("hello")
printAnything([]int{1, 2, 3})
```

See Section 1 and 6 for advanced interface patterns.

---

## 0.9. Goroutines & Channels (Basics)

### Goroutines

A goroutine is a lightweight thread managed by the Go runtime:

```go
func main() {
    go doWork()   // Launches doWork() in a new goroutine
    go doWork()   // Launches another
    time.Sleep(time.Second)  // Wait for them to finish (naive way)
}
```

### Channels

Channels are typed pipes for goroutine communication:

```go
// Create a channel
ch := make(chan int)

// Send (blocks until someone receives)
ch <- 42

// Receive (blocks until someone sends)
value := <-ch

// Buffered channel (non-blocking until full)
ch := make(chan int, 10)
```

### Common Patterns

```go
// Worker pool pattern
jobs := make(chan int, 100)
results := make(chan int, 100)

for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}

for j := 1; j <= 9; j++ {
    jobs <- j
}
close(jobs)
```

See Section 4 for advanced concurrency patterns (`sync.WaitGroup`, `Mutex`, `select`).

---

## 0.10. defer (Basics)

`defer` schedules a function call to run when the surrounding function returns:

```go
func readFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()   // Will run when readFile returns

    // Read file...
    return nil        // f.Close() runs here
}
```

**Key rules:**
- Deferred calls run in **LIFO** order (last defer runs first)
- Arguments are evaluated immediately, but the call is deferred

```go
func example() {
    defer fmt.Println("first")
    defer fmt.Println("second")
    defer fmt.Println("third")
}
// Output: third, second, first
```

See Section 8 for more `defer` patterns.

---

## 0.11. Error Handling (Basics)

Go uses **explicit error returns**, not exceptions.

```go
func fetch(url string) (*http.Response, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err      // Return error to the caller
    }
    return resp, nil
}

// Caller handles the error
resp, err := fetch("https://example.com")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
```

### Creating Errors

```go
import "errors"

var ErrNotFound = errors.New("not found")

func find(id string) (*Item, error) {
    if id == "" {
        return nil, ErrNotFound
    }
    // ...
}
```

See Section 5 for error wrapping and advanced patterns.

---

## 1. Interfaces & Duck Typing

Go interfaces are **implicitly satisfied** — you don't declare that a type implements an interface, you just implement the methods.

### The Core `Node` Interface

```go
// brws/content/agentic/engine.go
type Node interface {
    Name() string
    NodeType() string
    InputExpr() string
    Outputs() []string
    MinInputs() int
    Execute(ctx context.Context, state State) (State, string, error)
}
```

Any struct with these methods is a `Node` — no `implements` keyword needed.

### Multiple Interface Implementations

`FetchNode` implements `Node` without ever mentioning it:

```go
// brws/content/agentic/nodes_core.go
type FetchNode struct {
    Base         baseNode
    HTTPClient   *http.Client
    // ...
}

func (n *FetchNode) Name() string      { return n.Base.nodeName }
func (n *FetchNode) NodeType() string  { return n.Base.nodeType }
func (n *FetchNode) InputExpr() string { return n.Base.inputExpr }
func (n *FetchNode) Outputs() []string { return n.Base.output }
func (n *FetchNode) MinInputs() int    { return n.Base.minInputs }
func (n *FetchNode) Execute(ctx context.Context, state State) (State, string, error) {
    // ...
}
```

### Interface Composition

```go
// brws/browser/engine/engine.go
type Engine interface {
    Name() string
    Capabilities() Capabilities
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}
```

The `io.Closer` interface (`Close() error`) is embedded here. Any `Engine` is also an `io.Closer`.

### Empty Interface (`interface{}` / `any`)

Used for the generic `State` map values:

```go
// brws/content/agentic/engine.go
type State map[string]interface{}
```

This allows storing any type in the state dictionary, but requires **type assertions** when reading values back.

---

## 2. Struct Embedding & Composition

Go favors composition over inheritance. Struct embedding lets you "inherit" fields and methods.

### Embedded `net.Conn`

```go
// brws/network/proxy/proxy.go
type capturedConn struct {
    net.Conn           // embed net.Conn — gets all its methods

    id          string
    startTime   time.Time
    clientAddr  string
    // ...
}
```

`capturedConn` has all methods of `net.Conn` (`Read`, `Write`, `Close`, etc.) automatically. You can override specific methods.

### Embedding for Code Reuse

```go
// brws/content/agentic/nodes_core.go
type baseNode struct {
    nodeName   string
    nodeType   string
    inputExpr  string
    output     []string
    minInputs  int
    nodeConfig map[string]interface{}
}

type FetchNode struct {
    Base         baseNode    // embed baseNode
    HTTPClient   *http.Client
    Timeout      int
}
```

`FetchNode` accesses `Base.nodeName` directly. The methods on `FetchNode` delegate to `Base` for common behavior.

---

## 3. Context Propagation

`context.Context` is the backbone of cancellation, deadlines, and request-scoped values.

### Passing Context Through the Call Stack

```go
// brws/content/agentic/engine.go
func (g *BaseGraph) Execute(ctx context.Context, initialState State) (State, []ExecutionInfo, error) {
    // ...
    resultState, condNext, err := node.Execute(ctx, state)
    // ...
}
```

Every `Execute` method takes `context.Context` as its first argument. This allows:
- **Cancellation**: stop mid-execution
- **Deadlines**: timeout the entire graph
- **Values**: pass request-scoped metadata (trace IDs, etc.)

### Context With Timeout

```go
// brws/content/agent/agent.go
func (a *Agent) Execute(ctx context.Context, action Action) (*ExecuteResult, error) {
    execCtx, cancel := context.WithTimeout(ctx, a.cfg.ActionTimeout)
    defer cancel()
    res, err := a.executor.Execute(execCtx, action)
    // ...
}
```

### Context Cancellation for Goroutines

```go
// brws/network/proxy/proxy.go
func (p *Proxy) acceptLoop() {
    for {
        conn, err := p.listener.Accept()
        if err != nil {
            select {
            case <-p.ctx.Done():  // check if context was cancelled
                return
            default:
                p.logger.Error("Accept error", "error", err)
                continue
            }
        }
        go p.handleConnection(conn)
    }
}
```

---

## 4. Concurrency: Goroutines, Channels, sync

### Goroutines

Lightweight threads launched with the `go` keyword:

```go
// brws/network/proxy/proxy.go
go p.acceptLoop()
```

```go
// brws/content/agentic/nodes_llm.go
go func(idx int, c string) {
    defer wg.Done()
    // process chunk ...
}(i, chunk)
```

### sync.WaitGroup

Wait for a collection of goroutines to finish:

```go
// brws/content/agentic/nodes_llm.go
var wg sync.WaitGroup
for i, chunk := range chunks {
    wg.Add(1)
    go func(idx int, c string) {
        defer wg.Done()
        // ... LLM call ...
    }(i, chunk)
}
wg.Wait()  // block until all goroutines call Done()
```

### Semaphore Pattern (Buffered Channel)

Limit concurrent goroutines:

```go
// brws/content/agentic/nodes_llm.go
sem := make(chan struct{}, 4)  // max 4 concurrent workers

go func(idx int, c string) {
    defer wg.Done()
    sem <- struct{}{}        // acquire
    defer func() { <-sem }() // release
    // ... work ...
}(i, chunk)
```

### sync.Mutex / sync.RWMutex

Protect shared state:

```go
// brws/content/agentic/graphs.go
type GraphIteratorNode struct {
    // ...
}

// Parallel URL scraping
var mu sync.Mutex
var results []interface{}

for i, u := range urls {
    go func(idx int, url string) {
        // ... scrape ...
        mu.Lock()
        results[idx] = ans
        mu.Unlock()
    }(i, u)
}
```

Read-heavy scenarios use `RWMutex`:

```go
// brws/content/agent/agent.go
type Agent struct {
    mu        sync.RWMutex
    history   []Step
}

func (a *Agent) History() []Step {
    a.mu.RLock()
    defer a.mu.RUnlock()
    h := make([]Step, len(a.history))
    copy(h, a.history)
    return h
}
```

### sync.Map

Concurrent-safe map (used when map operations are spread across many goroutines):

```go
// brws/network/proxy/pool/tier.go
type TierTracker struct {
    states sync.Map  // map[eTLD+1]*domainTierState
}

// Load/Store without explicit locking
val, ok := t.states.Load(domain)
t.states.Store(domain, newState)
```

### Select Statement

Wait on multiple channel operations:

```go
select {
case <-p.ctx.Done():
    return  // shutdown
default:
    p.logger.Error("Accept error", "error", err)
}
```

---

## 5. Error Handling & Wrapping

Go uses explicit error returns, not exceptions.

### Basic Error Return

```go
func (g *BaseGraph) Execute(ctx context.Context, initialState State) (State, []ExecutionInfo, error) {
    // ...
    if err != nil {
        return state, execInfo, fmt.Errorf("node %q failed: %w", node.Name(), err)
    }
    // ...
}
```

### Error Wrapping with `%w`

The `%w` verb wraps an error, preserving it for `errors.Is()` and `errors.As()`:

```go
resp, err := client.Do(req)
if err != nil {
    return nil, fmt.Errorf("request failed: %w", err)
}
```

Later you can check:

```go
if errors.Is(err, context.DeadlineExceeded) {
    // handle timeout
}
```

### Sentinel Errors

```go
var ErrSessionNotFound = fmt.Errorf("session not found")
```

### Custom Error Types

```go
// brws/content/semantic/error.go
type LLMError struct {
    Message string
}

func (e *LLMError) Error() string {
    return fmt.Sprintf("LLM error: %s", e.Message)
}

func NewLLMError(msg string) error {
    return &LLMError{Message: msg}
}
```

---

## 6. Type Assertions & Type Switches

Since `State` uses `map[string]interface{}`, you must assert types when reading:

### Type Assertion

```go
// brws/content/agentic/nodes_llm.go
userPrompt, _ := state["user_prompt"].(string)
```

The two-value form checks success:

```go
urls, ok := state["urls"].([]string)
if !ok {
    return state, "", fmt.Errorf("graph iterator requires urls")
}
```

### Type Switch

```go
// brws/content/agentic/nodes_llm.go
switch v := state[keys[0]].(type) {
case []string:
    content = strings.Join(v, "\n")
case string:
    content = v
case []Document:
    var parts []string
    for _, d := range v {
        parts = append(parts, d.PageContent)
    }
    content = strings.Join(parts, "\n")
default:
    content = fmt.Sprintf("%v", v)
}
```

---

## 7. Method Chaining (Fluent API)

Return the receiver to enable chained calls:

```go
// brws/fingerprint/tls/spoofer.go
func (fg *FingerprintGenerator) Browser(browser Browser) *FingerprintGenerator {
    fg.browser = browser
    return fg
}

func (fg *FingerprintGenerator) Version(version string) *FingerprintGenerator {
    fg.version = version
    return fg
}

func (fg *FingerprintGenerator) ALPN(enabled bool) *FingerprintGenerator {
    fg.alpn = enabled
    return fg
}

// Usage:
id := tlsfprint.NewFingerprintGenerator().
    Browser(tlsfprint.Chrome).
    Version("133").
    ALPN(true).
    Seed(42).
    Build()
```

---

## 8. defer

`defer` schedules a function call to run when the surrounding function returns. Used for cleanup.

```go
func (p *Proxy) handleConnection(clientConn net.Conn) {
    defer func() { _ = clientConn.Close() }()
    // ...
}
```

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
```

```go
resp, err := client.Do(req)
if err != nil {
    return nil, err
}
defer func() { _ = resp.Body.Close() }()
```

**Important**: `defer` runs in LIFO order (last defer runs first).

---

## 9. Factory & Registry Patterns

### Factory Function

```go
// brws/network/proxy/proxy.go
func NewProxy(config *ProxyConfig, logger *slog.Logger) (*Proxy, error) {
    if config == nil {
        config = DefaultProxyConfig()
    }
    if logger == nil {
        logger = slog.Default()
    }
    // ...
}
```

### Global Registry

```go
// brws/browser/engine/engine.go
var engines = make(map[string]func(Options) (Engine, error))

func Register(name string, constructor func(Options) (Engine, error)) {
    engines[name] = constructor
}

func New(name string, opts Options) (Engine, error) {
    ctor, ok := engines[name]
    if !ok {
        return nil, fmt.Errorf("unknown engine: %s", name)
    }
    return ctor(opts)
}
```

Engines self-register via `init()`:

```go
// brws/browser/engine/native/native.go
func init() {
    engine.Register("native", newNativeEngine)
}
```

---

## 10. Parsing: Recursive Descent & go/ast

### Recursive Descent Parser

The input expression parser (`ParseInputKeys`) is a hand-written recursive descent parser:

```go
// brws/content/agentic/engine.go
func (p *exprParser) parseExpr() ([]string, error) {
    left, err := p.parseTerm()
    if err != nil {
        return nil, err
    }
    for p.peek() == "|" {
        p.consume()
        right, err := p.parseTerm()
        if err != nil {
            return nil, err
        }
        if len(left) > 0 {
            return left, nil
        }
        left = right
    }
    return left, nil
}
```

### go/ast for Expression Evaluation

`ConditionalNode` uses Go's standard library AST parser to evaluate conditions:

```go
// brws/content/agentic/nodes_control.go
import (
    "go/ast"
    "go/parser"
    "go/token"
)

func evalCondition(state State, expr string) (bool, error) {
    normalized := strings.ToLower(expr)
    normalized = strings.ReplaceAll(normalized, "not ", "!")
    normalized = strings.ReplaceAll(normalized, " and ", " && ")
    normalized = strings.ReplaceAll(normalized, " or ", " || ")

    fset := token.NewFileSet()
    node, err := parser.ParseExprFrom(fset, "", normalized, 0)
    if err != nil {
        return false, fmt.Errorf("parse condition %q: %w", expr, err)
    }

    return evalAST(node, state)
}
```

Then a recursive `evalAST` function walks the AST nodes:

```go
func evalAST(node ast.Expr, state State) (bool, error) {
    switch n := node.(type) {
    case *ast.BinaryExpr:
        // handle &&, ||, ==, !=
    case *ast.UnaryExpr:
        // handle !
    case *ast.Ident:
        // lookup in state map
    case *ast.ParenExpr:
        return evalAST(n.X, state)
    // ...
    }
}
```

---

## 11. CGO

CGO allows calling C (and Rust via C ABI) code from Go.

```go
// brws/network/sniff/sniffer.go
/*
#include <stdint.h>
#include <stdlib.h>

// Rust FFI declarations
typedef struct { ... } PacketEventC;

extern void stealth_sniffer_start(const char* iface, void* callback);
*/
import "C"

func StartSniffer(iface string, handler func(Packet)) {
    cIface := C.CString(iface)
    defer C.free(unsafe.Pointer(cIface))

    C.stealth_sniffer_start(cIface, unsafe.Pointer(&handler))
}
```

Key CGO concepts here:
- `/* ... */` comment before `import "C"` contains C code
- `C.CString()` converts Go string to C string (must `free` it)
- `unsafe.Pointer` bridges Go and C pointers
- `// #cgo LDFLAGS: -lstealth_sniffer` links the Rust library

---

## 12. Idioms & Conventions

### Named Return Values

```go
func splitText(text string, maxChars int) (chunks []string) {
    // chunks is pre-declared; just use return without naming it
    // ...
    return
}
```

### Blank Identifier `_`

Ignore unwanted return values:

```go
_ = resp.Body.Close()
```

Import for side effects only:

```go
import _ "github.com/skunkworq/stealth/brws/browser/engine/native"
```

### String Builders

```go
var buf strings.Builder
buf.WriteString("hello")
buf.WriteByte('\n')
result := buf.String()
```

### JSON Struct Tags

```go
type ExecutionInfo struct {
    NodeName           string        `json:"node_name"`
    TotalTokens        int           `json:"total_tokens"`
    PromptTokens       int           `json:"prompt_tokens"`
    CompletionTokens   int           `json:"completion_tokens"`
    SuccessfulRequests int           `json:"successful_requests"`
    TotalCostUSD       float64       `json:"total_cost_usd"`
    ExecTime           time.Duration `json:"exec_time"`
}
```

### Iota for Enums

```go
// brws/content/agent/types.go
type ActionType string

const (
    ActionClick        ActionType = "click"
    ActionTypeText     ActionType = "type"
    ActionSelect       ActionType = "select"
    ActionToggle       ActionType = "toggle"
    ActionScrollDown   ActionType = "scroll_down"
    // ...
)
```

### Functional Options Pattern (partially used)

```go
// brws/crawl/spider/spider.go (conceptual)
spider.NewCrawler(spiderObj,
    spider.WithSettings(settings),
    spider.WithEngine("chromium-stealth"),
    spider.WithConcurrentRequests(16),
)
```

### `make` for Slices and Maps

```go
m.sessions = make(map[string]*Session)
h := make([]Step, 0, cfg.HistorySize)  // len=0, cap=HistorySize
```

### Copy to Prevent Mutation

```go
func (a *Agent) History() []Step {
    a.mu.RLock()
    defer a.mu.RUnlock()
    h := make([]Step, len(a.history))
    copy(h, a.history)  // shallow copy of slice
    return h
}
```

### `strings.NewReplacer` for Template Substitution

```go
prompt := strings.NewReplacer(
    "{{format_instructions}}", formatInstructions,
    "{{question}}", question,
    "{{content}}", content,
).Replace(promptSingleChunk)
```

---

## 13. Build Tags & Directives

### `//go:build` Tags

Not heavily used in this project, but relevant:

```go
//go:build ignore

// Example: agentic_scraper.go — skipped during normal build
package main
```

### `//nolint` Directives

Suppress linter warnings:

```go
//nolint:gosec // SSRF protection is the responsibility of the caller - this is a proxy
resp, err := client.Do(targetReq)
```

```go
//nolint:revive // Variable names match utls library naming convention
var HelloChrome_Auto = utls.HelloChrome_Auto
```

```go
//nolint:gosec // G501, G404: crypto/md5 and math/rand used intentionally for fingerprinting
package tlsfprint
```

---

## Quick Reference: "If you see X, it means Y"

| Syntax | Meaning |
|---|---|
| `go func() { ... }()` | Launch a goroutine |
| `defer cancel()` | Run `cancel()` when function returns |
| `v, ok := m["key"]` | Check if map key exists |
| `v, ok := x.(string)` | Type assertion — check if `x` is a `string` |
| `switch v := x.(type)` | Type switch — handle multiple types |
| `select { case <-ch: ... }` | Wait on channels |
| `make(chan struct{}, N)` | Buffered channel used as semaphore |
| `sync.RWMutex` | Many readers, one writer |
| `fmt.Errorf("...: %w", err)` | Wrap error for inspection |
| `strings.Builder` | Efficient string concatenation |
| `io.NopCloser(bytes.NewReader(data))` | Wrap bytes as `io.ReadCloser` |
| `filepath.Clean(path)` | Normalize file path |
| `slog.Default()` | Structured logging default logger |
| `context.WithTimeout(ctx, dur)` | Cancel after duration |
| `parser.ParseExprFrom(...)` | Parse Go expression from string |

---

*This document covers the Go concepts essential for understanding the Stealth codebase. For Go language fundamentals, see [A Tour of Go](https://go.dev/tour/).*
