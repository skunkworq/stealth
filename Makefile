# Browser Fingerprint Lab Makefile
.PHONY: all build clean test ci test-go test-frontend typecheck run run-lab run-lab-https certs help install kill-ports lab-ui ml-datagen ml-generate ml-export ml-stats train train-run train-benchmark train-discover

# Variables
BINARY_DIR := build
LABD_BINARY := $(BINARY_DIR)/labd
BRWSLAB_BINARY := $(BINARY_DIR)/brwslab
EVALBENCH_BINARY := $(BINARY_DIR)/evalbench
ML_DATAGEN_BINARY := $(BINARY_DIR)/ml_datagen

# Source files
LABD_SRC := ./cmd/labd
BRWSLAB_SRC := ./cmd/brwslab
EVALBENCH_SRC := ./cmd/evalbench
ML_DATAGEN_SRC := ./cmd/ml_datagen

# Certificate files
CERT_FILE := server.crt
KEY_FILE := server.key

# Default ports
HTTP_PORT := 8080
HTTPS_PORT := 8443

# Build flags
LDFLAGS := -ldflags="-s -w"

# PID file for tracking labd process
PID_FILE := .labd.pid

all: build

## ------- Primary Entrypoint -------

lab-ui: ## Build the React UI and embed into Go static dir
	@echo "Building lab-ui..."
	@cd lab-ui && npm run build --silent
	@rm -rf brws/lab/static/_next brws/lab/static/_not-found
	@cp -r lab-ui/out/* brws/lab/static/
	@rm -rf brws/lab/static/_not-found brws/lab/static/_not-found.html brws/lab/static/__next.*
	@echo "✓ UI built and copied to brws/lab/static/"

run: kill-ports lab-ui $(LABD_BINARY) certs ## Build everything and run (UI + HTTPS + proxy)
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║       Browser Fingerprint Lab                                ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  HTTP:    http://localhost:$(HTTP_PORT)"
	@echo "  HTTPS:   https://localhost:$(HTTPS_PORT)"
	@echo "  Proxy:   localhost:$(PROXY_PORT)"
	@echo ""
	@echo "  Use the Controls panel in the UI to start proxy + Chrome"
	@echo ""
	@echo "  Press Ctrl+C to stop"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--proxy-port $(PROXY_PORT) \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) \
		-v

help: ## Show this help message
	@echo "Browser Fingerprint Lab - Available Targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: $(LABD_BINARY) $(BRWSLAB_BINARY) $(BENCHMARK_BINARY) $(ML_DATAGEN_BINARY) $(TRAIN_BINARY) ## Build all binaries

rust-sniffer:
	@echo "Building Rust sniffer library..."
	@cd brws/sniffer/rust && cargo build --release
	@echo "✓ Built rust sniffer"

$(LABD_BINARY): rust-sniffer $(shell find brws/lab brws/adversarial cmd/labd -name '*.go' 2>/dev/null) brws/lab/static/index.html
	@echo "Building labd..."
	@mkdir -p $(BINARY_DIR)
	go build $(LDFLAGS) -o $@ $(LABD_SRC)
	@echo "✓ Built $@"

$(BRWSLAB_BINARY): $(shell find brws -name '*.go' cmd/brwslab -name '*.go' 2>/dev/null)
	@echo "Building brwslab..."
	@mkdir -p $(BINARY_DIR)
	go build $(LDFLAGS) -o $@ $(BRWSLAB_SRC)
	@echo "✓ Built $@"

$(EVALBENCH_BINARY): $(shell find cmd/evalbench -name '*.go' 2>/dev/null)
	@echo "Building evalbench..."
	@mkdir -p $(BINARY_DIR)
	go build $(LDFLAGS) -o $@ $(EVALBENCH_SRC)
	@echo "✓ Built $@"

BENCHMARK_BINARY := $(BINARY_DIR)/benchmark
BENCHMARK_SRC := ./cmd/benchmark

$(BENCHMARK_BINARY): $(shell find cmd/benchmark -name '*.go' brws/benchmark -name '*.go' 2>/dev/null)
	@echo "Building benchmark..."
	@mkdir -p $(BINARY_DIR)
	go build $(LDFLAGS) -o $@ $(BENCHMARK_SRC)
	@echo "✓ Built $@"

benchmark: $(BENCHMARK_BINARY) ## Build the extended benchmark tool
	@echo "Extended benchmark tool built at $(BENCHMARK_BINARY)"
	@echo ""
	@echo "Usage examples:"
	@echo "  $(BENCHMARK_BINARY) --suite all"
	@echo "  $(BENCHMARK_BINARY) --suite capabilities"
	@echo "  $(BENCHMARK_BINARY) --suite endpoints --categories basic,protocol"
	@echo "  $(BENCHMARK_BINARY) --engines native,chromium --suite performance"
	@echo ""
	@echo "List available endpoints:"
	@echo "  $(BENCHMARK_BINARY) list"
	@echo ""
	@echo "List available engines:"
	@echo "  $(BENCHMARK_BINARY) engines"

benchmark-run: $(BENCHMARK_BINARY) ## Run the extended benchmark suite
	$(BENCHMARK_BINARY) --suite all --timeout 30s

# ML Data Generation targets
$(ML_DATAGEN_BINARY): $(shell find cmd/ml_datagen brws/ml -name '*.go' 2>/dev/null)
	@echo "Building ml_datagen..."
	@mkdir -p $(BINARY_DIR)
	go build $(LDFLAGS) -o $@ $(ML_DATAGEN_SRC)
	@echo "✓ Built $@"

ml-datagen: $(ML_DATAGEN_BINARY) ## Build the ML data generator tool

ml-generate: $(ML_DATAGEN_BINARY) ## Generate ML training episodes from the lab
	$(ML_DATAGEN_BINARY) generate --episodes 500

ml-export: $(ML_DATAGEN_BINARY) ## Export ML training data to CSV
	$(ML_DATAGEN_BINARY) export --format csv --output data/training/

ml-stats: $(ML_DATAGEN_BINARY) ## Show ML training data statistics
	$(ML_DATAGEN_BINARY) stats

# Training targets
TRAIN_BINARY := $(BINARY_DIR)/train
TRAIN_SRC := ./cmd/train

$(TRAIN_BINARY): $(shell find cmd/train brws/ml brws/lab -name '*.go' 2>/dev/null)
	@echo "Building train..."
	@mkdir -p $(BINARY_DIR)
	go build $(LDFLAGS) -o $@ $(TRAIN_SRC)
	@echo "✓ Built $@"

train: $(TRAIN_BINARY) ## Build the training orchestration tool

train-run: $(TRAIN_BINARY) ## Run the full training pipeline
	$(TRAIN_BINARY) run --lab-url http://localhost:$(HTTP_PORT) --episodes 500 --benchmark-episodes 100

train-benchmark: $(TRAIN_BINARY) ## Run a benchmark evaluation
	$(TRAIN_BINARY) benchmark --lab-url http://localhost:$(HTTP_PORT) --episodes 100

train-discover: $(TRAIN_BINARY) ## Discover browser fingerprints
	$(TRAIN_BINARY) discover --lab-url http://localhost:$(HTTP_PORT) --output signatures/

certs: $(CERT_FILE) $(KEY_FILE) ## Generate self-signed TLS certificates

$(CERT_FILE) $(KEY_FILE):
	@echo "Generating self-signed TLS certificates..."
	openssl req -x509 -newkey rsa:4096 \
		-keyout $(KEY_FILE) -out $(CERT_FILE) \
		-days 365 -nodes \
		-subj "/C=US/ST=State/L=City/O=BrowserLab/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "✓ Generated $(CERT_FILE) and $(KEY_FILE)"

kill-ports: ## Kill any processes using lab ports (8080, 8443, 8081)
	@echo "Checking for processes on ports $(HTTP_PORT), $(HTTPS_PORT), $(PROXY_PORT)..."
	@# Kill by PID file if exists
	@if [ -f $(PID_FILE) ]; then \
		PID=$$(cat $(PID_FILE) 2>/dev/null); \
		if [ -n "$$PID" ] && kill -0 $$PID 2>/dev/null; then \
			echo "Killing previous labd (PID: $$PID)"; \
			kill $$PID 2>/dev/null || true; \
			sleep 1; \
		fi; \
		rm -f $(PID_FILE); \
	fi
	@# Kill any process using the ports (macOS and Linux compatible)
	@for PORT in $(HTTP_PORT) $(HTTPS_PORT) $(PROXY_PORT); do \
		if command -v lsof >/dev/null 2>&1; then \
			PIDS=$$(lsof -ti:$$PORT 2>/dev/null); \
		elif command -v netstat >/dev/null 2>&1; then \
			PIDS=$$(netstat -vanp tcp 2>/dev/null | grep "\.$$PORT " | awk '{print $$9}' | grep -o '[0-9]*' | head -1); \
		elif command -v ss >/dev/null 2>&1; then \
			PIDS=$$(ss -tlnp 2>/dev/null | grep ":$$PORT " | sed 's/.*pid=\([0-9]*\).*/\1/' | head -1); \
		fi; \
		if [ -n "$$PIDS" ]; then \
			echo "Killing process(es) on port $$PORT: $$PIDS"; \
			kill -9 $$PIDS 2>/dev/null || true; \
		fi; \
	done
	@sleep 1
	@echo "✓ Ports cleared"

stop-lab: kill-ports ## Stop the lab server
	@echo "Lab server stopped"

# Proxy configuration
PROXY_PORT := 8081

run-lab: kill-ports $(LABD_BINARY) ## Run lab server (HTTP only, foreground with logs)
	@echo "Starting lab server on http://localhost:$(HTTP_PORT)"
	@echo "Press Ctrl+C to stop"
	@echo ""
	@$(LABD_BINARY) --http-port $(HTTP_PORT) --https-port $(HTTPS_PORT)

run-lab-https: kill-ports $(LABD_BINARY) certs ## Run lab server with HTTPS (foreground with logs)
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║           Browser Fingerprint Lab Server                      ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Endpoints:"
	@echo "  HTTP:    http://localhost:$(HTTP_PORT)"
	@echo "  HTTPS:   https://localhost:$(HTTPS_PORT)"
	@echo ""
	@echo "Test commands:"
	@echo "  curl http://localhost:$(HTTP_PORT)/health"
	@echo "  curl -k https://localhost:$(HTTPS_PORT)/health  # -k for self-signed cert"
	@echo ""
	@echo "Note: Browser will warn about self-signed certificate - this is expected"
	@echo ""
	@echo "Press Ctrl+C to stop"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) \
		-v

run-lab-debug: kill-ports $(LABD_BINARY) certs ## Run lab server with verbose logging
	@echo "Starting lab server in DEBUG mode..."
	@echo "Logs will be saved to labd.log"
	@echo "Press Ctrl+C to stop"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) \
		-v 2>&1 | tee labd.log

run-lab-bg: kill-ports $(LABD_BINARY) certs ## Run lab server in background
	@echo "Starting lab server in background..."
	@echo "  - HTTP:  http://localhost:$(HTTP_PORT)"
	@echo "  - HTTPS: https://localhost:$(HTTPS_PORT)"
	@nohup $(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) \
		-v > labd.log 2>&1 &
	@echo $$! > $(PID_FILE)
	@echo "Server PID: $$!"
	@echo "Logs: tail -f labd.log"

# MITM Proxy targets
run-proxy: kill-ports $(LABD_BINARY) certs ## Run lab with MITM proxy (no Chrome)
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║     Browser Fingerprint Lab - MITM Proxy Mode                ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Proxy Configuration:"
	@echo "  PAC File:  http://localhost:$(HTTP_PORT)/proxy.pac"
	@echo "  Proxy:     localhost:$(PROXY_PORT)"
	@echo ""
	@echo "Configure your browser:"
	@echo "  1. Automatic: Set PAC to http://localhost:$(HTTP_PORT)/proxy.pac"
	@echo "  2. Manual:    Set HTTP proxy to localhost:$(PROXY_PORT)"
	@echo ""
	@echo "Web UI: http://localhost:$(HTTP_PORT)/"
	@echo ""
	@echo "Press Ctrl+C to stop"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--proxy-port $(PROXY_PORT) \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) \
		-v

run-transparent: kill-ports $(LABD_BINARY) ## Run lab with transparent proxy (no MITM, captures then forwards)
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║     Browser Fingerprint Lab - Transparent Proxy              ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Mode: Capture ClientHello, then forward RAW TLS to target"
	@echo "Preserves Chrome's original TLS fingerprint (JA3)"
	@echo ""
	@echo "Proxy Configuration:"
	@echo "  PAC File:  http://localhost:$(HTTP_PORT)/proxy.pac"
	@echo "  Proxy:     localhost:$(PROXY_PORT)"
	@echo ""
	@echo "Configure your browser:"
	@echo "  1. Automatic: Set PAC to http://localhost:$(HTTP_PORT)/proxy.pac"
	@echo "  2. Manual:    Set HTTP proxy to localhost:$(PROXY_PORT)"
	@echo ""
	@echo "Web UI: http://localhost:$(HTTP_PORT)/"
	@echo ""
	@echo "Press Ctrl+C to stop"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--proxy-port $(PROXY_PORT) \
		--proxy-mode transparent \
		-v

run-chrome: kill-ports $(LABD_BINARY) certs ## Run lab with MITM proxy and auto-launch Chrome
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║     Browser Fingerprint Lab - Chrome + MITM Proxy            ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Starting lab server and Chrome..."
	@echo ""
	@echo "Web UI:    http://localhost:$(HTTP_PORT)/"
	@echo "Proxy:     localhost:$(PROXY_PORT)"
	@echo "Mode:      MITM (proxy terminates TLS)"
	@echo ""
	@echo "⚠️  Note: Some sites may detect the proxy TLS fingerprint"
	@echo "    Use 'make run-chrome-transparent' for bot-protected sites"
	@echo ""
	@echo "Press Ctrl+C to stop (Chrome will close)"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--proxy-port $(PROXY_PORT) \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) \
		--chrome \
		-v

run-chrome-transparent: kill-ports $(LABD_BINARY) ## Run lab with transparent proxy and auto-launch Chrome
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║  Browser Fingerprint Lab - Chrome + Transparent Proxy        ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Starting lab server and Chrome..."
	@echo ""
	@echo "Web UI:    http://localhost:$(HTTP_PORT)/"
	@echo "Proxy:     localhost:$(PROXY_PORT)"
	@echo "Mode:      Transparent (raw TLS forwarding)"
	@echo ""
	@echo "✓ Chrome's TLS fingerprint is preserved (JA3)"
	@echo "✓ Use this mode for bot-protected sites"
	@echo ""
	@echo "Press Ctrl+C to stop (Chrome will close)"
	@echo ""
	@$(LABD_BINARY) \
		--http-port $(HTTP_PORT) \
		--https-port $(HTTPS_PORT) \
		--proxy-port $(PROXY_PORT) \
		--proxy-mode transparent \
		--chrome \
		-v

proxy-test: $(LABD_BINARY) certs ## Quick test of the MITM proxy
	@echo "Testing MITM proxy..."
	@$(LABD_BINARY) \
		--http-port 18080 \
		--https-port 18443 \
		--proxy-port 18081 \
		--tls-cert $(CERT_FILE) \
		--tls-key $(KEY_FILE) > /tmp/labd_proxy_test.log 2>&1 &
	@LABD_PID=$$!; \
	sleep 2; \
	echo "Testing proxy on port 18081..."; \
	RESULT=$$(curl -s -x localhost:18081 -k https://localhost:18443/capture/json 2>/dev/null); \
	if [ -n "$$RESULT" ]; then \
		echo "$$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'✓ Proxy capture works! ID: {d[\"id\"][:20]}...')" 2>/dev/null || echo "✓ Proxy responded"; \
	else \
		echo "✗ Proxy test failed (no response)"; \
	fi; \
	kill $$LABD_PID 2>/dev/null || true; \
	rm -f /tmp/labd_proxy_test.log

ci: ## Run CI checks: build + lint + test (no frontend)
	@echo "--- Build ---"
	go build ./...
	@echo ""
	@echo "--- Lint ---"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout 5m ./...; \
	else \
		echo "Warning: golangci-lint not found, skipping"; \
	fi
	@echo ""
	@echo "--- Tests ---"
	go test -count=1 -timeout 180s ./...
	@echo ""
	@echo "--- Race Detector ---"
	go test -race -count=1 -timeout 180s -short ./...
	@echo ""
	@echo "CI checks passed"

test: ## Run full validation: lint + build + tests (Go + Frontend)
	@echo "=========================================="
	@echo "  Running full validation suite"
	@echo "=========================================="
	@echo ""
	@echo "--- Go Build ---"
	go build ./...
	@echo ""
	@echo "--- Go Lint (non-blocking) ---"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./... || echo "⚠ Go lint issues found (non-blocking)"; \
	else \
		echo "Warning: golangci-lint not found, skipping"; \
	fi
	@echo ""
	@echo "--- Go Tests (short) ---"
	go test -short -count=1 -timeout 120s ./...
	@echo ""
	@echo "--- Go Tests with Race Detector ---"
	go test -race -count=1 -timeout 120s ./...
	@echo ""
	@echo "--- Frontend ESLint ---"
	@cd lab-ui && npx eslint src/ --max-warnings 50
	@echo ""
	@echo "--- TypeScript Typecheck ---"
	@cd lab-ui && npx tsc --noEmit
	@echo ""
	@echo "--- Frontend Tests ---"
	@cd lab-ui && npm test -- --run
	@echo ""
	@echo "=========================================="
	@echo "  All checks passed!"
	@echo "=========================================="

test-go-race: ## Run Go tests with race detector
	@echo "Running Go tests with race detector..."
	go test -race -count=1 -timeout 120s ./...

test-go-cover: ## Run Go tests with coverage
	@echo "Running Go tests with coverage..."
	go test -cover -count=1 -timeout 120s ./...

test-go: ## Run Go tests only
	@echo "Running Go tests..."
	go test -v ./...

test-frontend: ## Run frontend tests only
	@cd lab-ui && npm test -- --run

# golangci-lint configuration
GOLANGCI_LINT_VERSION := v2.10.1
GOLANGCI_LINT := $(shell which golangci-lint 2>/dev/null || echo ./bin/golangci-lint)

.PHONY: lint lint-fix lint-ci fmt imports vet install-lint

lint: ## Run all linters (Go + Frontend)
	@echo "=========================================="
	@echo "  Running Go Linters"
	@echo "=========================================="
	@echo ""
	@if [ ! -f "$(GOLANGCI_LINT)" ] && ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not found. Installing..."; \
		$(MAKE) install-lint; \
	fi
	@echo "Running golangci-lint..."
	$(GOLANGCI_LINT) run ./...
	@echo ""
	@echo "=========================================="
	@echo "  Running Frontend Linters"
	@echo "=========================================="
	@echo ""
	@cd lab-ui && npx eslint src/ --max-warnings 50
	@cd lab-ui && npx tsc --noEmit

lint-fix: ## Run linters and fix issues where possible
	@echo "Running golangci-lint with auto-fix..."
	@if [ ! -f "$(GOLANGCI_LINT)" ] && ! command -v golangci-lint >/dev/null 2>&1; then \
		$(MAKE) install-lint; \
	fi
	$(GOLANGCI_LINT) run --fix ./...
	@echo "Formatting Go code..."
	$(GOLANGCI_LINT) fmt ./...

lint-ci: ## Run linters for CI (stricter, no fixes)
	@echo "=========================================="
	@echo "  CI Lint Checks"
	@echo "=========================================="
	@if [ ! -f "$(GOLANGCI_LINT)" ] && ! command -v golangci-lint >/dev/null 2>&1; then \
		$(MAKE) install-lint; \
	fi
	$(GOLANGCI_LINT) run --timeout=10m ./...

install-lint: ## Install golangci-lint to ./bin/
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@./scripts/install-golangci-lint.sh $(GOLANGCI_LINT_VERSION)

fmt: ## Format Go source code
	@echo "Formatting Go code..."
	@if [ -f "$(GOLANGCI_LINT)" ] || command -v golangci-lint >/dev/null 2>&1; then \
		$(GOLANGCI_LINT) fmt ./...; \
	else \
		go fmt ./...; \
	fi

imports: ## Fix Go imports
	@echo "Fixing Go imports..."
	@if [ -f "$(GOLANGCI_LINT)" ] || command -v golangci-lint >/dev/null 2>&1; then \
		$(GOLANGCI_LINT) run --fix --disable-all --enable=gci,goimports ./...; \
	else \
		echo "golangci-lint not found. Run 'make install-lint' first."; \
		exit 1; \
	fi

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

typecheck: ## Run TypeScript type checking
	@cd lab-ui && npx tsc --noEmit

install-hooks: ## Install git pre-commit hooks
	@echo "Installing git hooks..."
	@./scripts/install-hooks.sh

test-lab: $(LABD_BINARY) certs ## Test lab server endpoints
	@echo "Testing lab server..."
	@# Kill any existing on test ports
	@for PORT in 18080 18443; do \
		PIDS=$$(lsof -ti:$$PORT 2>/dev/null); \
		if [ -n "$$PIDS" ]; then kill -9 $$PIDS 2>/dev/null; fi; \
	done
	@$(LABD_BINARY) --http-port 18080 --https-port 18443 \
		--tls-cert $(CERT_FILE) --tls-key $(KEY_FILE) > /tmp/labd_test.log 2>&1 &
	@LABD_PID=$$!; \
	sleep 2; \
	echo "Testing /health endpoint..."; \
	curl -s http://localhost:18080/health | jq . || echo "Health check failed"; \
	echo "Testing /capture endpoint..."; \
	curl -s http://localhost:18080/capture | head -20 || echo "Capture endpoint failed"; \
	kill $$LABD_PID 2>/dev/null || true; \
	rm -f /tmp/labd_test.log

capture-chrome: $(BRWSLAB_BINARY) ## Capture Chrome fingerprint using Chromium engine
	@echo "Capturing Chrome fingerprint..."
	$(BRWSLAB_BINARY) fetch http://localhost:$(HTTP_PORT)/capture/json \
		--engine chromium \
		2>/dev/null | jq . > fingerprints/chrome_capture.json || \
		curl -s http://localhost:$(HTTP_PORT)/capture/json | jq . > fingerprints/native_capture.json
	@echo "✓ Fingerprint saved to fingerprints/"

capture-firefox: $(BRWSLAB_BINARY) ## Capture Firefox fingerprint using Firefox engine
	@echo "Capturing Firefox fingerprint..."
	$(BRWSLAB_BINARY) fetch http://localhost:$(HTTP_PORT)/capture/json \
		--engine firefox \
		2>/dev/null | jq . > fingerprints/firefox_capture.json || \
		echo "Firefox capture requires Firefox engine"

diff-fingerprints: $(BRWSLAB_BINARY) ## Compare fingerprints between engines
	@echo "Comparing fingerprints..."
	$(BRWSLAB_BINARY) diff --lab http://localhost:$(HTTP_PORT) \
		--engine native --engine chromium

install: build ## Install binaries to /usr/local/bin
	@echo "Installing binaries to /usr/local/bin..."
	cp $(LABD_BINARY) /usr/local/bin/
	cp $(BRWSLAB_BINARY) /usr/local/bin/
	@echo "✓ Installed labd and brwslab"

clean: kill-ports ## Remove build artifacts, certificates, and kill processes
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)
	rm -f $(CERT_FILE) $(KEY_FILE)
	rm -f labd.log
	rm -f $(PID_FILE)
	@echo "✓ Cleaned"

fmt: ## Format Go source code
	@echo "Formatting Go code..."
	go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod verify

# Docker targets
docker-build: ## Build Docker image for labd
	docker build -t brwslab/labd:latest -f Dockerfile.labd .

docker-run: ## Run labd in Docker
	docker run -p $(HTTP_PORT):8080 -p $(HTTPS_PORT):8443 brwslab/labd:latest

# Development helpers
dev-setup: kill-ports deps certs ## Setup development environment
	@mkdir -p fingerprints signatures captures
	@echo "✓ Development environment ready"
	@echo ""
	@echo "Next steps:"
	@echo "  make run-proxy      # Start with MITM proxy"
	@echo "  make run-chrome     # Start with proxy + auto-launch Chrome"
	@echo "  make run-lab-https  # Start basic HTTPS server"
	@echo "  make proxy-test     # Quick proxy test"
	@echo "  make stop-lab       # Stop everything"

watch: ## Run lab with auto-reload (requires entr)
	@echo "Watching for changes..."
	find . -name '*.go' | entr -r make run-lab-https

# Benchmark targets
BENCH_TIME := 1s
BENCH_PKG := ./brws/benchmark/

bench: ## Run all benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem -benchtime=$(BENCH_TIME) $(BENCH_PKG)

bench-quick: ## Run quick benchmarks (short mode)
	@echo "Running quick benchmarks..."
	go test -bench=. -benchmem -short $(BENCH_PKG)

bench-cpu: ## Run benchmarks with CPU profiling
	@echo "Running benchmarks with CPU profiling..."
	go test -bench=. -benchmem -benchtime=$(BENCH_TIME) -cpuprofile=cpu.prof $(BENCH_PKG)
	@echo "CPU profile saved to cpu.prof"
	@echo "View with: go tool pprof cpu.prof"

bench-mem: ## Run benchmarks with memory profiling
	@echo "Running benchmarks with memory profiling..."
	go test -bench=. -benchmem -benchtime=$(BENCH_TIME) -memprofile=mem.prof $(BENCH_PKG)
	@echo "Memory profile saved to mem.prof"
	@echo "View with: go tool pprof mem.prof"

bench-compare: ## Run benchmarks and compare with baseline (requires benchcmp)
	@echo "Running benchmarks for comparison..."
	@if [ ! -f benchmark.baseline ]; then \
		echo "No baseline found. Creating baseline..."; \
		go test -bench=. -benchmem -benchtime=$(BENCH_TIME) $(BENCH_PKG) > benchmark.baseline; \
	fi
	go test -bench=. -benchmem -benchtime=$(BENCH_TIME) $(BENCH_PKG) > benchmark.current
	@if command -v benchcmp >/dev/null 2>&1; then \
		benchcmp benchmark.baseline benchmark.current; \
	else \
		echo "benchcmp not installed. Results saved to benchmark.current"; \
		echo "Install with: go get golang.org/x/tools/cmd/benchcmp"; \
	fi

bench-visual: ## Generate visual benchmark report (requires benchviz)
	@echo "Generating visual benchmark report..."
	go test -bench=. -benchmem -benchtime=$(BENCH_TIME) $(BENCH_PKG) > benchmark.txt
	@if command -v benchviz >/dev/null 2>&1; then \
		benchviz benchmark.txt > benchmark.html; \
		echo "Report saved to benchmark.html"; \
	else \
		echo "benchviz not installed. Raw results in benchmark.txt"; \
		echo "Install with: go get github.com/ajstarks/svgo/benchviz"; \
	fi

.DEFAULT_GOAL := help
