#!/bin/bash
#
# Install git hooks for the project
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    echo "Pre-commit hook already exists, backing up to pre-commit.backup"
    cp "$HOOKS_DIR/pre-commit" "$HOOKS_DIR/pre-commit.backup"
fi

cat > "$HOOKS_DIR/pre-commit" << 'HOOK_EOF'
#!/bin/bash
#
# Pre-commit hook for stealth browser project
# Runs build validation and tests for both Go and TypeScript
#

set -e

echo "=========================================="
echo "Running pre-commit checks..."
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

FAILED=0

# Get list of staged files by type
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)
STAGED_TS_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(ts|tsx)$' || true)
STAGED_FRONTEND_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '^lab-ui/' || true)

# ==========================================
# Go checks
# ==========================================
if [ -n "$STAGED_GO_FILES" ]; then
    echo -e "${CYAN}=== Go Checks ===${NC}"
    echo ""

    # Full Go build
    echo "Verifying Go build (all packages)..."
    if ! go build ./... 2>&1; then
        echo -e "${RED}❌ Go build failed${NC}"
        FAILED=1
    else
        echo -e "${GREEN}✓ Go build successful${NC}"
    fi
    echo ""

    # Run golangci-lint if available
    if command -v golangci-lint &> /dev/null; then
        echo "Running golangci-lint..."
        # Extract unique package directories from staged Go files
        STAGED_PACKAGES=$(echo "$STAGED_GO_FILES" | xargs -I{} dirname {} | sort -u | sed 's|$|/...|')
        if [ -n "$STAGED_PACKAGES" ]; then
            if ! echo "$STAGED_PACKAGES" | xargs golangci-lint run 2>&1; then
                echo -e "${YELLOW}⚠ Linting issues found (non-blocking)${NC}"
            else
                echo -e "${GREEN}✓ Linting passed${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}Warning: golangci-lint not found, skipping lint${NC}"
    fi
    echo ""

    # Run tests for packages with staged changes
    echo "Running Go tests for changed packages..."
    STAGED_TEST_PACKAGES=$(echo "$STAGED_GO_FILES" | xargs -I{} dirname {} | sort -u)
    for pkg_dir in $STAGED_TEST_PACKAGES; do
        # Check if package has test files
        if ls "$pkg_dir"/*_test.go 1>/dev/null 2>&1; then
            echo "  Testing ./$pkg_dir/..."
            if ! go test -count=1 -timeout 60s "./$pkg_dir/..." 2>&1; then
                echo -e "${RED}  ❌ Tests failed for ./$pkg_dir/${NC}"
                FAILED=1
            else
                echo -e "${GREEN}  ✓ Tests passed for ./$pkg_dir/${NC}"
            fi
        fi
    done
    echo ""
else
    echo -e "${CYAN}No Go files staged, skipping Go checks${NC}"
    echo ""
fi

# ==========================================
# Frontend / TypeScript checks
# ==========================================
if [ -n "$STAGED_FRONTEND_FILES" ] || [ -n "$STAGED_TS_FILES" ]; then
    echo -e "${CYAN}=== Frontend Checks ===${NC}"
    echo ""

    if [ -d "lab-ui" ] && [ -f "lab-ui/tsconfig.json" ]; then
        # ESLint
        echo "Running ESLint..."
        if ! (cd lab-ui && npx eslint src/ --max-warnings 50 2>&1); then
            echo -e "${RED}❌ ESLint failed${NC}"
            FAILED=1
        else
            echo -e "${GREEN}✓ ESLint passed${NC}"
        fi
        echo ""

        # TypeScript type checking
        echo "Running TypeScript type check..."
        if ! (cd lab-ui && npx tsc --noEmit 2>&1); then
            echo -e "${RED}❌ TypeScript type check failed${NC}"
            echo "Fix the type errors above before committing"
            FAILED=1
        else
            echo -e "${GREEN}✓ TypeScript type check passed${NC}"
        fi
        echo ""

        # Run frontend tests if available
        if [ -f "lab-ui/package.json" ] && grep -q '"test"' lab-ui/package.json; then
            echo "Running frontend tests..."
            if ! (cd lab-ui && npm test -- --run 2>&1); then
                echo -e "${RED}❌ Frontend tests failed${NC}"
                FAILED=1
            else
                echo -e "${GREEN}✓ Frontend tests passed${NC}"
            fi
            echo ""
        fi
    fi
else
    echo -e "${CYAN}No frontend files staged, skipping frontend checks${NC}"
    echo ""
fi

# ==========================================
# Final result
# ==========================================
if [ $FAILED -ne 0 ]; then
    echo "=========================================="
    echo -e "${RED}❌ Pre-commit checks FAILED${NC}"
    echo "Fix the issues above before committing."
    echo "To bypass in emergencies: git commit --no-verify"
    echo "=========================================="
    exit 1
fi

echo "=========================================="
echo -e "${GREEN}✅ All pre-commit checks passed!${NC}"
echo "=========================================="
exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Pre-commit hook installed successfully!"
echo ""
echo "The hook will run the following checks on commit:"
echo "  • Go build verification (all packages)"
echo "  • golangci-lint on staged Go packages"
echo "  • go test on staged Go packages with tests"
echo "  • TypeScript type checking (npx tsc --noEmit)"
echo "  • Frontend tests (if configured)"
echo ""
echo "To bypass the hook in emergencies, use: git commit --no-verify"
