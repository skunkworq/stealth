#!/bin/bash
# Install golangci-lint v2.10+ for CI/CD environments
# Usage: ./scripts/install-golangci-lint.sh [version]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default version (match the one specified in .golangci.yml)
VERSION="${1:-v2.10.1}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${ARCH}" in
    x86_64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    i386|i686)
        ARCH="386"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

case "${OS}" in
    linux|darwin|windows)
        ;;
    *)
        echo "Unsupported OS: ${OS}"
        exit 1
        ;;
esac

INSTALL_DIR="${PROJECT_ROOT}/bin"
mkdir -p "${INSTALL_DIR}"

BINARY_NAME="golangci-lint"
if [ "${OS}" = "windows" ]; then
    BINARY_NAME="${BINARY_NAME}.exe"
fi

INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}"

echo "Installing golangci-lint ${VERSION} for ${OS}/${ARCH}..."

# Check if already installed with correct version
if [ -f "${INSTALL_PATH}" ]; then
    INSTALLED_VERSION=$("${INSTALL_PATH}" --version 2>/dev/null | grep -o 'version [0-9.]*' | cut -d' ' -f2 || echo "")
    TARGET_VERSION=$(echo "${VERSION}" | sed 's/^v//')
    
    if [ "${INSTALLED_VERSION}" = "${TARGET_VERSION}" ]; then
        echo "golangci-lint ${VERSION} is already installed at ${INSTALL_PATH}"
        exit 0
    else
        echo "Updating golangci-lint from ${INSTALLED_VERSION} to ${VERSION}..."
    fi
fi

# Download URL
DOWNLOAD_URL="https://github.com/golangci/golangci-lint/releases/download/${VERSION}/golangci-lint-${VERSION#v}-${OS}-${ARCH}.tar.gz"

echo "Downloading from ${DOWNLOAD_URL}..."

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# Download and extract
curl -sL "${DOWNLOAD_URL}" | tar -xz -C "${TEMP_DIR}" --strip-components=1

# Move binary to install directory
mv "${TEMP_DIR}/golangci-lint" "${INSTALL_PATH}"
chmod +x "${INSTALL_PATH}"

echo "golangci-lint ${VERSION} installed successfully at ${INSTALL_PATH}"
echo ""
echo "To use it, either:"
echo "  1. Add ${INSTALL_DIR} to your PATH"
echo "  2. Run: ./bin/golangci-lint run"
echo "  3. Use make lint (which uses the project-local binary if available)"
