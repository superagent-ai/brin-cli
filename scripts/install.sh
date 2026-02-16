#!/bin/sh
set -e

# brin installer
# Usage: curl -fsSL https://brin.sh/install.sh | sh

REPO="superagent-ai/brin"
BINARY="brin"
INSTALL_DIR="${BRIN_INSTALL_DIR:-$HOME/.local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

info() { printf "${GREEN}info${NC}: %s\n" "$1"; }
warn() { printf "${YELLOW}warn${NC}: %s\n" "$1"; }
error() { printf "${RED}error${NC}: %s\n" "$1" >&2; exit 1; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       error "Unsupported OS: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64" ;;
        arm64|aarch64)  echo "aarch64" ;;
        *)              error "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Get latest version from GitHub
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | 
        grep '"tag_name"' | 
        sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    info "Installing brin..."

    OS=$(detect_os)
    ARCH=$(detect_arch)
    VERSION="${BRIN_VERSION:-$(get_latest_version)}"

    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Set BRIN_VERSION manually."
    fi

    info "Detected: $OS-$ARCH"
    info "Version: $VERSION"

    # Download URL
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/brin-$OS-$ARCH.tar.gz"
    
    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    info "Downloading from $DOWNLOAD_URL..."
    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/brin.tar.gz"; then
        error "Failed to download. Check if version $VERSION exists for $OS-$ARCH."
    fi

    # Extract
    info "Extracting..."
    tar -xzf "$TMP_DIR/brin.tar.gz" -C "$TMP_DIR"

    # Install
    mkdir -p "$INSTALL_DIR"
    mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
    chmod +x "$INSTALL_DIR/$BINARY"

    info "Installed to $INSTALL_DIR/$BINARY"

    # Check if in PATH
    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        warn "$INSTALL_DIR is not in your PATH"
        echo ""
        echo "Add it to your shell profile:"
        echo ""
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        echo ""
    fi

    info "Done! Run 'brin --help' to get started."
    echo ""
    echo "To uninstall later, run: brin uninstall"
}

main
