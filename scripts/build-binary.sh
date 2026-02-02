#!/bin/bash
# =============================================================================
# Build standalone binary using Bun
# =============================================================================
# Usage: ./scripts/build-binary.sh [target]
# Targets: linux-x64, linux-arm64, macos-x64, macos-arm64, win-x64
# Default: current platform
#
# Output: dist/etc-collector-<target>.zip containing:
#   - etc-collector (or .exe on Windows)
#   - better_sqlite3.node (native SQLite module)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"

# Detect current platform
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        linux*) os="linux" ;;
        darwin*) os="macos" ;;
        mingw*|msys*|cygwin*) os="win" ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="x64" ;;
        arm64|aarch64) arch="arm64" ;;
    esac

    echo "${os}-${arch}"
}

TARGET="${1:-$(detect_platform)}"
BUILD_DIR="$DIST_DIR/etc-collector-${TARGET}"
BINARY_NAME="etc-collector"

# Add .exe for Windows
if [[ "$TARGET" == win-* ]]; then
    BINARY_NAME="etc-collector.exe"
fi

echo -e "${GREEN}=== Building etc-collector for ${TARGET} ===${NC}"
echo ""

# Step 1: Check prerequisites
echo -e "${YELLOW}[1/5] Checking prerequisites...${NC}"

if ! command -v bun &> /dev/null; then
    echo -e "${RED}Error: Bun is required. Install with: curl -fsSL https://bun.sh/install | bash${NC}"
    exit 1
fi

echo -e "${GREEN}Bun $(bun --version) found${NC}"

# Step 2: Build TypeScript
echo -e "${YELLOW}[2/5] Building TypeScript...${NC}"
cd "$PROJECT_DIR"
npm run build

# Step 3: Compile with Bun
echo -e "${YELLOW}[3/5] Compiling binary with Bun...${NC}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Map target to Bun target format
case "$TARGET" in
    linux-x64) BUN_TARGET="bun-linux-x64" ;;
    linux-arm64) BUN_TARGET="bun-linux-arm64" ;;
    macos-x64) BUN_TARGET="bun-darwin-x64" ;;
    macos-arm64) BUN_TARGET="bun-darwin-arm64" ;;
    win-x64) BUN_TARGET="bun-windows-x64" ;;
    *)
        echo -e "${RED}Unknown target: $TARGET${NC}"
        exit 1
        ;;
esac

bun build dist/server.js \
    --compile \
    --target="$BUN_TARGET" \
    --outfile "$BUILD_DIR/$BINARY_NAME"

echo -e "${GREEN}Binary compiled successfully${NC}"

# Step 4: Copy native modules
echo -e "${YELLOW}[4/5] Including native modules...${NC}"

# Find and copy better-sqlite3 native module for the target platform
SQLITE_NODE=""
case "$TARGET" in
    macos-arm64)
        SQLITE_NODE="node_modules/better-sqlite3/build/Release/better_sqlite3.node"
        ;;
    macos-x64|linux-x64|linux-arm64|win-x64)
        # For cross-compilation, we need the target platform's native module
        # These would need to be pre-built or downloaded
        echo -e "${YELLOW}Note: Cross-compilation requires pre-built native modules for $TARGET${NC}"
        echo -e "${YELLOW}For CI, native modules are built on each platform runner${NC}"
        ;;
esac

if [ -n "$SQLITE_NODE" ] && [ -f "$SQLITE_NODE" ]; then
    cp "$SQLITE_NODE" "$BUILD_DIR/"
    echo -e "${GREEN}Copied better_sqlite3.node${NC}"
fi

# Step 5: Create ZIP
echo -e "${YELLOW}[5/5] Creating distribution package...${NC}"

cd "$DIST_DIR"
ZIP_NAME="etc-collector-${TARGET}.zip"
rm -f "$ZIP_NAME"
zip -r "$ZIP_NAME" "etc-collector-${TARGET}/"

# Cleanup directory, keep only ZIP
rm -rf "etc-collector-${TARGET}"

# Show result
echo ""
echo -e "${GREEN}=== Build complete ===${NC}"
ls -lh "$DIST_DIR/$ZIP_NAME"
echo ""
echo -e "Distribution package: ${YELLOW}$DIST_DIR/$ZIP_NAME${NC}"
echo ""
echo -e "To use:"
echo -e "  1. Unzip: ${YELLOW}unzip $ZIP_NAME${NC}"
echo -e "  2. Run:   ${YELLOW}./etc-collector-${TARGET}/${BINARY_NAME}${NC}"
