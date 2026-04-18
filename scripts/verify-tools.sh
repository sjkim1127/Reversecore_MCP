#!/bin/bash
# CI/CD Tool Installation and Verification Script
# This script verifies that all analysis tools are properly installed and functional
# Used in GitHub Actions and local development

set -e

echo "=========================================="
echo "Tool Installation Verification"
echo "=========================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track results
TOTAL_TOOLS=0
INSTALLED_TOOLS=0
MISSING_TOOLS=0

# Function to check tool
check_tool() {
    local tool_name=$1
    local version_cmd=$2
    TOTAL_TOOLS=$((TOTAL_TOOLS + 1))
    
    if command -v "$tool_name" &> /dev/null; then
        INSTALLED_TOOLS=$((INSTALLED_TOOLS + 1))
        echo -e "${GREEN}✓${NC} $tool_name installed"
        if [ -n "$version_cmd" ]; then
            eval "$version_cmd" | head -1 | sed 's/^/  /'
        fi
    else
        MISSING_TOOLS=$((MISSING_TOOLS + 1))
        echo -e "${YELLOW}✗${NC} $tool_name not found"
    fi
}

echo ""
echo -e "${BLUE}Core Analysis Tools:${NC}"
check_tool "r2" "r2 -v"
check_tool "yara" "yara --version"
check_tool "file" "file --version | head -1"
check_tool "strings" "strings --version | head -1"
check_tool "binwalk" "binwalk --version"

echo ""
echo -e "${BLUE}Binary Utilities:${NC}"
check_tool "objdump" "objdump --version | head -1"
check_tool "nm" "nm --version | head -1"
check_tool "readelf" "readelf --version | head -1"

echo ""
echo -e "${BLUE}Additional Tools:${NC}"
check_tool "ghidra" "ghidra --version" 2>/dev/null || echo -e "${YELLOW}✗${NC} ghidra not found"

echo ""
echo "=========================================="
echo -e "Summary: ${GREEN}$INSTALLED_TOOLS/$TOTAL_TOOLS${NC} tools installed"
echo "=========================================="

# Test tool functionality
echo ""
echo -e "${BLUE}Running Tool Functionality Tests:${NC}"

# Create test binary
TEST_DIR=$(mktemp -d)
TEST_BINARY="$TEST_DIR/test.bin"
printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00' > "$TEST_BINARY"

# Test file command
if command -v file &> /dev/null; then
    echo -n "Testing file command... "
    if file "$TEST_BINARY" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
fi

# Test strings command
if command -v strings &> /dev/null; then
    echo -n "Testing strings command... "
    if strings "$TEST_BINARY" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
fi

# Test radare2
if command -v r2 &> /dev/null; then
    echo -n "Testing radare2 (r2 -c afl)... "
    if r2 -c "afl" -q "$TEST_BINARY" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠${NC} (may be normal for minimal binary)"
    fi
fi

# Cleanup
rm -rf "$TEST_DIR"

echo ""
echo "=========================================="
echo "Tool Verification Complete"
echo "=========================================="
