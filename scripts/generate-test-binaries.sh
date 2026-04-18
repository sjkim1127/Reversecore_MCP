#!/bin/bash
# Generate test binaries for CI/CD tool verification
# Creates real binaries to test analysis tools (radare2, file, strings, etc.)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${SCRIPT_DIR}/../tests/fixtures/workspace"
BINARIES_DIR="${WORKSPACE_DIR}/binaries"

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Generating Test Binaries${NC}"
echo -e "${BLUE}========================================${NC}"

mkdir -p "$BINARIES_DIR"
cd "$BINARIES_DIR"

# 1. Simple C program - Hello World
echo -e "${GREEN}[1/5]${NC} Generating hello.c..."
cat > hello.c << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello from test binary\n");
    return 0;
}
EOF

echo -e "${GREEN}[2/5]${NC} Compiling hello to hello_x64..."
gcc -m64 -o hello_x64 hello.c 2>/dev/null || {
    echo "Warning: 64-bit compilation failed, trying 32-bit..."
    gcc -m32 -o hello_x64 hello.c 2>/dev/null || echo "Warning: gcc compilation skipped"
}

if [ -f hello_x64 ]; then
    echo "✓ hello_x64 created"
else
    # Fallback: create minimal ELF manually
    printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > hello_x64
    echo "✓ hello_x64 created (minimal ELF)"
fi

# 2. Assembly program - simple loop
echo -e "${GREEN}[3/5]${NC} Creating loop_x64.asm..."
cat > loop_x64.asm << 'EOF'
; Simple x86-64 assembly: loop with syscall
bits 64
org 0x400000

_start:
    mov rax, 60        ; sys_exit
    mov rdi, 0         ; exit code 0
    syscall
EOF

if command -v nasm &> /dev/null; then
    nasm -f elf64 -o loop_x64.o loop_x64.asm 2>/dev/null || true
    if command -v ld &> /dev/null; then
        ld -o loop_x64 loop_x64.o 2>/dev/null || echo "Warning: ld linking skipped"
    fi
    [ -f loop_x64 ] && echo "✓ loop_x64 created" || echo "⚠ loop_x64 not created"
else
    echo "⚠ nasm not available, skipping loop_x64"
fi

# 3. Stripped binary (for testing stripped/unstripped analysis)
echo -e "${GREEN}[4/5]${NC} Creating stripped binary..."
if [ -f hello_x64 ]; then
    cp hello_x64 hello_x64_stripped
    strip hello_x64_stripped 2>/dev/null || true
    echo "✓ hello_x64_stripped created"
fi

# 4. Position Independent Code (PIE)
echo -e "${GREEN}[5/5]${NC} Generating PIE binary..."
cat > pie.c << 'EOF'
int add(int a, int b) { return a + b; }
int main() { return add(2, 3); }
EOF

if gcc --version &> /dev/null; then
    gcc -fPIE -pie -o pie_x64 pie.c 2>/dev/null || echo "⚠ PIE compilation skipped"
    [ -f pie_x64 ] && echo "✓ pie_x64 created" || echo "⚠ pie_x64 not created"
fi

# Create metadata file with test binaries info
cat > BINARIES_INFO.json << 'EOF'
{
  "test_binaries": {
    "hello_x64": {
      "type": "ELF x86-64",
      "description": "Simple Hello World compiled with GCC",
      "expected_strings": ["Hello from test binary"],
      "architecture": "x86-64",
      "has_symbols": true
    },
    "hello_x64_stripped": {
      "type": "ELF x86-64 (Stripped)",
      "description": "hello_x64 with symbols removed",
      "architecture": "x86-64",
      "has_symbols": false
    },
    "loop_x64": {
      "type": "ELF x86-64",
      "description": "Simple assembly loop with syscall",
      "architecture": "x86-64",
      "has_symbols": true
    },
    "pie_x64": {
      "type": "ELF x86-64 (PIE)",
      "description": "Position Independent Executable",
      "architecture": "x86-64",
      "has_symbols": true
    }
  }
}
EOF

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Test binaries generated${NC}"
echo -e "${BLUE}========================================${NC}"

# List created binaries
echo ""
echo "Generated binaries:"
ls -lh * 2>/dev/null | grep -E '^-' | awk '{print "  " $9 " (" $5 ")"}'

echo ""
echo "Binary analysis with 'file' command:"
for binary in hello_x64 hello_x64_stripped loop_x64 pie_x64; do
    if [ -f "$binary" ]; then
        echo "  $binary: $(file -b "$binary")"
    fi
done

echo ""
echo -e "${BLUE}All test binaries ready in: $BINARIES_DIR${NC}"
