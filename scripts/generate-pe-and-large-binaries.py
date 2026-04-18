#!/usr/bin/env python3
"""
Generate Windows PE binaries for testing.

Creates minimal PE binaries and compiled PE binaries for analysis testing.
"""

import struct
import os
from pathlib import Path
from typing import Tuple
import subprocess
import shutil
import json


class PEBinaryGenerator:
    """Generate Windows PE binaries for testing."""

    # PE file signatures and constants
    DOS_SIGNATURE = b"MZ"
    PE_SIGNATURE = b"PE\0\0"
    DOS_STUB_SIZE = 64

    # Machine types
    MACHINE_I386 = 0x014c    # x86
    MACHINE_AMD64 = 0x8664   # x64
    MACHINE_ARM = 0x01c0     # ARM
    MACHINE_ARM64 = 0xaa64   # ARM64

    # Characteristics
    EXECUTABLE_IMAGE = 0x0002
    FILE_32BIT_MACHINE = 0x0100
    FILE_64BIT_MACHINE = 0x0020

    # Subsystems
    WINDOWS_GUI = 2
    WINDOWS_CUI = 3

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("tests/fixtures/workspace/binaries/pe")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def create_minimal_pe_x86(self) -> bytes:
        """Create minimal x86 PE binary."""
        # DOS Header
        dos_header = bytearray(64)
        dos_header[0:2] = self.DOS_SIGNATURE
        dos_header[0x3c:0x40] = struct.pack("<I", 64)  # PE header offset

        # PE Header
        pe_header = self.PE_SIGNATURE
        # COFF Header
        pe_header += struct.pack("<H", self.MACHINE_I386)       # Machine
        pe_header += struct.pack("<H", 0)                        # Number of sections
        pe_header += struct.pack("<I", 0)                        # TimeDateStamp
        pe_header += struct.pack("<I", 0)                        # PointerToSymbolTable
        pe_header += struct.pack("<I", 0)                        # NumberOfSymbols
        pe_header += struct.pack("<H", 224)                      # SizeOfOptionalHeader
        pe_header += struct.pack("<H", 
                                self.EXECUTABLE_IMAGE | 
                                self.FILE_32BIT_MACHINE)        # Characteristics

        # Optional Header (32-bit)
        opt_header = struct.pack("<H", 0x010b)                   # Magic (32-bit)
        opt_header += struct.pack("<B", 14)                      # MajorLinkerVersion
        opt_header += struct.pack("<B", 0)                       # MinorLinkerVersion
        opt_header += struct.pack("<I", 0x1000)                  # SizeOfCode
        opt_header += struct.pack("<I", 0)                       # SizeOfInitializedData
        opt_header += struct.pack("<I", 0)                       # SizeOfUninitializedData
        opt_header += struct.pack("<I", 0x1000)                  # AddressOfEntryPoint
        opt_header += struct.pack("<I", 0x1000)                  # BaseOfCode
        opt_header += struct.pack("<I", 0x2000)                  # BaseOfData

        # Windows-specific fields
        opt_header += struct.pack("<I", 0x400000)                # ImageBase
        opt_header += struct.pack("<I", 0x1000)                  # SectionAlignment
        opt_header += struct.pack("<I", 0x200)                   # FileAlignment
        opt_header += struct.pack("<H", 6)                       # MajorOperatingSystemVersion
        opt_header += struct.pack("<H", 0)                       # MinorOperatingSystemVersion
        opt_header += struct.pack("<H", 0)                       # MajorImageVersion
        opt_header += struct.pack("<H", 0)                       # MinorImageVersion
        opt_header += struct.pack("<H", 6)                       # MajorSubsystemVersion
        opt_header += struct.pack("<H", 0)                       # MinorSubsystemVersion
        opt_header += struct.pack("<I", 0)                       # Win32VersionValue
        opt_header += struct.pack("<I", 0x2000)                  # SizeOfImage
        opt_header += struct.pack("<I", 0x200)                   # SizeOfHeaders
        opt_header += struct.pack("<I", 0)                       # CheckSum
        opt_header += struct.pack("<H", self.WINDOWS_CUI)        # Subsystem
        opt_header += struct.pack("<H", 0)                       # DllCharacteristics

        return bytes(dos_header) + bytes(pe_header) + bytes(opt_header)

    def create_minimal_pe_x64(self) -> bytes:
        """Create minimal x64 PE binary."""
        # DOS Header
        dos_header = bytearray(64)
        dos_header[0:2] = self.DOS_SIGNATURE
        dos_header[0x3c:0x40] = struct.pack("<I", 64)

        # PE Header
        pe_header = self.PE_SIGNATURE
        # COFF Header
        pe_header += struct.pack("<H", self.MACHINE_AMD64)       # Machine
        pe_header += struct.pack("<H", 0)                        # Number of sections
        pe_header += struct.pack("<I", 0)                        # TimeDateStamp
        pe_header += struct.pack("<I", 0)                        # PointerToSymbolTable
        pe_header += struct.pack("<I", 0)                        # NumberOfSymbols
        pe_header += struct.pack("<H", 240)                      # SizeOfOptionalHeader
        pe_header += struct.pack("<H", 
                                self.EXECUTABLE_IMAGE | 
                                self.FILE_64BIT_MACHINE)        # Characteristics

        # Optional Header (64-bit)
        opt_header = struct.pack("<H", 0x020b)                   # Magic (64-bit)
        opt_header += struct.pack("<B", 14)                      # MajorLinkerVersion
        opt_header += struct.pack("<B", 0)                       # MinorLinkerVersion
        opt_header += struct.pack("<I", 0x1000)                  # SizeOfCode
        opt_header += struct.pack("<I", 0)                       # SizeOfInitializedData
        opt_header += struct.pack("<I", 0)                       # SizeOfUninitializedData
        opt_header += struct.pack("<I", 0x1000)                  # AddressOfEntryPoint
        opt_header += struct.pack("<I", 0x1000)                  # BaseOfCode

        # Windows-specific fields (64-bit)
        opt_header += struct.pack("<Q", 0x140000000)             # ImageBase
        opt_header += struct.pack("<I", 0x1000)                  # SectionAlignment
        opt_header += struct.pack("<I", 0x200)                   # FileAlignment
        opt_header += struct.pack("<H", 6)                       # MajorOperatingSystemVersion
        opt_header += struct.pack("<H", 0)                       # MinorOperatingSystemVersion
        opt_header += struct.pack("<H", 0)                       # MajorImageVersion
        opt_header += struct.pack("<H", 0)                       # MinorImageVersion
        opt_header += struct.pack("<H", 6)                       # MajorSubsystemVersion
        opt_header += struct.pack("<H", 0)                       # MinorSubsystemVersion
        opt_header += struct.pack("<I", 0)                       # Win32VersionValue
        opt_header += struct.pack("<I", 0x2000)                  # SizeOfImage
        opt_header += struct.pack("<I", 0x200)                   # SizeOfHeaders
        opt_header += struct.pack("<I", 0)                       # CheckSum
        opt_header += struct.pack("<H", self.WINDOWS_CUI)        # Subsystem
        opt_header += struct.pack("<H", 0)                       # DllCharacteristics

        return bytes(dos_header) + bytes(pe_header) + bytes(opt_header)

    def save_binary(self, name: str, data: bytes) -> Path:
        """Save binary to file."""
        path = self.output_dir / name
        path.write_bytes(data)
        return path

    def generate_all_pe_binaries(self) -> dict:
        """Generate all PE binary types."""
        results = {}

        # Minimal x86 PE
        pe_x86 = self.create_minimal_pe_x86()
        path_x86 = self.save_binary("minimal_x86.exe", pe_x86)
        results["minimal_x86.exe"] = {
            "size": len(pe_x86),
            "arch": "x86",
            "path": str(path_x86),
        }
        print(f"✓ Created {path_x86.name} ({len(pe_x86)} bytes)")

        # Minimal x64 PE
        pe_x64 = self.create_minimal_pe_x64()
        path_x64 = self.save_binary("minimal_x64.exe", pe_x64)
        results["minimal_x64.exe"] = {
            "size": len(pe_x64),
            "arch": "x64",
            "path": str(path_x64),
        }
        print(f"✓ Created {path_x64.name} ({len(pe_x64)} bytes)")

        # Try to compile with Visual Studio or LLVM on Windows
        self._try_compile_pe_binaries(results)

        # Save metadata
        metadata_path = self.output_dir / "PE_BINARIES_INFO.json"
        with open(metadata_path, "w") as f:
            json.dump(results, f, indent=2)

        return results

    def _try_compile_pe_binaries(self, results: dict):
        """Try to compile PE binaries using available compilers."""
        # Create test C file
        c_file = self.output_dir / "hello.c"
        c_file.write_text("""
#include <windows.h>

int main() {
    MessageBoxA(NULL, "Hello PE", "Test", MB_OK);
    return 0;
}
""")

        # Try Visual Studio (Windows only)
        if shutil.which("cl.exe"):
            try:
                subprocess.run(
                    ["cl.exe", "/Fe:test_gui.exe", str(c_file)],
                    cwd=self.output_dir,
                    capture_output=True,
                    timeout=30,
                    check=False
                )
                exe_path = self.output_dir / "test_gui.exe"
                if exe_path.exists():
                    results["test_gui.exe"] = {
                        "size": exe_path.stat().st_size,
                        "arch": "x86/x64",
                        "path": str(exe_path),
                        "compiler": "MSVC",
                    }
                    print(f"✓ Compiled {exe_path.name}")
            except Exception as e:
                print(f"⚠ MSVC compilation failed: {e}")

        # Try MinGW (if available on cross-platform setup)
        if shutil.which("i686-w64-mingw32-gcc"):
            try:
                subprocess.run(
                    [
                        "i686-w64-mingw32-gcc",
                        "-o", str(self.output_dir / "mingw_x86.exe"),
                        str(c_file),
                    ],
                    capture_output=True,
                    timeout=30,
                    check=False
                )
                exe_path = self.output_dir / "mingw_x86.exe"
                if exe_path.exists():
                    results["mingw_x86.exe"] = {
                        "size": exe_path.stat().st_size,
                        "arch": "x86",
                        "path": str(exe_path),
                        "compiler": "MinGW",
                    }
                    print(f"✓ Compiled {exe_path.name}")
            except Exception as e:
                print(f"⚠ MinGW compilation failed: {e}")


class LargeBinaryGenerator:
    """Generate large binaries for testing."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("tests/fixtures/workspace/binaries/large")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def create_large_binary(self, size_mb: int, name: str = None) -> Path:
        """Create a large binary of specified size."""
        if name is None:
            name = f"large_{size_mb}mb.bin"

        path = self.output_dir / name

        # Create binary with pattern
        chunk_size = 1024 * 1024  # 1MB chunks
        bytes_written = 0
        target_bytes = size_mb * 1024 * 1024

        with open(path, "wb") as f:
            while bytes_written < target_bytes:
                chunk = bytes([i % 256 for i in range(chunk_size)])
                f.write(chunk)
                bytes_written += len(chunk)

        return path

    def create_compiled_large_binary(self, size_mb: int, name: str = None) -> Path:
        """Create a compiled binary with specified code size."""
        if name is None:
            name = f"compiled_large_{size_mb}mb"

        c_file = self.output_dir / f"{name}.c"

        # Generate C code that will result in large binary
        code = "#include <stdio.h>\n\n"

        # Add many functions to increase code size
        num_functions = min(size_mb * 100, 10000)  # Limit to reasonable number
        for i in range(num_functions):
            code += f"""
int func_{i}(int x) {{
    return x * {i} + {i % 256};
}}
"""

        code += """
int main() {
    int sum = 0;
"""

        for i in range(min(1000, num_functions)):
            code += f"    sum += func_{i}({i});\n"

        code += """
    printf("Result: %d\\n", sum);
    return 0;
}
"""

        c_file.write_text(code)

        # Compile
        binary_path = self.output_dir / name
        if shutil.which("gcc"):
            try:
                result = subprocess.run(
                    ["gcc", "-o", str(binary_path), str(c_file)],
                    capture_output=True,
                    timeout=60,
                    check=False
                )
                if binary_path.exists():
                    actual_size = binary_path.stat().st_size / (1024 * 1024)
                    print(f"✓ Created {binary_path.name} ({actual_size:.2f}MB)")
                    return binary_path
            except Exception as e:
                print(f"⚠ Compilation failed: {e}")

        # Fallback: pad existing binary
        if shutil.which("gcc"):
            simple_c = self.output_dir / "simple.c"
            simple_c.write_text("int main() { return 0; }")
            try:
                subprocess.run(
                    ["gcc", "-o", str(binary_path), str(simple_c)],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
            except:
                pass

        return binary_path


def main():
    """Generate test binaries."""
    print("\n" + "=" * 70)
    print("GENERATING WINDOWS PE BINARIES")
    print("=" * 70)

    pe_gen = PEBinaryGenerator()
    pe_results = pe_gen.generate_all_pe_binaries()

    print("\n" + "=" * 70)
    print("GENERATING LARGE BINARIES")
    print("=" * 70)

    large_gen = LargeBinaryGenerator()

    # Generate various sizes
    sizes = [1, 5, 10]  # MB
    for size in sizes:
        try:
            path = large_gen.create_large_binary(size)
            print(f"✓ Created {path.name}")
        except Exception as e:
            print(f"✗ Failed to create {size}MB binary: {e}")

    # Compile large binaries
    for size in [5]:  # Start with 5MB
        try:
            path = large_gen.create_compiled_large_binary(size)
            if path.exists():
                actual_size = path.stat().st_size / (1024 * 1024)
                print(f"✓ Created compiled {actual_size:.2f}MB binary")
        except Exception as e:
            print(f"⚠ Failed to compile {size}MB binary: {e}")

    print("\n" + "=" * 70)
    print("BINARY GENERATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
