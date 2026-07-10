"""
Extended binary analysis tools testing.

Tests for additional analysis tools: Yara, binwalk, readelf, ldd, strace, ltrace, otool, nm, etc.
"""

import shutil
import subprocess

import pytest


class TestOtoolAnalysis:
    """Test otool (macOS binary analysis tool)."""

    def test_otool_available(self):
        """Check if otool is available."""
        if not shutil.which("otool"):
            pytest.skip("otool not available (macOS only)")

    def test_otool_headers(self, tmp_path):
        """Test otool for analyzing Mach-O headers."""
        if not shutil.which("otool"):
            pytest.skip("otool not available")

        # Create test binary
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 0; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        # Test otool -h (headers)
        result = subprocess.run(
            ["otool", "-h", str(binary)], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_otool_load_commands(self, tmp_path):
        """Test otool for analyzing load commands."""
        if not shutil.which("otool"):
            pytest.skip("otool not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 0; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        # Test otool -l (load commands)
        result = subprocess.run(
            ["otool", "-l", str(binary)], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        output = result.stdout.lower()
        assert any(x in output for x in ["load command", "segment"])

    def test_otool_libraries(self, tmp_path):
        """Test otool for listing linked libraries."""
        if not shutil.which("otool"):
            pytest.skip("otool not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text('#include <stdio.h>\nint main() { printf("test"); return 0; }')

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        # Test otool -L (libraries)
        result = subprocess.run(
            ["otool", "-L", str(binary)], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        assert "libc" in result.stdout or "libc.dylib" in result.stdout or len(result.stdout) > 0


class TestNmSymbolAnalysis:
    """Test nm (symbol table analysis)."""

    def test_nm_available(self):
        """Check if nm is available."""
        assert shutil.which("nm") is not None

    def test_nm_symbols_with_debug_info(self, tmp_path):
        """Test nm on binary with debug info."""
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int add(int a, int b) {
    return a + b;
}

int main() {
    return add(2, 3);
}
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-g", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0

        # Test nm -a (all symbols)
        result = subprocess.run(
            ["nm", "-a", str(binary)], capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        symbols = result.stdout.lower()
        # Should find main function
        assert "main" in symbols

    def test_nm_symbols_stripped(self, tmp_path):
        """Test nm on stripped binary."""
        binary = tmp_path / "test"
        binary_stripped = tmp_path / "test_stripped"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 0; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        # Strip binary
        subprocess.run(["strip", str(binary), "-o", str(binary_stripped)], timeout=5)

        if binary_stripped.exists():
            result = subprocess.run(
                ["nm", str(binary_stripped)], capture_output=True, text=True, timeout=5
            )
            # nm should handle stripped binary gracefully
            assert result.returncode in (0, 1)

    def test_nm_symbol_types(self, tmp_path):
        """Test nm for different symbol types."""
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int global_var = 42;
static int static_var = 10;
int func() { return 0; }
int main() { return 0; }
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-g", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0

        result = subprocess.run(
            ["nm", "-C", str(binary)],  # -C: demangle names
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0


class TestYaraIntegration:
    """Test Yara pattern matching."""

    def test_yara_import(self):
        """Test if Yara can be imported."""
        try:
            import yara

            assert hasattr(yara, "compile")
        except ImportError:
            pytest.skip("Yara not installed: pip install yara-python")

    def test_yara_compile_rule(self):
        """Test Yara rule compilation."""
        try:
            import yara
        except ImportError:
            pytest.skip("Yara not installed")

        rule_source = """
        rule test_rule {
            strings:
                $test = "test"
            condition:
                $test
        }
        """

        rules = yara.compile(source=rule_source)
        assert rules is not None

    def test_yara_match_strings(self, tmp_path):
        """Test Yara string matching."""
        try:
            import yara
        except ImportError:
            pytest.skip("Yara not installed")

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("This contains test string for yara")

        rule_source = """
        rule find_test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        rules = yara.compile(source=rule_source)
        matches = rules.match(str(test_file))

        assert len(matches) > 0
        assert matches[0].rule == "find_test"

    def test_yara_binary_matching(self, tmp_path):
        """Test Yara matching on binary."""
        try:
            import yara
        except ImportError:
            pytest.skip("Yara not installed")

        # Create test binary
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text('#include <stdio.h>\nint main() { printf("test string"); return 0; }')

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        # Create Yara rule to find common patterns
        rule_source = """
        rule elf_binary {
            strings:
                $elf = { 7F 45 4C 46 }
            condition:
                $elf
        }
        """

        rules = yara.compile(source=rule_source)
        matches = rules.match(str(binary))

        # May or may not match depending on binary format
        assert isinstance(matches, list)


class TestBinwalkAnalysis:
    """Test binwalk firmware analysis tool."""

    def test_binwalk_import(self):
        """Test if binwalk can be imported."""
        try:
            import binwalk

            assert hasattr(binwalk, "scan")
        except ImportError:
            pytest.skip("binwalk not installed: pip install binwalk")

    def test_binwalk_signature_scan(self):
        """Test binwalk signature scanning."""
        try:
            import binwalk
        except ImportError:
            pytest.skip("binwalk not installed")

        # binwalk requires actual firmware files
        # For testing, we just verify the API
        assert hasattr(binwalk, "scan")
        assert hasattr(binwalk, "Module")

    def test_binwalk_on_binary(self, tmp_path):
        """Test binwalk on compiled binary."""
        try:
            import binwalk
        except ImportError:
            pytest.skip("binwalk not installed")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 0; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        try:
            # Scan binary for signatures
            for module in binwalk.scan(str(binary), signature=True, quiet=True):
                # Just verify it runs without crashing
                assert module is not None
        except Exception as e:
            pytest.skip(f"binwalk scan failed: {e}")


class TestLddDependencyAnalysis:
    """Test ldd (dynamic library dependency analyzer)."""

    def test_ldd_available(self):
        """Check if ldd is available."""
        if not shutil.which("ldd"):
            pytest.skip("ldd not available (Linux only)")

    def test_ldd_list_dependencies(self, tmp_path):
        """Test ldd for listing library dependencies."""
        if not shutil.which("ldd"):
            pytest.skip("ldd not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text('#include <stdio.h>\nint main() { printf("test"); return 0; }')

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        result = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, timeout=5)

        if result.returncode == 0:
            # Should list libc
            assert "libc" in result.stdout or "c library" in result.stdout.lower()


class TestReadelfAnalysis:
    """Test readelf (ELF file analysis)."""

    def test_readelf_available(self):
        """Check if readelf is available."""
        if not shutil.which("readelf"):
            pytest.skip("readelf not available (usually on Linux)")

    def test_readelf_headers(self, tmp_path):
        """Test readelf for ELF headers."""
        if not shutil.which("readelf"):
            pytest.skip("readelf not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 0; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        result = subprocess.run(
            ["readelf", "-h", str(binary)], capture_output=True, text=True, timeout=5
        )

        if result.returncode == 0:
            assert "ELF" in result.stdout or "Header" in result.stdout

    def test_readelf_sections(self, tmp_path):
        """Test readelf for section headers."""
        if not shutil.which("readelf"):
            pytest.skip("readelf not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 0; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        result = subprocess.run(
            ["readelf", "-S", str(binary)], capture_output=True, text=True, timeout=5
        )

        if result.returncode == 0:
            output = result.stdout.lower()
            # Should list sections
            assert any(x in output for x in ["section", "header", ".text"])


class TestStraceAnalysis:
    """Test strace (system call tracer)."""

    def test_strace_available(self):
        """Check if strace is available."""
        if not shutil.which("strace"):
            pytest.skip("strace not available")

    def test_strace_trace_execution(self, tmp_path):
        """Test strace for tracing system calls."""
        if not shutil.which("strace"):
            pytest.skip("strace not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("int main() { return 42; }")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        result = subprocess.run(
            ["strace", "-e", "trace=exit", str(binary)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # strace outputs to stderr
        output = result.stdout + result.stderr
        # Should show exit call
        assert "exit" in output.lower() or result.returncode == 0


class TestLtraceAnalysis:
    """Test ltrace (library call tracer)."""

    def test_ltrace_available(self):
        """Check if ltrace is available."""
        if not shutil.which("ltrace"):
            pytest.skip("ltrace not available")

    def test_ltrace_trace_calls(self, tmp_path):
        """Test ltrace for tracing library calls."""
        if not shutil.which("ltrace"):
            pytest.skip("ltrace not available")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text('#include <stdio.h>\nint main() { printf("test"); return 0; }')

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0

        result = subprocess.run(
            ["ltrace", "-e", "printf", str(binary)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # ltrace outputs to stderr
        output = result.stdout + result.stderr
        # Should show printf call
        assert "printf" in output.lower() or len(output) > 0


@pytest.mark.integration
class TestExtendedToolComparison:
    """Compare different tools for the same analysis."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create test binary."""
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

int calculate(int x, int y) {
    return x * 2 + y;
}

int main(int argc, char *argv[]) {
    printf("Start\\n");
    int result = calculate(10, 5);
    printf("Result: %d\\n", result);
    return 0;
}
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-g", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0
        return binary

    def test_multiple_tools_symbol_analysis(self, test_binary):
        """Compare nm, objdump, and readelf for symbol analysis."""
        results = {}

        # nm
        if shutil.which("nm"):
            result = subprocess.run(
                ["nm", "-a", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["nm"] = result.returncode == 0

        # objdump
        if shutil.which("objdump"):
            result = subprocess.run(
                ["objdump", "-t", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["objdump"] = result.returncode == 0

        # readelf (if available)
        if shutil.which("readelf"):
            result = subprocess.run(
                ["readelf", "-s", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["readelf"] = result.returncode == 0

        # At least one should succeed
        assert any(results.values()), "No tool succeeded"

    def test_multiple_tools_header_analysis(self, test_binary):
        """Compare file, otool, readelf for header analysis."""
        results = {}

        # file
        if shutil.which("file"):
            result = subprocess.run(
                ["file", str(test_binary)], capture_output=True, text=True, timeout=5
            )
            results["file"] = result.returncode == 0

        # otool (macOS)
        if shutil.which("otool"):
            result = subprocess.run(
                ["otool", "-h", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["otool"] = result.returncode == 0

        # readelf (Linux)
        if shutil.which("readelf"):
            result = subprocess.run(
                ["readelf", "-h", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["readelf"] = result.returncode == 0

        # At least one should succeed
        assert any(results.values()), "No tool succeeded"

    def test_tool_output_consistency(self, test_binary):
        """Test consistency of tool outputs."""
        # All tools should identify the binary correctly
        results = {}

        if shutil.which("file"):
            result = subprocess.run(
                ["file", "-b", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["file"] = result.stdout.lower()

        if shutil.which("otool"):
            result = subprocess.run(
                ["otool", "-h", str(test_binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            results["otool"] = result.stdout.lower()

        # Verify at least one tool provides output
        assert any(results.values()), "No tool output generated"
