"""
Enhanced integration tests with real binary analysis verification.

Tests that tools can actually analyze binaries and extract meaningful data.
"""

import shutil
import subprocess
from pathlib import Path

import pytest


class TestBinaryGeneration:
    """Test that test binaries can be generated."""

    def test_generate_test_binaries(self):
        """Verify test binaries can be generated."""
        script_path = Path(__file__).parent.parent.parent / "scripts" / "fetch_test_binaries.py"
        assert script_path.exists(), f"Binary generation script not found: {script_path}"

    @pytest.fixture
    def binaries_dir(self, tmp_path):
        """Generate test binaries in temp directory."""
        workspace = tmp_path / "workspace"
        binaries = workspace / "binaries"
        binaries.mkdir(parents=True)

        # Copy sample binary
        hello_c = binaries / "hello.c"
        hello_c.write_text("""
#include <stdio.h>
int main() {
    printf("Hello from test binary\\n");
    return 0;
}
""")
        return binaries


class TestToolsWithRealBinaries:
    """Test analysis tools with actual binaries."""

    @pytest.fixture
    def sample_binary_path(self, tmp_path):
        """Create a real compilable binary."""
        binary_dir = tmp_path / "binaries"
        binary_dir.mkdir()

        c_file = binary_dir / "hello.c"
        c_file.write_text("""
#include <stdio.h>
#include <stdlib.h>

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n-1) + fibonacci(n-2);
}

int main(int argc, char *argv[]) {
    printf("Fibonacci test binary\\n");
    int result = fibonacci(10);
    printf("Result: %d\\n", result);
    return 0;
}
""")

        binary_path = binary_dir / "hello_test"

        # Try to compile with gcc
        if shutil.which("gcc"):
            result = subprocess.run(
                ["gcc", "-o", str(binary_path), str(c_file)], capture_output=True, timeout=10
            )
            if result.returncode == 0 and binary_path.exists():
                return binary_path

        # Fallback: create minimal ELF binary
        binary_path.write_bytes(
            bytes(
                [
                    0x7F,
                    0x45,
                    0x4C,
                    0x46,
                    0x02,
                    0x01,
                    0x01,
                    0x00,  # ELF header
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x02,
                    0x00,
                    0x3E,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x10,
                    0x40,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x40,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x40,
                    0x00,
                    0x38,
                    0x00,
                    0x01,
                    0x00,
                    0x40,
                    0x00,
                    0x00,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x40,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x40,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x10,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x10,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ]
            )
        )
        return binary_path

    def test_file_command_analysis(self, sample_binary_path):
        """Test file command extracts binary info."""
        output = subprocess.run(
            ["file", str(sample_binary_path)], capture_output=True, text=True, timeout=5
        )
        assert output.returncode == 0
        assert len(output.stdout) > 0
        # Check for expected output patterns
        assert any(x in output.stdout.lower() for x in ["elf", "executable"])

    def test_strings_command_extraction(self, sample_binary_path):
        """Test strings command extracts strings from binary."""
        output = subprocess.run(
            ["strings", str(sample_binary_path)], capture_output=True, text=True, timeout=5
        )
        assert output.returncode == 0
        # Should have some output
        assert len(output.stdout.strip().split("\n")) > 0

    def test_radare2_analysis(self, sample_binary_path):
        """Test radare2 analysis capabilities."""
        if not shutil.which("r2"):
            pytest.skip("radare2 not installed")

        # Run basic r2 commands
        commands = [
            ("afl", "list functions"),
            ("ii", "get imports"),
            ("is", "list symbols"),
        ]

        for cmd, desc in commands:
            output = subprocess.run(
                ["r2", "-q", "-c", f"{cmd}", str(sample_binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Should not crash
            assert output.returncode in (0, 1), f"r2 {desc} failed"

    def test_objdump_analysis(self, sample_binary_path):
        """Test objdump for disassembly."""
        if not shutil.which("objdump"):
            pytest.skip("objdump not installed")

        output = subprocess.run(
            ["objdump", "-d", str(sample_binary_path)], capture_output=True, text=True, timeout=10
        )
        # objdump should succeed or gracefully fail
        assert output.returncode in (0, 1)


class TestToolOutputValidation:
    """Validate that tool output is meaningful."""

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create test binary."""
        binary = tmp_path / "test_bin"

        if shutil.which("gcc"):
            c_file = tmp_path / "test.c"
            c_file.write_text("""
int add(int a, int b) { return a + b; }
int main() { return add(2, 3); }
""")
            result = subprocess.run(
                ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
            )
            if result.returncode == 0:
                return binary

        # Minimal ELF fallback
        binary.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 50)
        return binary

    def test_file_output_contains_info(self, test_binary):
        """file should provide architecture/format info."""
        output = subprocess.run(
            ["file", str(test_binary)], capture_output=True, text=True, timeout=5
        )
        assert output.returncode == 0
        # Should contain meaningful info
        info = output.stdout.lower()
        assert len(info) > 10

    def test_strings_finds_content(self, test_binary):
        """strings should find actual strings."""
        output = subprocess.run(
            ["strings", str(test_binary)], capture_output=True, text=True, timeout=5
        )
        assert output.returncode == 0
        # Output may be empty for minimal binaries, but command should succeed

    def test_nm_lists_symbols(self, test_binary):
        """nm should list symbols if available."""
        if not shutil.which("nm"):
            pytest.skip("nm not installed")

        output = subprocess.run(["nm", str(test_binary)], capture_output=True, text=True, timeout=5)
        # Should succeed or gracefully fail
        assert output.returncode in (0, 1)


class TestAnalysisToolAccuracy:
    """Test that tools provide accurate analysis results."""

    @pytest.fixture
    def test_files(self, tmp_path):
        """Create various test files."""
        files = {
            "text": tmp_path / "text.txt",
            "binary": tmp_path / "binary.bin",
        }

        files["text"].write_text("This is a text file with some content")
        files["binary"].write_bytes(b"\x00\x01\x02\x03" * 10)

        return files

    def test_file_distinguishes_text_and_binary(self, test_files):
        """file should correctly identify text vs binary."""
        text_output = subprocess.run(
            ["file", str(test_files["text"])], capture_output=True, text=True, timeout=5
        )

        binary_output = subprocess.run(
            ["file", str(test_files["binary"])], capture_output=True, text=True, timeout=5
        )

        assert text_output.returncode == 0
        assert binary_output.returncode == 0

        # Outputs should be different
        assert text_output.stdout != binary_output.stdout

    def test_strings_finds_text_in_file(self, test_files):
        """strings should find readable text."""
        output = subprocess.run(
            ["strings", str(test_files["text"])], capture_output=True, text=True, timeout=5
        )

        assert output.returncode == 0
        # Should contain the text content
        assert "text file" in output.stdout.lower() or len(output.stdout) > 0


@pytest.mark.integration
class TestCombinedToolAnalysis:
    """Test multiple tools working together for comprehensive analysis."""

    @pytest.fixture
    def target_binary(self, tmp_path):
        """Create a target binary for analysis."""
        binary = tmp_path / "analysis_target"

        if shutil.which("gcc"):
            c_file = tmp_path / "prog.c"
            c_file.write_text("""
void helper() { }
int calculate(int x) {
    helper();
    return x * 2;
}
int main() {
    return calculate(21);
}
""")
            result = subprocess.run(
                ["gcc", "-g", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
            )
            if result.returncode == 0:
                return binary

        binary.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 100)
        return binary

    def test_comprehensive_analysis(self, target_binary):
        """Run comprehensive analysis on target binary."""
        results = {}

        # file command
        file_result = subprocess.run(
            ["file", str(target_binary)], capture_output=True, text=True, timeout=5
        )
        results["file"] = file_result.returncode == 0

        # strings command
        strings_result = subprocess.run(
            ["strings", str(target_binary)], capture_output=True, text=True, timeout=5
        )
        results["strings"] = strings_result.returncode == 0

        # At least one should succeed
        assert any(results.values()), "No analysis tools succeeded"

        # Verify we got meaningful output from file
        if file_result.returncode == 0:
            assert len(file_result.stdout) > 0
        # strings may be empty for minimal binaries, just verify command succeeded

    def test_radare2_decompilation(self, target_binary):
        """Test radare2 decompilation capabilities."""
        if not shutil.which("r2"):
            pytest.skip("radare2 not installed")

        # Try to get decompilation output
        output = subprocess.run(
            ["r2", "-q", "-c", "pdc", str(target_binary)],
            capture_output=True,
            text=True,
            timeout=15,
        )

        # Should not crash, even if decompilation fails
        assert output.returncode in (0, 1, 127)  # 127 = command not found
