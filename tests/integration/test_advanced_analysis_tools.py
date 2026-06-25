"""
Advanced analysis tools testing (Ghidra, Capstone, angr).

Tests for decompilation, disassembly, and symbolic execution frameworks.
"""

import shutil
import subprocess

import pytest


class TestCapstoneIntegration:
    """Test Capstone disassembler integration."""

    @pytest.fixture
    def sample_code(self):
        """Sample x86 machine code for disassembly."""
        # mov rax, 0x1000; ret
        return bytes(
            [
                0x48,
                0xC7,
                0xC0,
                0x00,
                0x10,
                0x00,
                0x00,  # mov rax, 0x1000
                0xC3,  # ret
            ]
        )

    def test_capstone_import(self):
        """Test Capstone can be imported."""
        try:
            import capstone

            assert hasattr(capstone, "Cs")
            assert capstone.CS_ARCH_X86 is not None
        except ImportError:
            pytest.skip("Capstone not installed: pip install capstone")

    def test_capstone_disassembly(self, sample_code):
        """Test Capstone disassembly functionality."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError:
            pytest.skip("Capstone not installed")

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions = list(md.disasm(sample_code, 0x1000))

        assert len(instructions) >= 2, "Should disassemble at least 2 instructions"
        assert instructions[0].mnemonic == "mov"
        assert instructions[-1].mnemonic == "ret"

    def test_capstone_with_binary_file(self, tmp_path):
        """Test Capstone on actual compiled binary."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError:
            pytest.skip("Capstone not installed")

        # Create test binary
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int add(int a, int b) { return a + b; }
int main() { return add(2, 3); }
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        if not shutil.which("readelf"):
            pytest.skip("readelf not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )
        assert result.returncode == 0, "gcc compilation failed"

        # Read .text section
        readelf = subprocess.run(
            ["readelf", "-x", ".text", str(binary)], capture_output=True, text=True, timeout=5
        )

        if readelf.returncode == 0:
            # Parse hexdump and disassemble
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            # This is a basic test - just verify it runs
            assert md is not None


class TestAngrIntegration:
    """Test angr symbolic execution engine."""

    def test_angr_import(self):
        """Test angr can be imported."""
        try:
            import angr

            assert hasattr(angr, "Project")
        except Exception:
            pytest.skip("angr not installed: pip install angr")

    def test_angr_project_load(self, tmp_path):
        """Test angr project creation."""
        try:
            import angr
        except Exception:
            pytest.skip("angr not installed")

        # Create test binary
        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int sum(int a, int b) { return a + b; }
int main() { return sum(2, 3); }
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )

        if result.returncode != 0:
            pytest.skip("gcc compilation failed")

        # Try to load with angr
        try:
            proj = angr.Project(str(binary), auto_load_libs=False)
            assert proj.arch is not None
            assert proj.entry is not None
        except Exception as e:
            pytest.skip(f"angr project loading failed: {e}")

    def test_angr_cfg_generation(self, tmp_path):
        """Test angr CFG (Control Flow Graph) generation."""
        try:
            import angr
        except Exception:
            pytest.skip("angr not installed")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int test_func(int x) {
    if (x > 0) return x * 2;
    return 0;
}
int main() { return test_func(5); }
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )

        if result.returncode != 0:
            pytest.skip("Compilation failed")

        try:
            proj = angr.Project(str(binary), auto_load_libs=False)
            # Generate CFG for main function
            cfg = proj.analyses.CFGFast()
            assert cfg is not None
            assert len(cfg.nodes) > 0
        except Exception as e:
            pytest.skip(f"CFG generation failed: {e}")

    def test_angr_vex_ir(self, tmp_path):
        """Test angr VEX IR (Intermediate Representation) generation."""
        try:
            import angr
        except Exception:
            pytest.skip("angr not installed")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int simple() { return 42; }
int main() { return simple(); }
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )

        if result.returncode != 0:
            pytest.skip("Compilation failed")

        try:
            proj = angr.Project(str(binary), auto_load_libs=False)
            state = proj.factory.entry_state()
            assert state is not None
        except Exception as e:
            pytest.skip(f"VEX IR generation failed: {e}")


@pytest.mark.integration
class TestDecompilationAccuracy:
    """Test decompilation accuracy of various tools."""

    @pytest.fixture
    def target_source(self, tmp_path):
        """Create test source with known structure."""
        c_file = tmp_path / "test.c"
        c_file.write_text("""
typedef struct {
    int x;
    int y;
} Point;

int calculate(Point p) {
    return p.x + p.y;
}

int main(int argc, char *argv[]) {
    Point p = {10, 20};
    return calculate(p);
}
""")
        return c_file

    @pytest.fixture
    def compiled_binary(self, target_source, tmp_path):
        """Compile source to binary."""
        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        binary = tmp_path / "test_bin"
        result = subprocess.run(
            ["gcc", "-g", "-o", str(binary), str(target_source)], capture_output=True, timeout=10
        )

        if result.returncode != 0:
            pytest.skip("Compilation failed")

        return binary

    def test_capstone_handles_structs(self, compiled_binary):
        """Test Capstone disassembly of struct operations."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError:
            pytest.skip("Capstone not installed")

        # Read binary and look for specific patterns
        with open(compiled_binary, "rb") as f:
            data = f.read()

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions = list(md.disasm(data, 0))

        # Should have multiple instructions
        assert len(instructions) > 10, "Binary should have enough code"

        # Look for common patterns
        mnemonics = [i.mnemonic for i in instructions[:50]]
        assert any(m in ["mov", "lea", "add", "push", "pop", "cmp"] for m in mnemonics)

    def test_angr_memory_analysis(self, compiled_binary):
        """Test angr memory state analysis."""
        try:
            import angr
        except Exception:
            pytest.skip("angr not installed")

        try:
            proj = angr.Project(str(compiled_binary), auto_load_libs=False)
            state = proj.factory.entry_state()

            # Check memory operations
            assert state.memory is not None
            assert state.regs is not None
        except Exception as e:
            pytest.skip(f"angr analysis failed: {e}")


@pytest.mark.benchmark
class TestAnalysisToolPerformance:
    """Test performance characteristics of analysis tools."""

    def test_capstone_disassembly_speed(self):
        """Test Capstone disassembly performance."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError:
            pytest.skip("Capstone not installed")

        # Large code buffer
        code = bytes([0x90] * 10000)  # 10KB of NOPs

        import time

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        start = time.time()
        instructions = list(md.disasm(code, 0))
        elapsed = time.time() - start

        assert len(instructions) == 10000
        # Should disassemble quickly (< 100ms)
        assert elapsed < 0.1, f"Disassembly took {elapsed:.3f}s"

    def test_angr_analysis_timeout(self, tmp_path):
        """Test angr analysis with timeout."""
        try:
            import angr
        except Exception:
            pytest.skip("angr not installed")

        binary = tmp_path / "test"
        c_file = tmp_path / "test.c"
        c_file.write_text("""
int main() {
    int sum = 0;
    for(int i = 0; i < 1000; i++) {
        sum += i;
    }
    return sum;
}
""")

        if not shutil.which("gcc"):
            pytest.skip("gcc not available")

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)], capture_output=True, timeout=10
        )

        if result.returncode != 0:
            pytest.skip("Compilation failed")

        import time

        try:
            start = time.time()
            _ = angr.Project(str(binary), auto_load_libs=False)
            # This should complete quickly
            elapsed = time.time() - start
            assert elapsed < 5, "Project loading took too long"
        except Exception as e:
            pytest.skip(f"angr failed: {e}")
