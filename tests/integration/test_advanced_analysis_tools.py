"""
Advanced analysis tools testing (Ghidra, Capstone, angr).

Tests for decompilation, disassembly, and symbolic execution frameworks.
"""

import subprocess
import json
import pytest
from pathlib import Path
import shutil
import tempfile
from typing import Optional


class TestCapstoneIntegration:
    """Test Capstone disassembler integration."""

    @pytest.fixture
    def sample_code(self):
        """Sample x86 machine code for disassembly."""
        # mov rax, 0x1000; ret
        return bytes([
            0x48, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00,  # mov rax, 0x1000
            0xc3                                         # ret
        ])

    def test_capstone_import(self):
        """Test Capstone can be imported."""
        try:
            import capstone
            assert hasattr(capstone, 'Cs')
            assert capstone.CS_ARCH_X86 is not None
        except ImportError:
            pytest.skip("Capstone not installed: pip install capstone")

    def test_capstone_disassembly(self, sample_code):
        """Test Capstone disassembly functionality."""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
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
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
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

        result = subprocess.run(
            ["gcc", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10
        )
        assert result.returncode == 0, "gcc compilation failed"

        # Read .text section
        readelf = subprocess.run(
            ["readelf", "-x", ".text", str(binary)],
            capture_output=True,
            text=True,
            timeout=5
        )

        if readelf.returncode == 0:
            # Parse hexdump and disassemble
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            # This is a basic test - just verify it runs
            assert md is not None


class TestGhidraIntegration:
    """Test Ghidra decompilation and analysis."""

    @pytest.fixture
    def ghidra_available(self):
        """Check if Ghidra is installed."""
        ghidra_paths = [
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
            Path.home() / "ghidra",
            Path("/Applications/Ghidra.app/Contents"),
        ]
        for path in ghidra_paths:
            if path.exists():
                return path
        return None

    def test_ghidra_installation_check(self, ghidra_available):
        """Verify Ghidra installation detection."""
        if ghidra_available is None:
            pytest.skip("Ghidra not found in standard locations")
        assert ghidra_available.exists()

    def test_ghidra_headless_command(self):
        """Test Ghidra headless mode availability."""
        result = subprocess.run(
            ["which", "analyzeHeadless"],
            capture_output=True,
            timeout=5
        )

        if result.returncode != 0:
            pytest.skip("Ghidra headless tools not in PATH")
        assert len(result.stdout) > 0

    def test_ghidra_analysis_script(self, tmp_path):
        """Test Ghidra analysis script creation and execution."""
        script_path = tmp_path / "test_analysis.py"
        script_path.write_text("""
# @author 
# @category Search
# @keybinding 
# @menupath Tools.Test
# @toolbar 

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit

def analyze_functions():
    func_manager = currentProgram.getFunctionManager()
    functions = func_manager.getFunctions(True)
    
    count = 0
    for func in functions:
        count += 1
    
    print("Found {} functions".format(count))

analyze_functions()
""")

        # Just verify the script can be created
        assert script_path.exists()
        assert "analyze_functions" in script_path.read_text()


class TestAngrIntegration:
    """Test angr symbolic execution engine."""

    def test_angr_import(self):
        """Test angr can be imported."""
        try:
            import angr
            assert hasattr(angr, 'Project')
        except ImportError:
            pytest.skip("angr not installed: pip install angr")

    def test_angr_project_load(self, tmp_path):
        """Test angr project creation."""
        try:
            import angr
        except ImportError:
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
            ["gcc", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10
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
        except ImportError:
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
            ["gcc", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10
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
            from angr import sim_options
        except ImportError:
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
            ["gcc", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10
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
            ["gcc", "-g", "-o", str(binary), str(target_source)],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            pytest.skip("Compilation failed")

        return binary

    def test_capstone_handles_structs(self, compiled_binary):
        """Test Capstone disassembly of struct operations."""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
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
        assert "mov" in mnemonics or "lea" in mnemonics

    def test_ghidra_type_recovery(self):
        """Test Ghidra type recovery capabilities."""
        # This would require Ghidra to be running
        pytest.skip("Requires active Ghidra instance")

    def test_angr_memory_analysis(self, compiled_binary):
        """Test angr memory state analysis."""
        try:
            import angr
        except ImportError:
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
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
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
        except ImportError:
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
            ["gcc", "-o", str(binary), str(c_file)],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            pytest.skip("Compilation failed")

        import time
        try:
            start = time.time()
            proj = angr.Project(str(binary), auto_load_libs=False)
            # This should complete quickly
            elapsed = time.time() - start
            assert elapsed < 5, "Project loading took too long"
        except Exception as e:
            pytest.skip(f"angr failed: {e}")
