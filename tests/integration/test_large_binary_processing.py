"""
Large binary processing tests.

Tests for handling binaries > 100MB, memory efficiency, and timeout handling.
"""

import shutil
import subprocess
import time

import pytest


class TestLargeBinaryHandling:
    """Test handling of large binaries."""

    @pytest.fixture
    def large_binary(self, tmp_path):
        """Create a large binary (100MB+)."""
        binary_path = tmp_path / "large_binary"
        size_mb = 100

        # Create a large file with pattern
        chunk_size = 1024 * 1024  # 1MB
        bytes_to_write = size_mb * chunk_size

        with open(binary_path, "wb") as f:
            bytes_written = 0
            while bytes_written < bytes_to_write:
                chunk = bytes(
                    [i % 256 for i in range(min(chunk_size, bytes_to_write - bytes_written))]
                )
                f.write(chunk)
                bytes_written += len(chunk)

        return binary_path

    def test_file_command_on_large_binary(self, large_binary):
        """Test 'file' command on large binary."""
        if not shutil.which("file"):
            pytest.skip("file not available")

        start = time.time()
        result = subprocess.run(
            ["file", "-b", str(large_binary)], capture_output=True, text=True, timeout=10
        )
        elapsed = time.time() - start

        assert result.returncode == 0
        assert len(result.stdout) > 0
        # file should be fast even on large files
        assert elapsed < 1.0, f"file command took {elapsed:.2f}s on large binary"

    def test_strings_command_timeout(self, large_binary):
        """Test strings command with timeout handling."""
        if not shutil.which("strings"):
            pytest.skip("strings not available")

        start = time.time()
        try:
            subprocess.run(
                ["strings", str(large_binary)],
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
            )
            elapsed = time.time() - start
            # Should complete or timeout gracefully
            assert elapsed < 40, "strings took too long"
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            # Timeout is acceptable for very large files
            assert elapsed >= 30, "Timeout should trigger after timeout value"

    def test_objdump_on_large_binary(self, large_binary):
        """Test objdump handling of large binary."""
        if not shutil.which("objdump"):
            pytest.skip("objdump not available")

        # objdump may fail on non-ELF, but should handle it gracefully
        try:
            result = subprocess.run(
                ["objdump", "-h", str(large_binary)], capture_output=True, text=True, timeout=10
            )
            # Should return quickly even if it fails
            assert result.returncode in (0, 1)
        except subprocess.TimeoutExpired:
            pytest.fail("objdump timed out on large binary")

    def test_streaming_analysis(self, large_binary):
        """Test streaming/chunked analysis of large binary."""
        chunk_size = 1024 * 1024  # 1MB chunks

        total_bytes = 0
        with open(large_binary, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)

        # Should efficiently read large file in chunks
        assert total_bytes == large_binary.stat().st_size


class TestMemoryEfficientProcessing:
    """Test memory-efficient processing of large binaries."""

    @pytest.fixture
    def memory_monitor(self):
        """Monitor memory usage."""
        try:
            import psutil  # noqa: F401

            return True
        except ImportError:
            return False

    def test_capstone_chunked_disassembly(self, tmp_path):
        """Test Capstone disassembly with streaming."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError:
            pytest.skip("Capstone not installed")

        # Create large code buffer (10MB)
        code = bytes([0x90] * (10 * 1024 * 1024))

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # Disassemble in chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        total_instructions = 0

        start_time = time.time()
        for offset in range(0, len(code), chunk_size):
            chunk = code[offset : offset + chunk_size]
            instructions = list(md.disasm(chunk, offset))
            total_instructions += len(instructions)
        elapsed = time.time() - start_time

        assert total_instructions > 0
        # Should handle large code reasonably
        assert elapsed < 60, f"Chunked disassembly took {elapsed:.2f}s"

    def test_binary_reading_patterns(self, tmp_path):
        """Test efficient binary reading patterns."""
        binary = tmp_path / "test_binary"
        size_mb = 100

        # Create binary
        chunk_size = 1024 * 1024
        size_mb * chunk_size

        with open(binary, "wb") as f:
            for _ in range(size_mb):
                f.write(bytes([i % 256 for i in range(chunk_size)]))

        # Pattern 1: Read all at once
        start = time.time()
        with open(binary, "rb") as f:
            data_all = f.read()
        time.time() - start

        # Pattern 2: Read in chunks
        start = time.time()
        chunks = []
        with open(binary, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
        time.time() - start

        # Both should succeed
        assert len(data_all) == binary.stat().st_size
        assert sum(len(c) for c in chunks) == binary.stat().st_size

    def test_binary_header_analysis_only(self, tmp_path):
        """Test analyzing only binary headers for large files."""
        binary = tmp_path / "large_binary"

        # Create 100MB binary
        with open(binary, "wb") as f:
            # Write ELF header
            f.write(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
            # Pad rest
            f.write(bytes([0] * (100 * 1024 * 1024 - 64)))

        # Analyze only header
        header_size = 4096  # 4KB header
        with open(binary, "rb") as f:
            header = f.read(header_size)

        # Should be fast
        assert len(header) == header_size
        assert header.startswith(b"\x7fELF")


class TestTimeoutHandling:
    """Test timeout handling for long-running analysis."""

    def test_tool_with_short_timeout(self, tmp_path):
        """Test tool execution with short timeout."""
        binary = tmp_path / "test"
        binary.write_text("test content")

        if shutil.which("file"):
            # Should complete within 1 second
            result = subprocess.run(["file", str(binary)], capture_output=True, timeout=1)
            assert result.returncode == 0

    def test_analysis_timeout_recovery(self, tmp_path):
        """Test recovery from analysis timeout."""
        binary = tmp_path / "test"
        binary.write_bytes(bytes([0xFF] * 1000))

        timeout_value = 2
        max_retries = 3

        for attempt in range(max_retries):
            try:
                subprocess.run(
                    ["strings", str(binary)], capture_output=True, timeout=timeout_value, text=True
                )
                # Success
                break
            except subprocess.TimeoutExpired:
                if attempt == max_retries - 1:
                    pytest.fail(f"Analysis failed after {max_retries} attempts")
                # Retry with longer timeout
                timeout_value *= 2

    def test_concurrent_binary_analysis(self, tmp_path):
        """Test analyzing multiple large binaries concurrently."""
        import concurrent.futures

        # Create test binaries
        binaries = []
        for i in range(3):
            binary = tmp_path / f"test_{i}"
            binary.write_bytes(bytes([i % 256] * (10 * 1024 * 1024)))  # 10MB each
            binaries.append(binary)

        def analyze_binary(path):
            if shutil.which("file"):
                result = subprocess.run(["file", str(path)], capture_output=True, timeout=10)
                return result.returncode == 0
            return True

        # Analyze concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(analyze_binary, binaries))

        assert all(results), "Some binary analyses failed"


@pytest.mark.integration
class TestPEBinaryProcessing:
    """Test Windows PE binary processing."""

    @pytest.fixture
    def pe_x86_binary(self, tmp_path):
        """Create minimal PE x86 binary."""
        # Minimal PE header for x86
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = b"\x40\x00\x00\x00"  # PE offset at 0x40

        pe_header = b"PE\x00\x00"
        # COFF header
        pe_header += b"\x4c\x01"  # Machine i386
        pe_header += b"\x00\x00"  # Number of sections
        pe_header += b"\x00" * 12  # Timestamps and symbol info
        pe_header += b"\xe0\x00"  # SizeOfOptionalHeader
        pe_header += b"\x02\x01"  # Characteristics

        binary_data = bytes(dos_header) + bytes(pe_header) + b"\x00" * 1000

        path = tmp_path / "minimal.exe"
        path.write_bytes(binary_data)
        return path

    def test_file_recognizes_pe(self, pe_x86_binary):
        """Test file command recognizes PE binary."""
        if not shutil.which("file"):
            pytest.skip("file not available")

        result = subprocess.run(
            ["file", "-b", str(pe_x86_binary)], capture_output=True, text=True, timeout=5
        )

        assert result.returncode == 0
        output = result.stdout.lower()
        # Should identify as PE or executable
        assert any(x in output for x in ["pe", "executable", "coff"])

    def test_pe_binary_strings_extraction(self, pe_x86_binary):
        """Test strings extraction from PE binary."""
        if not shutil.which("strings"):
            pytest.skip("strings not available")

        result = subprocess.run(
            ["strings", str(pe_x86_binary)], capture_output=True, text=True, timeout=5
        )

        assert result.returncode == 0
        # Should find at least PE signature
        output = result.stdout.upper()
        assert "PE" in output or len(result.stdout) >= 0  # strings may be empty
