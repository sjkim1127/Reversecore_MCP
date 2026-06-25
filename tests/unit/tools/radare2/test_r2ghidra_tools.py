"""
Unit tests for r2ghidra_tools — r2ghidra decompilation and analysis tools.

All radare2/r2ghidra calls are mocked so tests run without any binary tools installed.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_r2_run():
    """Patch _execute_r2_command to return controlled output."""
    with patch(
        "reversecore_mcp.tools.radare2.r2ghidra_tools._execute_r2_command",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.fixture()
def mock_validate_file_path():
    """Patch validate_file_path to return a fake path."""
    from pathlib import Path

    with patch(
        "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path",
        return_value=Path("/workspace/test.elf"),
    ) as mock:
        yield mock


@pytest.fixture()
def mock_validate_addr():
    """Patch validate_address_format to succeed by default."""
    with patch(
        "reversecore_mcp.core.validators.validate_address_format",
        return_value=None,
    ) as mock:
        yield mock


# ---------------------------------------------------------------------------
# r2_decompile tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2Decompile:
    """Tests for r2_decompile tool."""

    @pytest.mark.asyncio
    async def test_success_returns_pseudo_c(self, mock_r2_run, mock_validate_file_path):
        """r2_decompile returns pseudo_c from pdg output."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile

        mock_r2_run.return_value = (
            "int main(int argc, char **argv) {\n    return 0;\n}\n",
            100,
        )

        result = await r2_decompile("/workspace/test.elf", "main")

        assert result.status == "success"
        data = result.data
        assert "pseudo_c" in data
        assert "main" in data["pseudo_c"] or "return" in data["pseudo_c"]
        assert data["decompiler"] == "r2ghidra"

    @pytest.mark.asyncio
    async def test_empty_output_returns_error(self, mock_r2_run, mock_validate_file_path):
        """r2_decompile returns failure when pdg produces no output."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile

        mock_r2_run.return_value = ("", 0)

        result = await r2_decompile("/workspace/test.elf", "0x401000")

        assert result.status == "error"
        assert "r2ghidra" in result.message.lower() or "failed" in result.message.lower()

    @pytest.mark.asyncio
    async def test_error_prefix_returns_failure(self, mock_r2_run, mock_validate_file_path):
        """r2_decompile returns failure when output starts with ERROR."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile

        mock_r2_run.return_value = ("ERROR: cannot find function at 0xdeadbeef\n", 50)

        result = await r2_decompile("/workspace/test.elf", "0xdeadbeef")

        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_invalid_address_returns_error(self, mock_validate_file_path):
        """r2_decompile fails fast on invalid address."""
        from reversecore_mcp.core.exceptions import ValidationError
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile

        with patch(
            "reversecore_mcp.core.validators.validate_address_format",
            side_effect=ValidationError("Invalid address"),
        ):
            result = await r2_decompile("/workspace/test.elf", "INVALID!!ADDR")

        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code or "invalid" in result.message.lower()

    @pytest.mark.asyncio
    async def test_decompilation_caching(
        self, mock_r2_run, mock_validate_file_path, patched_config
    ):
        """r2_decompile uses the caching layer to avoid redundant decompiler invocations."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile

        workspace_dir = patched_config.workspace

        # Create a dummy binary file so sha256 calculation works
        test_file = workspace_dir / "test.elf"
        test_file.write_bytes(b"dummy elf content")
        mock_validate_file_path.return_value = test_file

        mock_r2_run.return_value = (
            "int main() { return 0; }",
            100,
        )

        with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=None):
            # 1. First invocation (cache miss)
            res1 = await r2_decompile(str(test_file), "main")
            assert res1.status == "success"
            assert mock_r2_run.call_count == 1
            assert res1.metadata is None or not res1.metadata.get("cache_hit")

            # 2. Second invocation (cache hit)
            res2 = await r2_decompile(str(test_file), "main")
            assert res2.status == "success"
            # Invocations to r2 should still be 1 (meaning it was loaded from cache)
            assert mock_r2_run.call_count == 1
            assert res2.metadata.get("cache_hit") is True
            assert res2.data["pseudo_c"] == "int main() { return 0; }"


# ---------------------------------------------------------------------------
# r2_recover_structures tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2RecoverStructures:
    """Tests for r2_recover_structures tool."""

    @pytest.mark.asyncio
    async def test_parses_afvfj_json(self, mock_r2_run, mock_validate_file_path):
        """r2_recover_structures parses afvfj JSON correctly."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_recover_structures

        mock_r2_run.return_value = (
            '[{"name":"local_10h","type":"int","delta":-16,"size":4}]\n[]\n[]\n',
            200,
        )

        result = await r2_recover_structures("/workspace/test.elf", "main")

        assert result.status == "success"
        data = result.data
        assert isinstance(data["structures"], list)
        assert data["field_count"] >= 0

    @pytest.mark.asyncio
    async def test_empty_output_returns_empty_structures(
        self, mock_r2_run, mock_validate_file_path
    ):
        """r2_recover_structures returns empty list on empty r2 output."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_recover_structures

        mock_r2_run.return_value = ("null\n", 10)

        result = await r2_recover_structures("/workspace/test.elf", "0x401000")

        assert result.status == "success"
        data = result.data
        assert data["structures"] == []

    @pytest.mark.asyncio
    async def test_recover_structures_caching(
        self, mock_r2_run, mock_validate_file_path, patched_config
    ):
        """r2_recover_structures uses the caching layer to avoid redundant analysis."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_recover_structures

        workspace_dir = patched_config.workspace

        # Create a dummy binary file so sha256 calculation works
        test_file = workspace_dir / "test.elf"
        test_file.write_bytes(b"dummy elf content")
        mock_validate_file_path.return_value = test_file

        mock_r2_run.return_value = (
            '[{"name":"local_10h","type":"int","delta":-16,"size":4}]\n',
            100,
        )

        with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=None):
            # 1. First invocation (cache miss)
            res1 = await r2_recover_structures(str(test_file), "main")
            assert res1.status == "success"
            assert mock_r2_run.call_count == 1
            assert res1.metadata is None or not res1.metadata.get("cache_hit")

            # 2. Second invocation (cache hit)
            res2 = await r2_recover_structures(str(test_file), "main")
            assert res2.status == "success"
            assert mock_r2_run.call_count == 1
            assert res2.metadata.get("cache_hit") is True


# ---------------------------------------------------------------------------
# r2_analyze_function tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2AnalyzeFunction:
    """Tests for r2_analyze_function tool."""

    @pytest.mark.asyncio
    async def test_success_returns_metadata(self, mock_r2_run, mock_validate_file_path):
        """r2_analyze_function returns structured function metadata."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_analyze_function

        fn_json = (
            '[{"name":"main","offset":4198400,"size":120,"cc":5,'
            '"edges":10,"nbbs":4,"nlocals":3,"nargs":2,'
            '"signature":"int main(int argc, char **argv)","calltype":"cdecl"}]\n'
        )
        mock_r2_run.return_value = (fn_json, 300)

        result = await r2_analyze_function("/workspace/test.elf", "main")

        assert result.status == "success"
        data = result.data
        assert data["name"] == "main"
        assert data["size"] == 120
        assert data["complexity"] == 5
        assert data["nargs"] == 2

    @pytest.mark.asyncio
    async def test_empty_afij_returns_error(self, mock_r2_run, mock_validate_file_path):
        """r2_analyze_function returns error when afij gives no data."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_analyze_function

        mock_r2_run.return_value = ("", 0)

        result = await r2_analyze_function("/workspace/test.elf", "0xdeadbeef")

        assert result.status == "error"


# ---------------------------------------------------------------------------
# r2_get_call_graph tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2GetCallGraph:
    """Tests for r2_get_call_graph tool."""

    @pytest.mark.asyncio
    async def test_returns_nodes_and_edges(self, mock_r2_run, mock_validate_file_path):
        """r2_get_call_graph returns nodes and edges lists."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_get_call_graph

        mock_r2_run.return_value = (
            '[{"from":{"name":"main","offset":4198400},"to":{"name":"printf","offset":4202000}}]\n'
            '[{"from":{"name":"caller","offset":4200000},"to":{"name":"main","offset":4198400}}]\n',
            400,
        )

        result = await r2_get_call_graph("/workspace/test.elf", "main", depth=2)

        assert result.status == "success"
        data = result.data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    @pytest.mark.asyncio
    async def test_invalid_depth_returns_error(self, mock_validate_file_path):
        """r2_get_call_graph rejects depth out of range."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_get_call_graph

        result = await r2_get_call_graph("/workspace/test.elf", "main", depth=99)

        assert result.status == "error"
        assert "depth" in result.message.lower()


# ---------------------------------------------------------------------------
# r2_simulate_patch tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2SimulatePatch:
    """Tests for r2_simulate_patch tool."""

    @pytest.mark.asyncio
    async def test_invalid_hex_returns_error(self, mock_validate_file_path):
        """r2_simulate_patch rejects non-hex patch_bytes."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_simulate_patch

        result = await r2_simulate_patch("/workspace/test.elf", "0x401000", "ZZZZ")

        assert result.status == "error"
        assert "hex" in result.message.lower()

    @pytest.mark.asyncio
    async def test_odd_length_hex_returns_error(self, mock_validate_file_path):
        """r2_simulate_patch rejects odd-length hex strings."""
        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_simulate_patch

        result = await r2_simulate_patch("/workspace/test.elf", "0x401000", "909")

        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_success_with_nop_patch(self, mock_r2_run, mock_validate_file_path):
        """r2_simulate_patch succeeds with valid NOP patch and mocked r2."""

        from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_simulate_patch

        mock_r2_run.return_value = ("0x401000  90 90  nop; nop\n", 50)

        with patch("shutil.which", return_value="/usr/bin/r2"):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(
                return_value=(b"0x401000  90 90  nop; nop\nint main() { return 0; }\n", b"")
            )
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ):
                result = await r2_simulate_patch("/workspace/test.elf", "0x401000", "9090")

        assert result.status == "success"
        data = result.data
        assert data["byte_count"] == 2
        assert "NOT modified" in data["note"]
