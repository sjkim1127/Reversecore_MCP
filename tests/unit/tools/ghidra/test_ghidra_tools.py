"""Unit tests for Ghidra tools."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.ghidra.ghidra_tools import (
    GhidraToolsPlugin,
    _get_ghidra_program,
)


@pytest.fixture(autouse=True)
def patch_validate_file_path():
    """Patch validate_file_path to avoid filesystem checks."""
    import reversecore_mcp.tools.ghidra.ghidra_tools as gt
    import reversecore_mcp.core.security as sec
    orig_gt = getattr(gt, "validate_file_path", None)
    orig_sec = getattr(sec, "validate_file_path", None)
    try:
        gt.validate_file_path = lambda p: Path(p)
        sec.validate_file_path = lambda p: Path(p)
        yield
    finally:
        if orig_gt is not None:
            gt.validate_file_path = orig_gt
        if orig_sec is not None:
            sec.validate_file_path = orig_sec


class TestGetGhidraProgram:
    """Tests for _get_ghidra_program helper."""

    def test_not_available_raises(self):
        """Should raise ImportError when Ghidra unavailable."""
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = False
            with pytest.raises(ImportError, match="PyGhidra is not installed"):
                _get_ghidra_program("/app/test.exe")

    def test_returns_program_and_flat_api(self):
        """Should return program and flat_api when available."""
        mock_program = MagicMock()
        mock_flat = MagicMock()
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
            program, flat_api = _get_ghidra_program("/app/test.exe")
            assert program is mock_program
            assert flat_api is mock_flat
            mock_svc._ensure_jvm_started.assert_called_once()


class TestGhidraListStructures:
    """Tests for Ghidra_list_structures tool."""

    @pytest.mark.asyncio
    async def test_ghidra_unavailable(self):
        """Should return error when Ghidra unavailable."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_list_structures
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = False
            result = await Ghidra_list_structures("/app/test.exe")
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_basic_list(self):
        """Should list structures successfully."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_list_structures
        mock_program = MagicMock()
        mock_flat = MagicMock()
        mock_dt = MagicMock()
        mock_dt.getName.return_value = "MyStruct"
        mock_dt.getCategoryPath.return_value.toString.return_value = "/"
        mock_flat.getDataTypes.return_value = [mock_dt]
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
            result = await Ghidra_list_structures("/app/test.exe")
            assert result.status == "success"


class TestGhidraGetStructure:
    """Tests for Ghidra_get_structure tool."""

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Should return error when structure not found."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_get_structure
        mock_flat = MagicMock()
        mock_flat.getDataTypes.return_value = []
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (MagicMock(), mock_flat, MagicMock())
            result = await Ghidra_get_structure("/app/test.exe", "NonExistent")
            assert result.status == "error"
            assert "not found" in str(result).lower() or "STRUCTURE_NOT_FOUND" in str(result)

    @pytest.mark.asyncio
    async def test_found(self):
        """Should return structure details."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_get_structure
        mock_program = MagicMock()
        mock_struct = MagicMock()
        mock_struct.getName.return_value = "TestStruct"
        mock_struct.getLength.return_value = 16
        mock_struct.getCategoryPath.return_value.toString.return_value = "/"
        mock_struct.getNumComponents.return_value = 0
        mock_dtm = MagicMock()
        mock_dtm.getAllStructures.return_value = [mock_struct]
        mock_program.getDataTypeManager.return_value = mock_dtm
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, MagicMock(), MagicMock())
            result = await Ghidra_get_structure("/app/test.exe", "TestStruct")
            assert result.status == "success"


class TestGhidraCreateStructure:
    """Tests for Ghidra_create_structure tool."""

    @pytest.mark.asyncio
    async def test_invalid_json(self):
        """Should return error for invalid JSON fields."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_create_structure
        result = await Ghidra_create_structure("/app/test.exe", "NewStruct", "not json")
        assert result.status == "error"
        assert "INVALID_FIELDS_JSON" in str(result)


class TestGhidraListEnums:
    """Tests for Ghidra_list_enums tool."""

    @pytest.mark.asyncio
    async def test_basic(self):
        """Should list enums."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_list_enums
        mock_flat = MagicMock()
        mock_flat.getDataTypes.return_value = []
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (MagicMock(), mock_flat, MagicMock())
            result = await Ghidra_list_enums("/app/test.exe")
            assert result.status == "success"


class TestGhidraListDataTypes:
    """Tests for Ghidra_list_data_types tool."""

    @pytest.mark.asyncio
    async def test_basic(self):
        """Should list data types."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_list_data_types
        mock_flat = MagicMock()
        mock_flat.getDataTypes.return_value = []
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (MagicMock(), mock_flat, MagicMock())
            result = await Ghidra_list_data_types("/app/test.exe")
            assert result.status == "success"


class TestGhidraListBookmarks:
    """Tests for Ghidra_list_bookmarks tool."""

    @pytest.mark.asyncio
    async def test_basic(self):
        """Should list bookmarks."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_list_bookmarks
        mock_program = MagicMock()
        mock_bm_mgr = MagicMock()
        mock_bm_mgr.getBookmarksIterator.return_value = iter([])
        mock_program.getBookmarkManager.return_value = mock_bm_mgr
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, MagicMock(), MagicMock())
            result = await Ghidra_list_bookmarks("/app/test.exe")
            assert result.status == "success"


class TestGhidraAddBookmark:
    """Tests for Ghidra_add_bookmark tool."""

    @pytest.mark.asyncio
    async def test_invalid_address(self):
        """Should fail for invalid address."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_add_bookmark
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_flat = MagicMock()
            mock_flat.toAddr.side_effect = Exception("Invalid address")
            mock_svc._get_project.return_value = (MagicMock(), mock_flat, MagicMock())
            result = await Ghidra_add_bookmark("/app/test.exe", "bad_addr", "note", "test")
            assert result.status == "error"


class TestGhidraReadMemory:
    """Tests for Ghidra_read_memory tool."""

    @pytest.mark.asyncio
    async def test_read_success(self):
        """Should read memory successfully."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_read_memory
        mock_program = MagicMock()
        mock_mem = MagicMock()
        mock_mem.getBytes.return_value = b"\x90\x90\x90\x90"
        mock_program.getMemory.return_value = mock_mem
        mock_flat = MagicMock()
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x401000
        mock_flat.toAddr.return_value = mock_addr
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
            result = await Ghidra_read_memory("/app/test.exe", "0x401000", 4)
            assert result.status == "success"

    @pytest.mark.asyncio
    async def test_read_failure(self):
        """Should handle memory read failure."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_read_memory
        mock_flat = MagicMock()
        mock_flat.toAddr.return_value = MagicMock()
        mock_flat.getBytes.side_effect = Exception("Memory access denied")
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (MagicMock(), mock_flat, MagicMock())
            result = await Ghidra_read_memory("/app/test.exe", "0x401000", 4)
            assert result.status == "error"


class TestGhidraGetBytes:
    """Tests for Ghidra_get_bytes tool."""

    @pytest.mark.asyncio
    async def test_get_bytes(self):
        """Should get bytes."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_get_bytes
        mock_program = MagicMock()
        mock_mem = MagicMock()
        mock_mem.getBytes.return_value = b"\x55\x48\x89\xe5"
        mock_program.getMemory.return_value = mock_mem
        mock_flat = MagicMock()
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x401000
        mock_flat.toAddr.return_value = mock_addr
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
            result = await Ghidra_get_bytes("/app/test.exe", "0x401000", 4)
            assert result.status == "success"


class TestGhidraSimulatePatch:
    """Tests for Ghidra_simulate_patch tool."""

    @pytest.mark.asyncio
    async def test_simulate_nop(self):
        """Should simulate NOP patch."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_simulate_patch
        mock_program = MagicMock()
        mock_mem = MagicMock()
        mock_mem.getBytes.return_value = b"\x75\x12"
        mock_program.getMemory.return_value = mock_mem
        mock_flat = MagicMock()
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x401000
        mock_flat.toAddr.return_value = mock_addr
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
            result = await Ghidra_simulate_patch("/app/test.exe", "0x401000", "9090")
            assert result.status == "success"

    @pytest.mark.asyncio
    async def test_invalid_hex(self):
        """Should fail for invalid hex."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_simulate_patch
        result = await Ghidra_simulate_patch("/app/test.exe", "0x401000", "GHIJK")
        assert result.status == "error"
        assert "INVALID_HEX" in str(result) or "hex" in str(result).lower()


class TestGhidraAnalyzeFunction:
    """Tests for Ghidra_analyze_function tool."""

    @pytest.mark.asyncio
    async def test_analysis_success(self):
        """Should analyze function."""
        import sys
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_analyze_function
        mock_cmd = MagicMock()
        mock_ghidra = MagicMock()
        mock_ghidra.app.cmd.function.CreateFunctionCmd = mock_cmd
        sys.modules["ghidra"] = mock_ghidra
        sys.modules["ghidra.app"] = mock_ghidra.app
        sys.modules["ghidra.app.cmd"] = mock_ghidra.app.cmd
        sys.modules["ghidra.app.cmd.function"] = mock_ghidra.app.cmd.function
        mock_program = MagicMock()
        mock_func = MagicMock()
        mock_func.getName.return_value = "main"
        mock_func.getEntryPoint.return_value.toString.return_value = "0x401000"
        mock_func.getBody.return_value.getNumAddresses.return_value = 10
        mock_func.getParameterCount.return_value = 2
        mock_func.getLocalVariables.return_value = []
        mock_func.getCallingConvention.return_value = "cdecl"
        mock_fm = MagicMock()
        mock_fm.getFunctionAt.return_value = mock_func
        mock_program.getFunctionManager.return_value = mock_fm
        mock_flat = MagicMock()
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x401000
        mock_flat.toAddr.return_value = mock_addr
        try:
            with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
                mock_svc.is_available.return_value = True
                mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
                result = await Ghidra_analyze_function("/app/test.exe", "0x401000")
            assert result.status == "success"
        finally:
            for mod in ["ghidra.app.cmd.function", "ghidra.app.cmd", "ghidra.app", "ghidra"]:
                sys.modules.pop(mod, None)

    @pytest.mark.asyncio
    async def test_function_not_found(self):
        """Should fail when function not found."""
        import sys
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_analyze_function
        mock_cmd = MagicMock()
        mock_ghidra = MagicMock()
        mock_ghidra.app.cmd.function.CreateFunctionCmd = mock_cmd
        sys.modules["ghidra"] = mock_ghidra
        sys.modules["ghidra.app"] = mock_ghidra.app
        sys.modules["ghidra.app.cmd"] = mock_ghidra.app.cmd
        sys.modules["ghidra.app.cmd.function"] = mock_ghidra.app.cmd.function
        mock_program = MagicMock()
        mock_fm = MagicMock()
        mock_fm.getFunctionAt.return_value = None
        mock_program.getFunctionManager.return_value = mock_fm
        mock_flat = MagicMock()
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x401000
        mock_flat.toAddr.return_value = mock_addr
        try:
            with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
                mock_svc.is_available.return_value = True
                mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
                result = await Ghidra_analyze_function("/app/test.exe", "0x401000")
            assert result.status == "error"
            assert "FUNCTION_NOT_FOUND" in str(result) or "not found" in str(result).lower()
        finally:
            for mod in ["ghidra.app.cmd.function", "ghidra.app.cmd", "ghidra.app", "ghidra"]:
                sys.modules.pop(mod, None)


class TestGhidraGetCallGraph:
    """Tests for Ghidra_get_call_graph tool."""

    @pytest.mark.asyncio
    async def test_success(self):
        """Should get call graph."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_get_call_graph
        mock_flat = MagicMock()
        mock_func = MagicMock()
        mock_func.getName.return_value = "main"
        mock_ref = MagicMock()
        mock_ref.getFromAddress.return_value.toString.return_value = "0x401020"
        mock_ref.getReferenceType.return_value.toString.return_value = "CALL"
        mock_func.getReferences.return_value = [mock_ref]
        mock_flat.getFunction.return_value = mock_func
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (MagicMock(), mock_flat, MagicMock())
            result = await Ghidra_get_call_graph("/app/test.exe", "main")
            assert result.status == "success"

    @pytest.mark.asyncio
    async def test_function_not_found(self):
        """Should fail when function not found."""
        from reversecore_mcp.tools.ghidra.ghidra_tools import Ghidra_get_call_graph
        mock_program = MagicMock()
        mock_fm = MagicMock()
        mock_fm.getFunctionAt.return_value = None
        mock_fm.getFunctionContaining.return_value = None
        mock_program.getFunctionManager.return_value = mock_fm
        mock_flat = MagicMock()
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x401000
        mock_flat.toAddr.return_value = mock_addr
        with patch("reversecore_mcp.tools.ghidra.ghidra_tools.ghidra_service") as mock_svc:
            mock_svc.is_available.return_value = True
            mock_svc._get_project.return_value = (mock_program, mock_flat, MagicMock())
            result = await Ghidra_get_call_graph("/app/test.exe", "0x401000")
            assert result.status == "error"


class TestGhidraToolsPlugin:
    """Tests for GhidraToolsPlugin."""

    def test_plugin_name(self):
        """Should have correct name."""
        plugin = GhidraToolsPlugin()
        assert plugin.name == "ghidra_tools"

    def test_plugin_description(self):
        """Should have description."""
        plugin = GhidraToolsPlugin()
        assert "ghidra" in plugin.description.lower()

    def test_register(self):
        """Should register tools."""
        plugin = GhidraToolsPlugin()
        mock_mcp = MagicMock()
        plugin.register(mock_mcp)
        assert mock_mcp.tool.call_count >= 5
