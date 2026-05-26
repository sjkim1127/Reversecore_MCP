"""Tests for reversecore_mcp.core.ghidra (GhidraService)."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def reset_ghidra_service():
    """Reset GhidraService singleton before each test."""
    from reversecore_mcp.core.ghidra import GhidraService

    GhidraService._instance = None
    yield
    GhidraService._instance = None


class TestGhidraServiceSingleton:
    """Tests for GhidraService singleton pattern."""

    def test_same_instance(self):
        """Two instantiations return the same object."""
        from reversecore_mcp.core.ghidra import GhidraService

        s1 = GhidraService()
        s2 = GhidraService()
        assert s1 is s2

    def test_initialized_flag(self):
        """__init__ is skipped on second call."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        assert s._initialized is True
        # Second call should not re-initialize
        s.__init__()
        assert s._jvm_started is False  # unchanged


class TestIsAvailable:
    """Tests for is_available."""

    def test_available(self):
        """Return True when pyghidra is importable."""
        from reversecore_mcp.core.ghidra import ghidra_service

        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            assert ghidra_service.is_available() is True

    def test_not_available(self):
        """Return False when pyghidra is missing."""
        from reversecore_mcp.core.ghidra import ghidra_service

        with patch.dict("sys.modules", {"pyghidra": None}):
            assert ghidra_service.is_available() is False


class TestConfigureEnvironment:
    """Tests for _configure_environment."""

    def test_already_set(self, monkeypatch):
        """Do nothing when JAVA_HOME is already set."""
        from reversecore_mcp.core.ghidra import ghidra_service

        monkeypatch.setenv("JAVA_HOME", "/usr/lib/jvm/java-21")
        ghidra_service._configure_environment()
        assert os.environ["JAVA_HOME"] == "/usr/lib/jvm/java-21"

    def test_from_which(self, monkeypatch):
        """Set JAVA_HOME from shutil.which('java')."""
        from reversecore_mcp.core.ghidra import ghidra_service

        monkeypatch.delenv("JAVA_HOME", raising=False)
        with patch("shutil.which", return_value="/opt/jdk/bin/java"):
            with patch.object(Path, "resolve", return_value=Path("/opt/jdk/bin/java")):
                ghidra_service._configure_environment()

    def test_java_not_found(self, monkeypatch):
        """Handle missing java gracefully."""
        from reversecore_mcp.core.ghidra import ghidra_service

        monkeypatch.delenv("JAVA_HOME", raising=False)
        with patch("shutil.which", return_value=None):
            ghidra_service._configure_environment()
            assert "JAVA_HOME" not in os.environ


class TestEnsureJvmStarted:
    """Tests for _ensure_jvm_started."""

    def test_already_started(self):
        """Skip if JVM already started."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        s._jvm_started = True
        s._ensure_jvm_started()
        assert s._jvm_started is True

    def test_pyghidra_not_installed(self):
        """Raise ImportError when pyghidra is missing."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        with patch.dict("sys.modules", {"pyghidra": None}):
            with pytest.raises(ImportError, match="pyghidra not installed"):
                s._ensure_jvm_started()


class TestGetProject:
    """Tests for _get_project caching logic."""

    def test_cache_miss(self):
        """Load new project on cache miss."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        s._max_projects = 2
        s._pyghidra = MagicMock()
        flat_api = MagicMock()
        program = MagicMock()
        flat_api.getCurrentProgram.return_value = program
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=flat_api)
        s._pyghidra.open_program.return_value = ctx

        p, f, c = s._get_project("/tmp/test.bin")
        assert p is program
        assert f is flat_api
        assert c is ctx
        assert "/tmp/test.bin" in s._projects

    def test_cache_hit(self):
        """Return cached project on hit."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        s._max_projects = 2
        ctx = MagicMock()
        s._projects["/tmp/test.bin"] = ("prog", "flat", ctx)

        p, f, c = s._get_project("/tmp/test.bin")
        assert p == "prog"
        assert f == "flat"
        assert c is ctx

    def test_lru_eviction(self):
        """Evict oldest project when cache is full."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        s._max_projects = 1
        s._pyghidra = MagicMock()
        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = MagicMock()
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=flat_api)
        s._pyghidra.open_program.return_value = ctx

        # First project
        s._get_project("/tmp/a.bin")
        assert "/tmp/a.bin" in s._projects

        # Second project evicts first
        ctx2 = MagicMock()
        ctx2.__enter__ = MagicMock(return_value=flat_api)
        s._pyghidra.open_program.return_value = ctx2
        s._get_project("/tmp/b.bin")
        assert "/tmp/a.bin" not in s._projects
        assert "/tmp/b.bin" in s._projects


class TestInvalidateProject:
    """Tests for _invalidate_project."""

    def test_removes_from_cache(self):
        """Remove a project from the cache."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        s._projects["/tmp/test.bin"] = ("p", "f", "c")
        s._invalidate_project("/tmp/test.bin")
        assert "/tmp/test.bin" not in s._projects


class TestResolveFunction:
    """Tests for _resolve_function."""

    def test_by_symbol(self):
        """Resolve by symbol name."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        symbol = MagicMock()
        symbol.getAddress.return_value = "addr_0x1234"

        symbols = MagicMock()
        symbols.hasNext.return_value = True
        symbols.next.return_value = symbol

        symbol_table = MagicMock()
        symbol_table.getSymbols.return_value = symbols

        program = MagicMock()
        program.getSymbolTable.return_value = symbol_table

        func = MagicMock()
        function_manager = MagicMock()
        function_manager.getFunctionAt.return_value = func
        program.getFunctionManager.return_value = function_manager

        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = program

        result = s._resolve_function(flat_api, "main")
        assert result is func

    def test_by_hex_address(self):
        """Resolve by hex address."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        symbols = MagicMock()
        symbols.hasNext.return_value = False

        symbol_table = MagicMock()
        symbol_table.getSymbols.return_value = symbols

        program = MagicMock()
        program.getSymbolTable.return_value = symbol_table

        func = MagicMock()
        function_manager = MagicMock()
        function_manager.getFunctionAt.return_value = func
        program.getFunctionManager.return_value = function_manager

        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = program
        flat_api.toAddr.return_value = "addr_0x401000"

        result = s._resolve_function(flat_api, "0x401000")
        assert result is func

    def test_create_if_missing(self):
        """Create function when not found and create_if_missing=True."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        symbols = MagicMock()
        symbols.hasNext.return_value = False

        symbol_table = MagicMock()
        symbol_table.getSymbols.return_value = symbols

        program = MagicMock()
        program.getSymbolTable.return_value = symbol_table

        function_manager = MagicMock()
        function_manager.getFunctionAt.return_value = None
        function_manager.getFunctionContaining.return_value = None
        program.getFunctionManager.return_value = function_manager

        func = MagicMock()
        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = program
        flat_api.toAddr.return_value = "addr_0x401000"
        flat_api.createFunction.return_value = func

        result = s._resolve_function(flat_api, "0x401000", create_if_missing=True)
        assert result is func

    def test_not_found_no_create(self):
        """Return None when not found and create_if_missing=False."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        symbols = MagicMock()
        symbols.hasNext.return_value = False

        symbol_table = MagicMock()
        symbol_table.getSymbols.return_value = symbols

        program = MagicMock()
        program.getSymbolTable.return_value = symbol_table

        function_manager = MagicMock()
        function_manager.getFunctionAt.return_value = None
        function_manager.getFunctionContaining.return_value = None
        program.getFunctionManager.return_value = function_manager

        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = program
        flat_api.toAddr.return_value = "addr_0x401000"

        result = s._resolve_function(flat_api, "0x401000", create_if_missing=False)
        assert result is None


class TestExtractStructureFields:
    """Tests for _extract_structure_fields."""

    def test_no_components(self):
        """Return empty list when no components."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        data_type = MagicMock()
        del data_type.getNumComponents
        assert s._extract_structure_fields(data_type) == []

    def test_extracts_fields(self):
        """Extract field data correctly."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        component = MagicMock()
        component.getFieldName.return_value = "field1"
        component.getDataType.return_value.getName.return_value = "int"
        component.getOffset.return_value = 0
        component.getLength.return_value = 4

        data_type = MagicMock()
        data_type.getNumComponents.return_value = 1
        data_type.getComponent.return_value = component

        fields = s._extract_structure_fields(data_type)
        assert fields[0]["name"] == "field1"
        assert fields[0]["type"] == "int"
        assert fields[0]["offset"] == "0x0"
        assert fields[0]["size"] == 4


class TestDecompileErrorPaths:
    """Error path tests for decompile."""

    def test_pyghidra_not_installed(self):
        """Raise ImportError when pyghidra is missing."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        with patch.object(
            s, "_ensure_jvm_started", side_effect=ImportError("pyghidra not installed")
        ):
            with pytest.raises(ImportError, match="pyghidra not installed"):
                s.decompile("/tmp/test.bin", "0x401000")


class TestRecoverStructuresErrorPaths:
    """Error path tests for recover_structures."""

    def test_pyghidra_not_installed(self):
        """Raise ImportError when pyghidra is missing."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        with patch.object(
            s, "_ensure_jvm_started", side_effect=ImportError("pyghidra not installed")
        ):
            with pytest.raises(ImportError, match="pyghidra not installed"):
                s.recover_structures("/tmp/test.bin", "0x401000")


class TestGetVersion:
    """Tests for get_version."""

    def test_not_available(self):
        """Return None when pyghidra is not installed."""
        from reversecore_mcp.core.ghidra import ghidra_service

        with patch.dict("sys.modules", {"pyghidra": None}):
            assert ghidra_service.get_version() is None


class TestCloseAll:
    """Tests for close_all."""

    def test_closes_projects(self):
        """Close all cached projects."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        ctx = MagicMock()
        s._projects["/tmp/a.bin"] = ("p", "f", ctx)
        s.close_all()
        assert s._projects == {}
        ctx.__exit__.assert_called_once()

    def test_handles_close_errors(self):
        """Log warning when project close fails."""
        from reversecore_mcp.core.ghidra import GhidraService

        s = GhidraService()
        ctx = MagicMock()
        ctx.__exit__.side_effect = RuntimeError("close failed")
        s._projects["/tmp/a.bin"] = ("p", "f", ctx)
        s.close_all()
        assert s._projects == {}


class TestLegacyAliases:
    """Tests for deprecated module-level functions."""

    def test_ensure_ghidra_available(self):
        """Legacy alias delegates to ghidra_service."""
        from reversecore_mcp.core.ghidra import (
            ensure_ghidra_available,
            ghidra_service,
        )

        with patch.object(ghidra_service, "is_available", return_value=True):
            assert ensure_ghidra_available() is True

    def test_get_ghidra_version(self):
        """Legacy alias delegates to ghidra_service."""
        from reversecore_mcp.core.ghidra import get_ghidra_version, ghidra_service

        with patch.object(ghidra_service, "get_version", return_value="12.1"):
            assert get_ghidra_version() == "12.1"

    def test_decompile_function_with_ghidra(self):
        """Legacy alias delegates to ghidra_service.decompile."""
        from reversecore_mcp.core.ghidra import (
            decompile_function_with_ghidra,
            ghidra_service,
        )

        with patch.object(ghidra_service, "decompile", return_value=("code", {})):
            result = decompile_function_with_ghidra(Path("/tmp/test.bin"), "0x401000")
            assert result == ("code", {})

    def test_recover_structures_with_ghidra(self):
        """Legacy alias delegates to ghidra_service.recover_structures."""
        from reversecore_mcp.core.ghidra import (
            ghidra_service,
            recover_structures_with_ghidra,
        )

        with patch.object(ghidra_service, "recover_structures", return_value=({"structs": []}, {})):
            result = recover_structures_with_ghidra(Path("/tmp/test.bin"), "0x401000")
            assert result == ({"structs": []}, {})

    def test_ghidra_manager_alias(self):
        """GhidraManager is a subclass of GhidraService."""
        from reversecore_mcp.core.ghidra import GhidraManager, GhidraService

        assert issubclass(GhidraManager, GhidraService)
