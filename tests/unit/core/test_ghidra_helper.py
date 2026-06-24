"""Tests for reversecore_mcp.core.ghidra_helper."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError


class TestExtractStructureFields:
    """Tests for _extract_structure_fields helper."""

    def test_no_components(self):
        """Return empty list when data_type has no components."""
        from reversecore_mcp.core.ghidra_helper import _extract_structure_fields

        data_type = MagicMock()
        del data_type.getNumComponents  # No getNumComponents attribute
        assert _extract_structure_fields(data_type) == []

    def test_extract_fields(self):
        """Extract fields from a structure data type."""
        from reversecore_mcp.core.ghidra_helper import _extract_structure_fields

        component = MagicMock()
        component.getFieldName.return_value = "my_field"
        component.getDataType.return_value.getName.return_value = "int"
        component.getOffset.return_value = 4
        component.getLength.return_value = 4

        data_type = MagicMock()
        data_type.getNumComponents.return_value = 1
        data_type.getComponent.return_value = component

        fields = _extract_structure_fields(data_type)
        assert len(fields) == 1
        assert fields[0] == {
            "offset": "0x4",
            "type": "int",
            "name": "my_field",
            "size": 4,
        }

    def test_field_without_name(self):
        """Use field_{offset} when field name is empty."""
        from reversecore_mcp.core.ghidra_helper import _extract_structure_fields

        component = MagicMock()
        component.getFieldName.return_value = ""
        component.getDataType.return_value.getName.return_value = "char"
        component.getOffset.return_value = 8
        component.getLength.return_value = 1

        data_type = MagicMock()
        data_type.getNumComponents.return_value = 1
        data_type.getComponent.return_value = component

        fields = _extract_structure_fields(data_type)
        assert fields[0]["name"] == "field_8"


class TestEnsureGhidraAvailable:
    """Tests for ensure_ghidra_available."""

    def test_available(self):
        """Return True when pyghidra is importable."""
        from reversecore_mcp.core.ghidra_helper import ensure_ghidra_available

        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            assert ensure_ghidra_available() is True

    def test_not_available(self):
        """Return False when pyghidra is not installed."""
        from reversecore_mcp.core.ghidra_helper import ensure_ghidra_available

        with patch.dict("sys.modules", {"pyghidra": None}):
            assert ensure_ghidra_available() is False


class TestConfigureGhidraEnvironment:
    """Tests for _configure_ghidra_environment."""

    def test_java_home_already_set(self):
        """Do nothing when JAVA_HOME is already set."""
        from reversecore_mcp.core.ghidra_helper import _configure_ghidra_environment

        with patch.dict(os.environ, {"JAVA_HOME": "/usr/lib/jvm/java-21"}, clear=False):
            _configure_ghidra_environment()
            assert os.environ["JAVA_HOME"] == "/usr/lib/jvm/java-21"

    def test_java_home_from_which(self, monkeypatch):
        """Set JAVA_HOME from shutil.which('java') path."""
        from reversecore_mcp.core.ghidra_helper import _configure_ghidra_environment

        monkeypatch.delenv("JAVA_HOME", raising=False)
        with patch("shutil.which", return_value="/usr/lib/jvm/java-21/bin/java"):
            with patch.object(Path, "resolve", return_value=Path("/usr/lib/jvm/java-21/bin/java")):
                _configure_ghidra_environment()
                assert os.environ["JAVA_HOME"] == "/usr/lib/jvm/java-21"

    def test_java_not_found(self, monkeypatch):
        """Handle case where java is not in PATH."""
        from reversecore_mcp.core.ghidra_helper import _configure_ghidra_environment

        monkeypatch.delenv("JAVA_HOME", raising=False)
        with patch("shutil.which", return_value=None):
            _configure_ghidra_environment()
            assert "JAVA_HOME" not in os.environ


class TestResolveFunction:
    """Tests for _resolve_function."""

    def test_resolve_by_symbol(self):
        """Resolve function by symbol name."""
        from reversecore_mcp.core.ghidra_helper import _resolve_function

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

        result = _resolve_function(flat_api, "main")
        assert result == func

    def test_resolve_by_hex_address(self):
        """Resolve function by hex address."""
        from reversecore_mcp.core.ghidra_helper import _resolve_function

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

        result = _resolve_function(flat_api, "0x401000")
        assert result == func

    def test_resolve_function_containing(self):
        """Find function containing address when exact match fails."""
        from reversecore_mcp.core.ghidra_helper import _resolve_function

        symbols = MagicMock()
        symbols.hasNext.return_value = False

        symbol_table = MagicMock()
        symbol_table.getSymbols.return_value = symbols

        program = MagicMock()
        program.getSymbolTable.return_value = symbol_table

        func = MagicMock()
        function_manager = MagicMock()
        function_manager.getFunctionAt.return_value = None
        function_manager.getFunctionContaining.return_value = func
        program.getFunctionManager.return_value = function_manager

        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = program
        flat_api.toAddr.return_value = "addr_0x401005"

        result = _resolve_function(flat_api, "0x401005")
        assert result == func

    def test_resolve_not_found(self):
        """Return None when function is not found."""
        from reversecore_mcp.core.ghidra_helper import _resolve_function

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
        flat_api.toAddr.side_effect = lambda x: x

        result = _resolve_function(flat_api, "0x999999")
        assert result is None


class TestGetGhidraVersion:
    """Tests for get_ghidra_version."""

    def test_not_available(self):
        """Return None when pyghidra is not installed."""
        from reversecore_mcp.core.ghidra_helper import get_ghidra_version

        with patch.dict("sys.modules", {"pyghidra": None}):
            assert get_ghidra_version() is None


class TestDecompileFunction:
    """Tests for decompile_function_with_ghidra."""

    def test_pyghidra_not_installed(self):
        """Raise ImportError when pyghidra is not available."""
        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        with patch.dict("sys.modules", {"pyghidra": None}):
            with pytest.raises(ImportError, match="PyGhidra is not installed"):
                decompile_function_with_ghidra(Path("/tmp/test.bin"), "0x401000")

    def test_success(self):
        """Decompile function with mocked Ghidra classes."""
        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        pyghidra_mock = MagicMock()
        sys.modules["pyghidra"] = pyghidra_mock
        sys.modules["ghidra"] = MagicMock()
        sys.modules["ghidra.app"] = MagicMock()
        sys.modules["ghidra.app.decompiler"] = MagicMock()

        decomp_result_mock = MagicMock()
        decomp_result_mock.getDecompiledFunction.return_value.getC.return_value = "void main() {}"

        decompiler_mock = MagicMock()
        decompiler_mock.decompileFunction.return_value = decomp_result_mock

        DecompInterface = MagicMock()
        DecompInterface.return_value = decompiler_mock
        sys.modules["ghidra.app.decompiler"].DecompInterface = DecompInterface

        func_mock = MagicMock()
        func_mock.getName.return_value = "main"

        flat_api = MagicMock()
        program = MagicMock()
        flat_api.getCurrentProgram.return_value = program

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                ctx.__exit__ = MagicMock(return_value=False)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=func_mock,
                ):
                    code, meta = decompile_function_with_ghidra(Path("/tmp/test.bin"), "main")

        assert code == "void main() {}"
        assert meta["function_name"] == "main"


class TestRecoverStructures:
    """Tests for recover_structures_with_ghidra."""

    def test_pyghidra_not_installed(self):
        """Raise ImportError when pyghidra is not available."""
        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        with patch.dict("sys.modules", {"pyghidra": None}):
            with pytest.raises(ImportError, match="PyGhidra is not installed"):
                recover_structures_with_ghidra(Path("/tmp/test.bin"), "0x401000")

    def test_decompile_failed(self):
        """Raise ValidationError when decompilation fails."""
        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        sys.modules["ghidra"] = MagicMock()
        sys.modules["ghidra.app"] = MagicMock()
        sys.modules["ghidra.app.decompiler"] = MagicMock()
        sys.modules["ghidra.program"] = MagicMock()
        sys.modules["ghidra.program.model"] = MagicMock()
        sys.modules["ghidra.program.model.pcode"] = MagicMock()

        decomp_result = MagicMock()
        decomp_result.decompileCompleted.return_value = False
        decomp_result.getErrorMessage.return_value = "decompile error"

        DecompInterface = MagicMock()
        DecompInterface.return_value.decompileFunction.return_value = decomp_result
        sys.modules["ghidra.app.decompiler"].DecompInterface = DecompInterface

        func_mock = MagicMock()
        func_mock.getName.return_value = "main"

        flat_api = MagicMock()
        program = MagicMock()
        flat_api.getCurrentProgram.return_value = program

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                ctx.__exit__ = MagicMock(return_value=False)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=func_mock,
                ):
                    with pytest.raises(ValidationError, match="Structure analysis failed"):
                        recover_structures_with_ghidra(Path("/tmp/test.bin"), "main")


class TestConfigureGhidraEnvironmentExtended:
    """Extended tests for _configure_ghidra_environment error cases."""

    def test_java_home_resolve_exception(self):
        """Handle exception when resolving java_path."""
        from reversecore_mcp.core.ghidra_helper import _configure_ghidra_environment

        with patch.dict(os.environ, {}, clear=True):
            with patch("shutil.which", return_value="/usr/bin/java"):
                with patch.object(Path, "resolve", side_effect=Exception("resolve error")):
                    # Should log warning and not crash
                    _configure_ghidra_environment()
                    assert "JAVA_HOME" not in os.environ


class TestResolveFunctionExtended:
    """Extended tests for _resolve_function error cases."""

    def test_resolve_function_value_error(self):
        """Handle ValueError/Exception when converting address to int."""
        from reversecore_mcp.core.ghidra_helper import _resolve_function

        symbols = MagicMock()
        symbols.hasNext.return_value = False
        symbol_table = MagicMock()
        symbol_table.getSymbols.return_value = symbols

        program = MagicMock()
        program.getSymbolTable.return_value = symbol_table

        function_manager = MagicMock()
        program.getFunctionManager.return_value = function_manager

        flat_api = MagicMock()
        flat_api.getCurrentProgram.return_value = program
        # toAddr raises exception
        flat_api.toAddr.side_effect = Exception("invalid address")

        # Pass an address string that causes ValueError in int(..., 16) or exception in toAddr
        result = _resolve_function(flat_api, "invalid_hex_addr")
        assert result is None


class TestDecompileFunctionExtended:
    """Extended tests for decompile_function_with_ghidra error/exception cases."""

    def test_function_not_found(self):
        """Raise ValidationError when function is not resolved."""
        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        flat_api = MagicMock()

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=None,
                ):
                    with pytest.raises(ValidationError, match="Could not find function"):
                        decompile_function_with_ghidra(Path("/tmp/test.bin"), "0x401000")

    def test_decompilation_failed(self):
        """Raise ValidationError when results.decompileCompleted() is False."""
        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        sys.modules["ghidra.app.decompiler"] = MagicMock()

        decomp_result_mock = MagicMock()
        decomp_result_mock.decompileCompleted.return_value = False
        decomp_result_mock.getErrorMessage.return_value = "internal error"

        decompiler_mock = MagicMock()
        decompiler_mock.decompileFunction.return_value = decomp_result_mock
        sys.modules["ghidra.app.decompiler"].DecompInterface.return_value = decompiler_mock

        flat_api = MagicMock()
        func_mock = MagicMock()
        func_mock.getName.return_value = "main"

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=func_mock,
                ):
                    with pytest.raises(ValidationError, match="Decompilation failed"):
                        decompile_function_with_ghidra(Path("/tmp/test.bin"), "main")

    def test_decompilation_called_process_error_launchsupport(self):
        """Raise ValidationError when CalledProcessError is raised containing LaunchSupport."""
        import subprocess

        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        sys.modules["pyghidra"] = MagicMock()

        err = subprocess.CalledProcessError(1, "LaunchSupport.sh", output="LaunchSupport failed")

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager", side_effect=err):
                with pytest.raises(ValidationError, match="Ghidra failed to launch"):
                    decompile_function_with_ghidra(Path("/tmp/test.bin"), "main")

    def test_decompilation_called_process_error_other(self):
        """Re-raise CalledProcessError when it doesn't contain LaunchSupport."""
        import subprocess

        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        err = subprocess.CalledProcessError(1, "other_command", output="other failed")

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager", side_effect=err):
                with pytest.raises(subprocess.CalledProcessError):
                    decompile_function_with_ghidra(Path("/tmp/test.bin"), "main")

    def test_decompilation_generic_exception(self):
        """Re-raise other exceptions during decompilation."""
        from reversecore_mcp.core.ghidra_helper import decompile_function_with_ghidra

        sys.modules["pyghidra"] = MagicMock()

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch(
                "reversecore_mcp.core.ghidra_helper.get_ghidra_manager",
                side_effect=RuntimeError("generic error"),
            ):
                with pytest.raises(RuntimeError, match="generic error"):
                    decompile_function_with_ghidra(Path("/tmp/test.bin"), "main")


class TestGetGhidraVersionExtended:
    """Extended tests for get_ghidra_version."""

    def test_get_version_success(self):
        """Return the Ghidra version string when pyghidra starts successfully."""
        from reversecore_mcp.core.ghidra_helper import get_ghidra_version

        pyghidra_mock = MagicMock()
        sys.modules["pyghidra"] = pyghidra_mock

        ghidra_mock = MagicMock()
        ghidra_mock.framework.Application.getApplicationVersion.return_value = "11.0"
        sys.modules["ghidra"] = ghidra_mock

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            assert get_ghidra_version() == "11.0"


class TestRecoverStructuresExtended:
    """Extended tests for recover_structures_with_ghidra."""

    def test_recover_structures_function_not_found(self):
        """Raise ValidationError when function is not resolved for structure recovery."""
        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        flat_api = MagicMock()

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=None,
                ):
                    with pytest.raises(ValidationError, match="Could not find function"):
                        recover_structures_with_ghidra(Path("/tmp/test.bin"), "0x401000")

    def test_recover_structures_high_function_none(self):
        """Raise ValidationError when getHighFunction() returns None."""
        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        sys.modules["ghidra.app.decompiler"] = MagicMock()

        decomp_result = MagicMock()
        decomp_result.decompileCompleted.return_value = True
        decomp_result.getHighFunction.return_value = None

        decompiler = MagicMock()
        decompiler.decompileFunction.return_value = decomp_result
        sys.modules["ghidra.app.decompiler"].DecompInterface.return_value = decompiler

        flat_api = MagicMock()
        func_mock = MagicMock()
        func_mock.getName.return_value = "main"

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=func_mock,
                ):
                    with pytest.raises(ValidationError, match="Could not get high-level function"):
                        recover_structures_with_ghidra(Path("/tmp/test.bin"), "main")

    def test_recover_structures_success(self):
        """Verify successful structure recovery, field extraction and C-definition formatting."""
        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        sys.modules["ghidra.app.decompiler"] = MagicMock()
        sys.modules["ghidra.program.model.pcode"] = MagicMock()

        # Mock structures found in local variables
        symbol = MagicMock()
        high_var = MagicMock()

        actual_type = MagicMock()
        actual_type.getName.return_value = "struct my_struct"
        actual_type.getLength.return_value = 16
        actual_type.getNumComponents.return_value = (
            0  # No components to mock to avoid format errors
        )

        data_type = MagicMock()
        data_type.getName.return_value = "struct my_struct"
        data_type.getLength.return_value = 16
        data_type.getDataType.return_value = actual_type

        high_var.getDataType.return_value = data_type
        symbol.getHighVariable.return_value = high_var

        local_symbols = MagicMock()
        local_symbols.getNumSymbols.return_value = 1
        local_symbols.getSymbol.return_value = symbol

        high_func = MagicMock()
        high_func.getLocalSymbolMap.return_value = local_symbols

        decomp_result = MagicMock()
        decomp_result.decompileCompleted.return_value = True
        decomp_result.getHighFunction.return_value = high_func

        decompiler = MagicMock()
        decompiler.decompileFunction.return_value = decomp_result
        sys.modules["ghidra.app.decompiler"].DecompInterface.return_value = decompiler

        # Also mock parameters
        param = MagicMock()
        param_type = MagicMock()
        param_type.getName.return_value = "struct param_struct"
        param_type.getLength.return_value = 8
        param.getDataType.return_value = param_type

        # Mock functions field extraction
        comp = MagicMock()
        comp.getFieldName.return_value = "field_a"
        comp.getDataType.return_value.getName.return_value = "int"
        comp.getOffset.return_value = 0
        comp.getLength.return_value = 4
        param_type.getNumComponents.return_value = 1
        param_type.getComponent.return_value = comp

        func_mock = MagicMock()
        func_mock.getName.return_value = "main"
        func_mock.getParameters.return_value = [param]

        flat_api = MagicMock()

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager") as mock_mgr:
                ctx = MagicMock()
                ctx.__enter__ = MagicMock(return_value=flat_api)
                mock_mgr.return_value.context.return_value = ctx
                with patch(
                    "reversecore_mcp.core.ghidra_helper._resolve_function",
                    return_value=func_mock,
                ):
                    res, meta = recover_structures_with_ghidra(Path("/tmp/test.bin"), "main")

        assert res["count"] > 0
        assert meta["function_name"] == "main"

    def test_recover_structures_called_process_error_launchsupport(self):
        """Raise ValidationError when CalledProcessError is raised in structure recovery."""
        import subprocess

        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        err = subprocess.CalledProcessError(1, "LaunchSupport.sh", output="LaunchSupport failed")

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager", side_effect=err):
                with pytest.raises(ValidationError, match="Ghidra failed to launch"):
                    recover_structures_with_ghidra(Path("/tmp/test.bin"), "main")

    def test_recover_structures_called_process_error_other(self):
        """Re-raise other CalledProcessError in structure recovery."""
        import subprocess

        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()
        err = subprocess.CalledProcessError(1, "other_command")

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch("reversecore_mcp.core.ghidra_helper.get_ghidra_manager", side_effect=err):
                with pytest.raises(subprocess.CalledProcessError):
                    recover_structures_with_ghidra(Path("/tmp/test.bin"), "main")

    def test_recover_structures_generic_exception(self):
        """Re-raise generic Exception during structure recovery."""
        from reversecore_mcp.core.ghidra_helper import recover_structures_with_ghidra

        sys.modules["pyghidra"] = MagicMock()

        with patch("reversecore_mcp.core.ghidra_helper._configure_ghidra_environment"):
            with patch(
                "reversecore_mcp.core.ghidra_helper.get_ghidra_manager",
                side_effect=RuntimeError("recovery error"),
            ):
                with pytest.raises(RuntimeError, match="recovery error"):
                    recover_structures_with_ghidra(Path("/tmp/test.bin"), "main")
