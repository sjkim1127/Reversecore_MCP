
import pytest
from unittest.mock import MagicMock, patch, Mock
import sys
from pathlib import Path

# Mock modules before importing the module under test
mock_pyghidra = MagicMock()
mock_ghidra = MagicMock()
mock_ghidra_app_decompiler = MagicMock()
mock_ghidra_program_model_listing = MagicMock()
mock_ghidra_program_flatapi = MagicMock()
mock_ghidra_program_model_pcode = MagicMock()
mock_ghidra_framework = MagicMock()

sys.modules["pyghidra"] = mock_pyghidra
sys.modules["ghidra"] = mock_ghidra
sys.modules["ghidra.app.decompiler"] = mock_ghidra_app_decompiler
sys.modules["ghidra.program.model.listing"] = mock_ghidra_program_model_listing
sys.modules["ghidra.program.flatapi"] = mock_ghidra_program_flatapi
sys.modules["ghidra.program.model.pcode"] = mock_ghidra_program_model_pcode
sys.modules["ghidra.framework"] = mock_ghidra_framework

from reversecore_mcp.core import ghidra_helper
from reversecore_mcp.core.exceptions import ValidationError

class TestGhidraHelperMocked:
    
    def setup_method(self):
        # Reset mocks
        mock_pyghidra.reset_mock()
        mock_ghidra.reset_mock()
        mock_ghidra_app_decompiler.reset_mock()
        
        # Setup common mock objects
        self.flat_api = MagicMock()
        self.program = MagicMock()
        self.function_manager = MagicMock()
        self.symbol_table = MagicMock()
        self.decompiler = MagicMock()
        self.decompile_results = MagicMock()
        self.function = MagicMock()
        
        # Wire up the mocks
        mock_ghidra.framework = mock_ghidra_framework
        self.flat_api.getCurrentProgram.return_value = self.program
        self.program.getFunctionManager.return_value = self.function_manager
        self.program.getSymbolTable.return_value = self.symbol_table
        
        # Setup pyghidra.open_program context manager
        self.open_program_ctx = MagicMock()
        self.open_program_ctx.__enter__.return_value = self.flat_api
        mock_pyghidra.open_program.return_value = self.open_program_ctx
        
        # Setup DecompInterface
        mock_ghidra_app_decompiler.DecompInterface.return_value = self.decompiler
        self.decompiler.decompileFunction.return_value = self.decompile_results
        
    def test_ensure_ghidra_available(self):
        assert ghidra_helper.ensure_ghidra_available() is True
        
    def test_get_ghidra_version(self):
        mock_ghidra_framework.Application.getApplicationVersion.return_value = "10.1.2"
        version = ghidra_helper.get_ghidra_version()
        assert version == "10.1.2"
        mock_pyghidra.start.assert_called_once()

    def test_get_ghidra_version_error(self):
        mock_pyghidra.start.side_effect = Exception("Start failed")
        version = ghidra_helper.get_ghidra_version()
        assert version is None

    def test_resolve_function_by_symbol(self):
        # Setup symbol found
        mock_symbol = MagicMock()
        mock_symbol.getAddress.return_value = "ADDRESS_OBJ"
        
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = True
        mock_iterator.next.return_value = mock_symbol
        
        self.symbol_table.getSymbols.return_value = mock_iterator
        self.function_manager.getFunctionAt.return_value = self.function
        
        result = ghidra_helper._resolve_function(self.flat_api, "main")
        
        assert result == self.function
        self.symbol_table.getSymbols.assert_called_with("main")
        self.function_manager.getFunctionAt.assert_called_with("ADDRESS_OBJ")

    def test_resolve_function_by_hex_address(self):
        # Setup symbol not found
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = False
        self.symbol_table.getSymbols.return_value = mock_iterator
        
        # Setup address parsing
        self.flat_api.toAddr.return_value = "ADDRESS_OBJ"
        self.function_manager.getFunctionAt.return_value = self.function
        
        result = ghidra_helper._resolve_function(self.flat_api, "0x401000")
        
        assert result == self.function
        self.flat_api.toAddr.assert_called_with(0x401000)
        self.function_manager.getFunctionAt.assert_called_with("ADDRESS_OBJ")

    def test_resolve_function_containing_address(self):
        # Setup symbol not found
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = False
        self.symbol_table.getSymbols.return_value = mock_iterator
        
        # Setup address parsing
        self.flat_api.toAddr.return_value = "ADDRESS_OBJ"
        
        # First attempt fails
        self.function_manager.getFunctionAt.return_value = None
        # Second attempt succeeds
        self.function_manager.getFunctionContaining.return_value = self.function
        
        result = ghidra_helper._resolve_function(self.flat_api, "0x401000")
        
        assert result == self.function
        self.function_manager.getFunctionContaining.assert_called_with("ADDRESS_OBJ")

    def test_resolve_function_not_found(self):
        # Setup symbol not found
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = False
        self.symbol_table.getSymbols.return_value = mock_iterator
        
        # Setup address parsing failure
        self.flat_api.toAddr.side_effect = ValueError("Invalid address")
        
        result = ghidra_helper._resolve_function(self.flat_api, "invalid")
        
        assert result is None

    def test_decompile_function_with_ghidra_success(self):
        # Setup function resolution
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = True
        mock_iterator.next.return_value = MagicMock()
        self.symbol_table.getSymbols.return_value = mock_iterator
        self.function_manager.getFunctionAt.return_value = self.function
        
        # Setup function details
        self.function.getName.return_value = "main"
        self.function.getEntryPoint.return_value = "0x401000"
        self.function.getSignature().getPrototypeString.return_value = "int main()"
        self.function.getBody().getNumAddresses.return_value = 100
        
        # Setup decompile results
        self.decompile_results.decompileCompleted.return_value = True
        mock_decompiled_func = MagicMock()
        mock_decompiled_func.getC.return_value = "int main() { return 0; }"
        self.decompile_results.getDecompiledFunction.return_value = mock_decompiled_func
        
        mock_high_func = MagicMock()
        mock_high_func.getFunctionPrototype().getNumParams.return_value = 0
        mock_high_func.getLocalSymbolMap().getNumSymbols.return_value = 2
        self.decompile_results.getHighFunction.return_value = mock_high_func
        
        code, metadata = ghidra_helper.decompile_function_with_ghidra(Path("test.exe"), "main")
        
        assert code == "int main() { return 0; }"
        assert metadata["function_name"] == "main"
        assert metadata["decompiler"] == "ghidra"
        assert metadata["parameter_count"] == 0
        assert metadata["local_symbol_count"] == 2
        
        self.decompiler.dispose.assert_called_once()

    def test_decompile_function_with_ghidra_function_not_found(self):
        # Setup function resolution failure
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = False
        self.symbol_table.getSymbols.return_value = mock_iterator
        self.flat_api.toAddr.side_effect = ValueError()
        
        with pytest.raises(ValidationError) as exc:
            ghidra_helper.decompile_function_with_ghidra(Path("test.exe"), "unknown")
        
        assert "Could not find function" in str(exc.value)

    def test_decompile_function_with_ghidra_decompilation_failed(self):
        # Setup function resolution
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = True
        self.symbol_table.getSymbols.return_value = mock_iterator
        self.function_manager.getFunctionAt.return_value = self.function
        
        # Setup decompile failure
        self.decompile_results.decompileCompleted.return_value = False
        self.decompile_results.getErrorMessage.return_value = "Decompilation error"
        
        with pytest.raises(ValidationError) as exc:
            ghidra_helper.decompile_function_with_ghidra(Path("test.exe"), "main")
            
        assert "Decompilation failed" in str(exc.value)
        self.decompiler.dispose.assert_called_once()

    def test_recover_structures_with_ghidra_success(self):
        # Setup function resolution
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = True
        self.symbol_table.getSymbols.return_value = mock_iterator
        self.function_manager.getFunctionAt.return_value = self.function
        self.function.getName.return_value = "process_struct"
        
        # Setup decompile results
        self.decompile_results.decompileCompleted.return_value = True
        mock_high_func = MagicMock()
        self.decompile_results.getHighFunction.return_value = mock_high_func
        
        # Setup local symbols with structure
        mock_symbol_map = MagicMock()
        mock_high_func.getLocalSymbolMap.return_value = mock_symbol_map
        mock_symbol_map.getNumSymbols.return_value = 1
        
        mock_symbol = MagicMock()
        mock_symbol_map.getSymbol.return_value = mock_symbol
        
        mock_high_var = MagicMock()
        mock_symbol.getHighVariable.return_value = mock_high_var
        
        mock_data_type = MagicMock()
        mock_high_var.getDataType.return_value = mock_data_type
        mock_data_type.getName.return_value = "MyStruct *"
        mock_data_type.getLength.return_value = 8
        mock_data_type.getDataType.return_value = mock_data_type # Dereference
        
        # Setup structure components
        mock_data_type.getNumComponents.return_value = 1
        mock_component = MagicMock()
        mock_data_type.getComponent.return_value = mock_component
        mock_component.getFieldName.return_value = "field1"
        mock_component.getDataType().getName.return_value = "int"
        mock_component.getOffset.return_value = 0
        mock_component.getLength.return_value = 4
        
        # Setup parameters
        self.function.getParameters.return_value = []
        
        result, metadata = ghidra_helper.recover_structures_with_ghidra(Path("test.exe"), "process_struct")
        
        assert result["count"] == 1
        assert "MyStruct *" in result["structures"][0]["name"]
        assert result["structures"][0]["fields"][0]["name"] == "field1"
        assert "struct MyStruct * {" in result["c_definitions"]

    def test_recover_structures_with_ghidra_no_high_function(self):
        # Setup function resolution
        mock_iterator = MagicMock()
        mock_iterator.hasNext.return_value = True
        self.symbol_table.getSymbols.return_value = mock_iterator
        self.function_manager.getFunctionAt.return_value = self.function
        
        # Setup decompile results
        self.decompile_results.decompileCompleted.return_value = True
        self.decompile_results.getHighFunction.return_value = None
        
        with pytest.raises(ValidationError) as exc:
            ghidra_helper.recover_structures_with_ghidra(Path("test.exe"), "main")
            
        assert "Could not get high-level function" in str(exc.value)

