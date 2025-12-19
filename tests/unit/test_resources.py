"""Unit tests for resources module."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from reversecore_mcp.resources import register_resources


class TestStaticResources:
    """Test static resource registration and retrieval."""

    @pytest.fixture
    def mock_mcp(self):
        """Create a mock FastMCP instance."""
        mcp = Mock()
        mcp.resource = Mock()
        return mcp

    def test_register_resources_called(self, mock_mcp):
        """Test that register_resources registers handlers with MCP."""
        register_resources(mock_mcp)

        # Should register at least the static resources
        assert mock_mcp.resource.call_count >= 3

    @patch("reversecore_mcp.resources._get_resources_path")
    def test_get_guide_exists(self, mock_get_resources_path, mock_mcp):
        """Test guide resource when file exists."""
        # Setup
        mock_guide_path = Mock()
        mock_guide_path.exists.return_value = True
        mock_guide_path.read_text.return_value = "# Test Guide Content"

        mock_resources_path = Mock()
        mock_resources_path.__truediv__ = Mock(return_value=mock_guide_path)
        mock_get_resources_path.return_value = mock_resources_path

        # Capture the registered function
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        # Test the guide function
        guide_func = registered_funcs.get("reversecore://guide")
        assert guide_func is not None

        result = guide_func()
        assert "# Test Guide Content" in result

    @patch("reversecore_mcp.resources._get_resources_path")
    def test_get_guide_not_found(self, mock_get_resources_path, mock_mcp):
        """Test guide resource when file doesn't exist."""
        # Setup
        mock_path = Mock()
        mock_path.__truediv__ = Mock(return_value=mock_path)
        mock_path.exists.return_value = False
        mock_get_resources_path.return_value = mock_path

        # Capture the registered function
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        # Test the guide function
        guide_func = registered_funcs.get("reversecore://guide")
        assert guide_func is not None

        result = guide_func()
        assert result == "Guide not found."

    def test_get_structure_guide(self, mock_mcp):
        """Test structure guide resource."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        structure_func = registered_funcs.get("reversecore://guide/structures")
        assert structure_func is not None

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "read_text", return_value="# Structure Guide"),
        ):
            result = structure_func()
            assert "# Structure Guide" in result

    def test_get_logs_exists(self, mock_mcp):
        """Test logs resource when log file exists."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        logs_func = registered_funcs.get("reversecore://logs")
        assert logs_func is not None

        # Mock log file with 150 lines (each line has newline)
        log_lines = [f"Log line {i}\n" for i in range(150)]

        # Mock the open function to simulate file reading
        from unittest.mock import mock_open

        mock_file = mock_open(read_data="".join(log_lines))

        with patch.object(Path, "exists", return_value=True), patch("builtins.open", mock_file):
            result = logs_func()
            # Should return last 100 lines with newlines
            result_lines = result.split("\n")
            # Filter out empty strings from split
            non_empty_lines = [line for line in result_lines if line]
            assert len(non_empty_lines) == 100
            assert "Log line 149" in result

    def test_get_logs_not_found(self, mock_mcp):
        """Test logs resource when log file doesn't exist."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        logs_func = registered_funcs.get("reversecore://logs")
        assert logs_func is not None

        with patch.object(Path, "exists", return_value=False):
            result = logs_func()
            assert result == "No logs found."

    def test_get_logs_error_handling(self, mock_mcp):
        """Test logs resource error handling."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        logs_func = registered_funcs.get("reversecore://logs")
        assert logs_func is not None

        # Mock open to raise an error
        with (
            patch.object(Path, "exists", return_value=True),
            patch("builtins.open", side_effect=OSError("Permission denied")),
        ):
            result = logs_func()
            assert "Error reading logs" in result
            assert "Permission denied" in result


class TestDynamicResources:
    """Test dynamic resource registration for binary analysis."""

    @pytest.fixture
    def mock_mcp(self):
        """Create a mock FastMCP instance."""
        mcp = Mock()
        mcp.resource = Mock()
        return mcp

    @pytest.mark.asyncio
    async def test_get_file_strings_success(self, mock_mcp):
        """Test file strings resource with successful extraction."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        strings_func = registered_funcs.get("reversecore://{filename}/strings")
        assert strings_func is not None

        # Mock the tool result
        mock_result = Mock()
        mock_result.status = "success"
        mock_result.data = "String1\nString2\nString3"
        mock_result.content = [Mock(text="String1\nString2\nString3")]

        with patch("reversecore_mcp.tools.static_analysis.run_strings", return_value=mock_result):
            result = await strings_func("test.exe")
            assert "# Strings from test.exe" in result
            assert "String1" in result

    @pytest.mark.asyncio
    async def test_get_file_strings_error(self, mock_mcp):
        """Test file strings resource with error."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        strings_func = registered_funcs.get("reversecore://{filename}/strings")
        assert strings_func is not None

        # Mock the tool result with error
        mock_result = Mock()
        mock_result.status = "error"
        mock_result.message = "File not found"

        with patch("reversecore_mcp.tools.static_analysis.run_strings", return_value=mock_result):
            result = await strings_func("missing.exe")
            assert "Error extracting strings" in result

    @pytest.mark.asyncio
    async def test_get_file_iocs_success(self, mock_mcp):
        """Test IOC extraction resource with success."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        iocs_func = registered_funcs.get("reversecore://{filename}/iocs")
        assert iocs_func is not None

        # Mock successful string extraction
        mock_strings_result = Mock()
        mock_strings_result.status = "success"
        mock_strings_result.data = "http://malicious.com\n192.168.1.1\ntest@example.com"
        mock_strings_result.content = [
            Mock(text="http://malicious.com\n192.168.1.1\ntest@example.com")
        ]

        # Mock successful IOC extraction
        mock_ioc_result = Mock()
        mock_ioc_result.status = "success"
        mock_ioc_result.data = {
            "ipv4": ["192.168.1.1"],
            "urls": ["http://malicious.com"],
            "emails": ["test@example.com"],
        }

        with (
            patch(
                "reversecore_mcp.tools.static_analysis.run_strings",
                return_value=mock_strings_result,
            ),
            patch(
                "reversecore_mcp.tools.malware.ioc_tools.extract_iocs", return_value=mock_ioc_result
            ),
        ):
            result = await iocs_func("malware.exe")
            assert "# IOC Report for malware.exe" in result
            # Check that IOCs appear in the proper list format (not just as substring)
            assert "- 192.168.1.1" in result
            assert "- http://malicious.com" in result
            assert "- test@example.com" in result

    @pytest.mark.asyncio
    async def test_get_decompiled_code_success(self, mock_mcp):
        """Test decompiled code resource."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        code_func = registered_funcs.get("reversecore://{filename}/func/{address}/code")
        assert code_func is not None

        # Mock successful decompilation
        mock_result = Mock()
        mock_result.status = "success"
        mock_result.data = "int main() {\n  return 0;\n}"
        mock_result.content = [Mock(text="int main() {\n  return 0;\n}")]

        with patch("reversecore_mcp.tools.decompilation.smart_decompile", return_value=mock_result):
            result = await code_func("test.exe", "main")
            assert "# Decompiled Code: test.exe @ main" in result
            assert "int main()" in result

    @pytest.mark.asyncio
    async def test_get_disassembly_success(self, mock_mcp):
        """Test disassembly resource."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        asm_func = registered_funcs.get("reversecore://{filename}/func/{address}/asm")
        assert asm_func is not None

        # Mock successful disassembly
        mock_result = Mock()
        mock_result.status = "success"
        mock_result.data = "push rbp\nmov rbp, rsp"
        mock_result.content = [Mock(text="push rbp\nmov rbp, rsp")]

        with patch("reversecore_mcp.tools.r2_analysis.run_radare2", return_value=mock_result):
            result = await asm_func("test.exe", "main")
            assert "# Disassembly: test.exe @ main" in result
            assert "push rbp" in result

    @pytest.mark.asyncio
    async def test_get_function_cfg_success(self, mock_mcp):
        """Test CFG resource."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        cfg_func = registered_funcs.get("reversecore://{filename}/func/{address}/cfg")
        assert cfg_func is not None

        # Mock successful CFG generation
        mock_result = Mock()
        mock_result.status = "success"
        mock_result.data = "graph TD\nA-->B"
        mock_result.content = [Mock(text="graph TD\nA-->B")]

        with patch(
            "reversecore_mcp.tools.r2_analysis.generate_function_graph", return_value=mock_result
        ):
            result = await cfg_func("test.exe", "main")
            assert "# Control Flow Graph: test.exe @ main" in result
            assert "graph TD" in result

    @pytest.mark.asyncio
    async def test_get_function_list_success(self, mock_mcp):
        """Test function list resource."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        func_list = registered_funcs.get("reversecore://{filename}/functions")
        assert func_list is not None

        # Mock successful function listing
        functions_json = [
            {"name": "main", "offset": 0x1000, "size": 100},
            {"name": "func1", "offset": 0x1100, "size": 50},
        ]
        mock_result = Mock()
        mock_result.status = "success"
        mock_result.data = str(functions_json)
        mock_result.content = [Mock(text=str(functions_json))]

        with (
            patch("reversecore_mcp.tools.r2_analysis.run_radare2", return_value=mock_result),
            patch("reversecore_mcp.resources.json.loads", return_value=functions_json),
        ):
            result = await func_list("test.exe")
            assert "# Functions in test.exe" in result
            assert "Total functions: 2" in result

    @pytest.mark.asyncio
    async def test_get_dormant_detector_report_success(self, mock_mcp):
        """Test dormant detector report resource."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        dormant_func = registered_funcs.get("reversecore://{filename}/dormant_detector")
        assert dormant_func is not None

        # Mock dormant detector result
        mock_result = Mock()
        mock_result.status = "success"
        mock_result.data = {
            "orphan_functions": [
                {"name": "orphan1", "address": "0x401000", "size": 100, "xrefs": 0}
            ],
            "suspicious_logic": [
                {
                    "function": "suspicious1",
                    "address": "0x402000",
                    "instruction": "cmp eax, 0xdeadbeef",
                    "reason": "Magic values",
                }
            ],
        }

        with patch(
            "reversecore_mcp.tools.dormant_detector.dormant_detector", return_value=mock_result
        ):
            result = await dormant_func("test.exe")
            assert "Dormant Detector" in result
            assert "Orphan Functions" in result

    @pytest.mark.asyncio
    async def test_get_dormant_detector_report_failure(self, mock_mcp):
        """Test dormant detector report resource when it fails."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        dormant_func = registered_funcs.get("reversecore://{filename}/dormant_detector")
        assert dormant_func is not None

        # Mock dormant detector failure
        mock_result = Mock()
        mock_result.status = "error"
        mock_result.message = "Analysis failed"

        with patch(
            "reversecore_mcp.tools.dormant_detector.dormant_detector", return_value=mock_result
        ):
            result = await dormant_func("test.exe")
            assert "Dormant Detector analysis failed" in result

    @pytest.mark.asyncio
    async def test_get_file_strings_exception(self, mock_mcp):
        """Test file strings resource with exception."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        strings_func = registered_funcs.get("reversecore://{filename}/strings")
        assert strings_func is not None

        with patch(
            "reversecore_mcp.tools.static_analysis.run_strings", side_effect=Exception("Test error")
        ):
            result = await strings_func("test.exe")
            assert "Error:" in result

    @pytest.mark.asyncio
    async def test_get_file_iocs_strings_failure(self, mock_mcp):
        """Test IOC extraction when string extraction fails."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        iocs_func = registered_funcs.get("reversecore://{filename}/iocs")
        assert iocs_func is not None

        # Mock failed string extraction
        mock_result = Mock()
        mock_result.status = "error"

        with patch("reversecore_mcp.tools.static_analysis.run_strings", return_value=mock_result):
            result = await iocs_func("test.exe")
            assert "Failed to extract strings" in result

    @pytest.mark.asyncio
    async def test_get_decompiled_code_error(self, mock_mcp):
        """Test decompiled code resource with error."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        code_func = registered_funcs.get("reversecore://{filename}/func/{address}/code")
        assert code_func is not None

        # Mock decompilation error
        mock_result = Mock()
        mock_result.status = "error"
        mock_result.message = "Decompilation failed"

        with patch("reversecore_mcp.tools.decompilation.smart_decompile", return_value=mock_result):
            result = await code_func("test.exe", "main")
            assert "Error decompiling" in result

    @pytest.mark.asyncio
    async def test_get_disassembly_error(self, mock_mcp):
        """Test disassembly resource with error."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        asm_func = registered_funcs.get("reversecore://{filename}/func/{address}/asm")
        assert asm_func is not None

        # Mock disassembly error
        mock_result = Mock()
        mock_result.status = "error"
        mock_result.message = "Disassembly failed"

        with patch("reversecore_mcp.tools.r2_analysis.run_radare2", return_value=mock_result):
            result = await asm_func("test.exe", "main")
            assert "Error disassembling" in result

    @pytest.mark.asyncio
    async def test_get_function_cfg_error(self, mock_mcp):
        """Test CFG resource with error."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        cfg_func = registered_funcs.get("reversecore://{filename}/func/{address}/cfg")
        assert cfg_func is not None

        # Mock CFG generation error
        mock_result = Mock()
        mock_result.status = "error"
        mock_result.message = "CFG generation failed"

        with patch(
            "reversecore_mcp.tools.r2_analysis.generate_function_graph", return_value=mock_result
        ):
            result = await cfg_func("test.exe", "main")
            assert "Error generating CFG" in result

    @pytest.mark.asyncio
    async def test_get_function_list_error(self, mock_mcp):
        """Test function list resource with error."""
        registered_funcs = {}

        def capture_resource(uri):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        func_list = registered_funcs.get("reversecore://{filename}/functions")
        assert func_list is not None

        # Mock function listing error
        mock_result = Mock()
        mock_result.status = "error"
        mock_result.message = "Failed to list functions"

        with patch("reversecore_mcp.tools.r2_analysis.run_radare2", return_value=mock_result):
            result = await func_list("test.exe")
            assert "Error listing functions" in result
