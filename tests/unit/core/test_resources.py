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

        with (
            patch.object(Path, "exists", return_value=True),
            patch("builtins.open", mock_file),
        ):
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

        with patch(
            "reversecore_mcp.tools.static_analysis.run_strings",
            return_value=mock_result,
        ):
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

        with patch(
            "reversecore_mcp.tools.static_analysis.run_strings",
            return_value=mock_result,
        ):
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
                "reversecore_mcp.tools.malware.ioc_tools.extract_iocs",
                return_value=mock_ioc_result,
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

        with patch("reversecore_mcp.resources.r2_decompile", return_value=mock_result):
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
            "reversecore_mcp.tools.r2_analysis.generate_function_graph",
            return_value=mock_result,
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
            patch(
                "reversecore_mcp.tools.r2_analysis.run_radare2",
                return_value=mock_result,
            ),
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
            "reversecore_mcp.tools.dormant_detector.dormant_detector",
            return_value=mock_result,
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
            "reversecore_mcp.tools.dormant_detector.dormant_detector",
            return_value=mock_result,
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
            "reversecore_mcp.tools.static_analysis.run_strings",
            side_effect=Exception("Test error"),
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

        with patch(
            "reversecore_mcp.tools.static_analysis.run_strings",
            return_value=mock_result,
        ):
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

        with patch("reversecore_mcp.resources.r2_decompile", return_value=mock_result):
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
            "reversecore_mcp.tools.r2_analysis.generate_function_graph",
            return_value=mock_result,
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

    @pytest.mark.asyncio
    async def test_get_binary_metadata_success(self, mock_mcp):
        """Test binary metadata resource success."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        metadata_func = registered_funcs.get("reversecore://{filename}/metadata")
        info_func = registered_funcs.get("reversecore://{filename}/info")
        assert metadata_func is not None
        assert info_func is not None

        mock_lief_res = Mock()
        mock_lief_res.status = "success"
        mock_lief_res.data = {
            "format": "ELF",
            "entry_point": "0x401000",
            "mitigations": {"nx": True, "pie": True, "canary": False, "relro": "Full"},
            "sections": [{"name": ".text"}],
        }

        mock_packer_res = Mock()
        mock_packer_res.status = "success"
        mock_packer_res.data = {
            "file_type": "ELF64",
            "arch": "x64",
            "packer": "UPX",
            "compiler": "GCC",
        }

        mock_hashes = {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ssdeep": "N/A",
        }

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.elf",
            ),
            patch(
                "reversecore_mcp.resources._calculate_file_hashes",
                return_value=mock_hashes,
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
            patch(
                "reversecore_mcp.tools.analysis.die_tools.detect_packer",
                return_value=mock_packer_res,
            ),
        ):
            result = await metadata_func("sample.elf")
            assert "# 📋 Binary Metadata: sample.elf" in result
            assert "ELF" in result
            assert "0x401000" in result
            assert "UPX" in result
            assert "GCC" in result
            assert "d41d8cd98f00b204e9800998ecf8427e" in result

            info_result = await info_func("sample.elf")
            assert "# 📋 Binary Metadata: sample.elf" in info_result

    @pytest.mark.asyncio
    async def test_get_binary_metadata_error(self, mock_mcp):
        """Test binary metadata resource error handling."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        metadata_func = registered_funcs.get("reversecore://{filename}/metadata")
        assert metadata_func is not None

        with patch(
            "reversecore_mcp.resources._get_workspace_path",
            side_effect=Exception("File not found"),
        ):
            result = await metadata_func("missing.bin")
            assert "Error extracting metadata" in result

    @pytest.mark.asyncio
    async def test_get_function_xrefs_success(self, mock_mcp):
        """Test function xrefs resource success."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        xrefs_func = registered_funcs.get("reversecore://{filename}/func/{address}/xrefs")
        assert xrefs_func is not None

        mock_res = Mock()
        mock_res.status = "success"
        mock_res.data = {
            "xrefs_to": [{"from": "0x401050", "type": "call", "fcn_name": "entry0"}],
            "xrefs_from": [{"addr": "0x401200", "type": "call", "fcn_name": "printf"}],
            "total_refs_to": 1,
            "total_refs_from": 1,
        }

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/test.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.analyze_xrefs",
                return_value=mock_res,
            ),
        ):
            result = await xrefs_func("test.exe", "main")
            assert "# 🔄 Cross-References: test.exe @ main" in result
            assert "0x401050" in result
            assert "entry0" in result
            assert "0x401200" in result
            assert "printf" in result

    @pytest.mark.asyncio
    async def test_get_function_xrefs_error(self, mock_mcp):
        """Test function xrefs resource error handling."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        xrefs_func = registered_funcs.get("reversecore://{filename}/func/{address}/xrefs")
        assert xrefs_func is not None

        mock_res = Mock()
        mock_res.status = "error"
        mock_res.message = "Invalid address"

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/test.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.analyze_xrefs",
                return_value=mock_res,
            ),
        ):
            result = await xrefs_func("test.exe", "invalid_addr")
            assert "Error analyzing cross-references" in result

    @pytest.mark.asyncio
    async def test_get_function_context_success(self, mock_mcp):
        """Test function context resource success."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        ctx_func = registered_funcs.get("reversecore://{filename}/func/{address}/context")
        assert ctx_func is not None

        mock_fn_res = Mock()
        mock_fn_res.status = "success"
        mock_fn_res.data = {
            "name": "sym.decrypt",
            "offset": "0x401120",
            "size": 128,
            "complexity": 4,
            "nbbs": 3,
            "edges": 4,
            "signature": "int sym.decrypt(char *buf, int len)",
            "calltype": "cdecl",
        }

        mock_struct_res = Mock()
        mock_struct_res.status = "success"
        mock_struct_res.data = {
            "structures": [{"name": "key_ptr", "type": "char *", "offset": "-0x8", "size": 8}]
        }

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/test.exe",
            ),
            patch(
                "reversecore_mcp.resources.r2_analyze_function",
                return_value=mock_fn_res,
            ),
            patch(
                "reversecore_mcp.resources.r2_recover_structures",
                return_value=mock_struct_res,
            ),
        ):
            result = await ctx_func("test.exe", "0x401120")
            assert "# 🧩 Function Context: test.exe @ 0x401120" in result
            assert "int sym.decrypt(char *buf, int len)" in result
            assert "Cyclomatic Complexity**: 4" in result
            assert "key_ptr" in result

    @pytest.mark.asyncio
    async def test_get_function_context_error(self, mock_mcp):
        """Test function context resource error handling."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        ctx_func = registered_funcs.get("reversecore://{filename}/func/{address}/context")
        assert ctx_func is not None

        mock_fn_res = Mock()
        mock_fn_res.status = "error"
        mock_fn_res.message = "Function not found"

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/test.exe",
            ),
            patch(
                "reversecore_mcp.resources.r2_analyze_function",
                return_value=mock_fn_res,
            ),
            patch(
                "reversecore_mcp.resources.r2_recover_structures",
                return_value=Mock(status="error"),
            ),
        ):
            result = await ctx_func("test.exe", "invalid_func")
            assert "Error analyzing function" in result

    @pytest.mark.asyncio
    async def test_get_memory_map_success(self, mock_mcp):
        """Test memory map resource success."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        mem_func = registered_funcs.get("reversecore://{filename}/memory_map")
        sec_func = registered_funcs.get("reversecore://{filename}/sections")
        assert mem_func is not None
        assert sec_func is not None

        mock_lief_res = Mock()
        mock_lief_res.status = "success"
        mock_lief_res.data = {
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": "0x401000",
                    "size": 4096,
                    "entropy": 6.2,
                },
                {
                    "name": ".upx0",
                    "virtual_address": "0x402000",
                    "size": 8192,
                    "entropy": 7.85,
                },
            ]
        }

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/test.exe",
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await mem_func("test.exe")
            assert "# 🗺️ Memory Map & Section Table: test.exe" in result
            assert ".text" in result
            assert ".upx0" in result
            assert "High Entropy (>7.0)" in result

            sec_result = await sec_func("test.exe")
            assert "# 🗺️ Memory Map & Section Table: test.exe" in sec_result

    @pytest.mark.asyncio
    async def test_get_memory_map_error(self, mock_mcp):
        """Test memory map resource error handling."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        mem_func = registered_funcs.get("reversecore://{filename}/memory_map")
        assert mem_func is not None

        mock_lief_res = Mock()
        mock_lief_res.status = "error"
        mock_lief_res.message = "Failed to parse ELF headers"

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/test.exe",
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await mem_func("test.exe")
            assert "Error parsing sections" in result

    @pytest.mark.asyncio
    async def test_get_signatures_report_success(self, mock_mcp):
        """Test threat signatures report resource success."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        sig_func = registered_funcs.get("reversecore://{filename}/signatures")
        assert sig_func is not None

        mock_yara = Mock()
        mock_yara.status = "success"
        mock_yara.data = {"matches": [{"rule": "Ransomware_LockBit", "tags": ["ransomware"]}]}

        mock_capa = Mock()
        mock_capa.status = "success"
        mock_capa.data = {
            "capabilities": ["encrypt data using AES"],
            "mitre_attack": ["T1486 Data Encrypted for Impact"],
        }

        mock_dd = Mock()
        mock_dd.status = "success"
        mock_dd.data = {
            "orphan_functions": [{"name": "hidden_shellcode"}],
            "suspicious_logic": [],
        }

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/malware.exe",
            ),
            patch(
                "reversecore_mcp.tools.malware.yara_tools.run_yara",
                return_value=mock_yara,
            ),
            patch(
                "reversecore_mcp.tools.analysis.capa_tools.run_capa",
                return_value=mock_capa,
            ),
            patch(
                "reversecore_mcp.tools.malware.dormant_detector.dormant_detector",
                return_value=mock_dd,
            ),
        ):
            result = await sig_func("malware.exe")
            assert "# 🛡️ Threat Signatures & Capabilities: malware.exe" in result
            assert "Ransomware_LockBit" in result
            assert "encrypt data using AES" in result
            assert "T1486" in result
            assert "orphan function" in result

    @pytest.mark.asyncio
    async def test_get_signatures_report_error(self, mock_mcp):
        """Test threat signatures report error handling."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        sig_func = registered_funcs.get("reversecore://{filename}/signatures")
        assert sig_func is not None

        with patch(
            "reversecore_mcp.resources._get_workspace_path",
            side_effect=Exception("Disk read error"),
        ):
            result = await sig_func("corrupt.bin")
            assert "Error extracting signatures" in result

    @pytest.mark.asyncio
    async def test_get_imports_success_and_sensitive_tagging(self, mock_mcp):
        """Test imports resource with API sensitivity classification."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        imports_func = registered_funcs.get("reversecore://{filename}/imports")
        assert imports_func is not None

        mock_r2_res = Mock()
        mock_r2_res.status = "success"
        mock_r2_res.data = (
            '[{"libname": "kernel32.dll", "name": "VirtualAllocEx"}, '
            '{"libname": "kernel32.dll", "name": "LoadLibraryA"}, '
            '{"libname": "ws2_32.dll", "name": "connect"}]'
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
        ):
            result = await imports_func("sample.exe")
            assert "# 📥 Imported Libraries & Functions: sample.exe" in result
            assert "kernel32.dll" in result
            assert "VirtualAllocEx" in result
            assert "[!] Process Injection" in result
            assert "LoadLibraryA" in result
            assert "[!] Dynamic Loading" in result
            assert "ws2_32.dll" in result
            assert "[!] Network/C2" in result

    @pytest.mark.asyncio
    async def test_get_imports_empty(self, mock_mcp):
        """Test imports resource when binary has no imports."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        imports_func = registered_funcs.get("reversecore://{filename}/imports")
        assert imports_func is not None

        mock_r2_res = Mock()
        mock_r2_res.status = "success"
        mock_r2_res.data = "[]"

        mock_lief_res = Mock()
        mock_lief_res.status = "success"
        mock_lief_res.data = {"imports": []}

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await imports_func("sample.exe")
            assert "No imported functions found" in result

    @pytest.mark.asyncio
    async def test_get_exports_success(self, mock_mcp):
        """Test exports resource success."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        exports_func = registered_funcs.get("reversecore://{filename}/exports")
        assert exports_func is not None

        mock_r2_res = Mock()
        mock_r2_res.status = "success"
        mock_r2_res.data = '[{"ordinal": 1, "vaddr": "0x10001234", "name": "ExportedFunction"}]'

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.dll",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
        ):
            result = await exports_func("sample.dll")
            assert "# 📤 Exported Symbols: sample.dll" in result
            assert "ExportedFunction" in result
            assert "0x10001234" in result

    @pytest.mark.asyncio
    async def test_get_exports_empty(self, mock_mcp):
        """Test exports resource when binary has no exports."""
        registered_funcs = {}

        def capture_resource(uri, **kwargs):
            def decorator(func):
                registered_funcs[uri] = func
                return func

            return decorator

        mock_mcp.resource = capture_resource
        register_resources(mock_mcp)

        exports_func = registered_funcs.get("reversecore://{filename}/exports")
        assert exports_func is not None

        mock_r2_res = Mock()
        mock_r2_res.status = "success"
        mock_r2_res.data = "[]"

        mock_lief_res = Mock()
        mock_lief_res.status = "success"
        mock_lief_res.data = {"exports": []}

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await exports_func("sample.exe")
            assert "No exported symbols found in binary" in result
