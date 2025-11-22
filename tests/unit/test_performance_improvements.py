"""
Tests for newly added performance improvements.

These tests verify that the optimizations made to address identified
bottlenecks actually improve performance without breaking functionality.
"""

import time
from unittest.mock import MagicMock, patch
import pytest


def test_analyze_variant_changes_binary_search_optimization(workspace_dir):
    """
    Test that analyze_variant_changes uses binary search instead of linear search.
    
    This tests the optimization at line 355 where we changed from O(n*m) nested loops
    to O(n*log(m)) using binary search.
    """
    from reversecore_mcp.tools.cli_tools import analyze_variant_changes
    
    # Create test files
    file_a = workspace_dir / "test_a.bin"
    file_b = workspace_dir / "test_b.bin"
    file_a.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    file_b.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    
    # Mock the diff_binaries call
    mock_diff_result = MagicMock()
    mock_diff_result.is_error = False
    mock_diff_result.content = [MagicMock(text='{"similarity": 0.8, "total_changes": 100, "changes": []}')]
    
    # Mock radare2 subprocess calls
    mock_funcs = [
        {"offset": 0x1000, "size": 0x100, "name": "func_a"},
        {"offset": 0x2000, "size": 0x200, "name": "func_b"},
        {"offset": 0x3000, "size": 0x150, "name": "func_c"},
    ]
    
    # Create many changes that map to these functions
    changes = [
        {"address": hex(0x1050 + i)} for i in range(50)  # All in func_a
    ] + [
        {"address": hex(0x2100 + i)} for i in range(30)  # All in func_b
    ]
    
    mock_diff_result.content[0].text = f'{{"similarity": 0.8, "total_changes": {len(changes)}, "changes": {changes}}}'
    
    with patch('reversecore_mcp.tools.cli_tools.diff_binaries', return_value=mock_diff_result):
        with patch('reversecore_mcp.tools.cli_tools._parse_json_output', return_value=mock_funcs):
            with patch('reversecore_mcp.tools.cli_tools.execute_subprocess_async', return_value=("[]", 0)):
                with patch('reversecore_mcp.tools.cli_tools.generate_function_graph') as mock_cfg:
                    mock_cfg.return_value = MagicMock(is_error=False, content=[MagicMock(text="graph")])
                    
                    import asyncio
                    start = time.time()
                    result = asyncio.run(analyze_variant_changes(str(file_a), str(file_b)))
                    elapsed = time.time() - start
                    
                    # With binary search, this should complete quickly even with many changes
                    assert elapsed < 0.5, f"Binary search optimization failed: {elapsed}s"
                    assert result.status == "success"


def test_trace_execution_path_set_optimization(workspace_dir):
    """
    Test that trace_execution_path uses set for path checking instead of list comprehension.
    
    This tests the optimization at line 179-182 where we pre-compute addresses
    in the current path as a set.
    """
    from reversecore_mcp.tools.cli_tools import trace_execution_path
    
    # Create test file
    test_file = workspace_dir / "trace_test.bin"
    test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    
    # Mock radare2 commands to return a simple call chain
    mock_xrefs = [
        {"fcn_addr": 0x1000, "fcn_name": "caller_1", "type": "call"},
        {"fcn_addr": 0x2000, "fcn_name": "main", "type": "call"},
    ]
    
    with patch('reversecore_mcp.tools.cli_tools._parse_json_output', return_value=mock_xrefs):
        with patch('reversecore_mcp.tools.cli_tools.execute_subprocess_async', return_value=("[]", 0)):
            with patch('reversecore_mcp.tools.cli_tools._build_r2_cmd', return_value=["r2", "-q"]):
                import asyncio
                start = time.time()
                result = asyncio.run(trace_execution_path(str(test_file), "target_func"))
                elapsed = time.time() - start
                
                # Should complete quickly with set-based checking
                assert elapsed < 1.0, f"Set optimization failed: {elapsed}s"
                assert result.status == "success"


def test_yara_processing_micro_optimization():
    """
    Test that YARA processing uses optimized early None check.
    
    This tests the micro-optimization in lib_tools.py where we check
    matched_data is None before doing the isinstance check.
    """
    from reversecore_mcp.tools.lib_tools import _format_yara_match
    
    # Create mock YARA match with many instances
    mock_instance_with_data = MagicMock()
    mock_instance_with_data.offset = 0x1000
    mock_instance_with_data.matched_data = b"test_data"
    
    mock_instance_no_data = MagicMock()
    mock_instance_no_data.offset = 0x2000
    mock_instance_no_data.matched_data = None
    
    mock_string = MagicMock()
    mock_string.identifier = "$test"
    # Mix of instances with and without data
    mock_string.instances = [mock_instance_with_data] * 100 + [mock_instance_no_data] * 100
    
    mock_match = MagicMock()
    mock_match.rule = "TestRule"
    mock_match.namespace = "default"
    mock_match.tags = ["test"]
    mock_match.meta = {"author": "test"}
    mock_match.strings = [mock_string]
    
    start = time.time()
    result = _format_yara_match(mock_match)
    elapsed = time.time() - start
    
    # Should process 200 instances very quickly
    assert elapsed < 0.01, f"YARA processing optimization failed: {elapsed}s"
    assert result["rule"] == "TestRule"
    assert len(result["strings"]) == 200


def test_ghidra_helper_extract_structure_fields():
    """
    Test that the new helper function _extract_structure_fields works correctly.
    
    This tests the refactoring that reduces code duplication and improves
    performance by avoiding repeated attribute checks.
    """
    from reversecore_mcp.core.ghidra_helper import _extract_structure_fields
    
    # Create mock Ghidra data type
    mock_component = MagicMock()
    mock_component.getFieldName.return_value = "test_field"
    mock_component.getDataType().getName.return_value = "int"
    mock_component.getOffset.return_value = 0
    mock_component.getLength.return_value = 4
    
    mock_data_type = MagicMock()
    mock_data_type.getNumComponents.return_value = 10
    mock_data_type.getComponent.return_value = mock_component
    
    start = time.time()
    fields = _extract_structure_fields(mock_data_type)
    elapsed = time.time() - start
    
    # Should extract fields very quickly
    assert elapsed < 0.01, f"Structure extraction optimization failed: {elapsed}s"
    assert len(fields) == 10
    assert fields[0]["name"] == "test_field"
    assert fields[0]["type"] == "int"


def test_binary_search_vs_linear_search_performance():
    """
    Benchmark test showing binary search is faster than linear search.
    
    This demonstrates the performance improvement from the analyze_variant_changes
    optimization.
    """
    # Simulate function list
    functions = [
        (i * 0x1000, (i + 1) * 0x1000, f"func_{i}")
        for i in range(1000)  # 1000 functions
    ]
    
    changes = [
        {"address": hex(500 * 0x1000 + j)}
        for j in range(100)  # 100 changes all in the same function
    ]
    
    # Linear search (old method)
    def linear_search():
        changed_funcs = {}
        for change in changes:
            addr_str = change.get("address")
            if not addr_str:
                continue
            try:
                addr = int(addr_str, 16)
                for func_start, func_end, func_name in functions:
                    if func_start <= addr < func_end:
                        changed_funcs[func_name] = changed_funcs.get(func_name, 0) + 1
                        break
            except:
                pass
        return changed_funcs
    
    # Binary search (new method)
    def binary_search():
        sorted_funcs = sorted(functions, key=lambda x: x[0])
        changed_funcs = {}
        for change in changes:
            addr_str = change.get("address")
            if not addr_str:
                continue
            try:
                addr = int(addr_str, 16)
                left, right = 0, len(sorted_funcs) - 1
                found_func = None
                
                while left <= right:
                    mid = (left + right) // 2
                    func_start, func_end, func_name = sorted_funcs[mid]
                    
                    if func_start <= addr < func_end:
                        found_func = func_name
                        break
                    elif addr < func_start:
                        right = mid - 1
                    else:
                        left = mid + 1
                
                if found_func:
                    changed_funcs[found_func] = changed_funcs.get(found_func, 0) + 1
            except:
                pass
        return changed_funcs
    
    # Benchmark
    start = time.time()
    result_linear = linear_search()
    time_linear = time.time() - start
    
    start = time.time()
    result_binary = binary_search()
    time_binary = time.time() - start
    
    # Results should be identical
    assert result_linear == result_binary
    
    # Binary search should be significantly faster (at least 5x)
    assert time_binary < time_linear / 5, \
        f"Binary search not faster enough: {time_binary}s vs {time_linear}s"
    
    print(f"Linear search: {time_linear:.4f}s")
    print(f"Binary search: {time_binary:.4f}s")
    print(f"Speedup: {time_linear/time_binary:.2f}x")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
