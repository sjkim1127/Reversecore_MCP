"""Unit tests for ToolResult data models."""

from reversecore_mcp.core.result import (
    PaginationMeta,
    ToolError,
    ToolResult,
    ToolSuccess,
    failure,
    success,
)


class TestPaginationMeta:
    """Validate PaginationMeta model defaults and custom fields."""

    def test_default_pagination_meta(self):
        meta = PaginationMeta()
        assert meta.has_more is False
        assert meta.next_cursor is None
        assert meta.total_items is None
        assert meta.page == 1
        assert meta.page_size == 100
        assert meta.truncated is False

    def test_custom_pagination_meta(self):
        meta = PaginationMeta(
            has_more=True,
            next_cursor="cursor_123",
            total_items=450,
            page=2,
            page_size=50,
            truncated=True,
        )
        assert meta.has_more is True
        assert meta.next_cursor == "cursor_123"
        assert meta.total_items == 450
        assert meta.page == 2
        assert meta.page_size == 50
        assert meta.truncated is True


class TestToolSuccess:
    """Validate ToolSuccess behaviors."""

    def test_success_creation(self):
        result = ToolSuccess(data="output")
        assert result.status == "success"
        assert result.data == "output"
        assert result.metadata is None
        assert result.pagination is None

    def test_success_with_metadata(self):
        result = ToolSuccess(data={"key": "value"}, metadata={"bytes": 10})
        assert result.metadata == {"bytes": 10}

    def test_success_with_pagination(self):
        pagination = PaginationMeta(has_more=True, next_cursor="offset:100", total_items=250)
        result = ToolSuccess(data=[{"addr": "0x1000"}], pagination=pagination)
        assert result.pagination is not None
        assert result.pagination.has_more is True
        assert result.pagination.next_cursor == "offset:100"
        assert result.pagination.total_items == 250

    def test_success_with_arbitrary_data_types(self):
        # Support lists, dicts, strings, ints, etc.
        res_list = ToolSuccess(data=[1, 2, 3])
        assert res_list.data == [1, 2, 3]

        res_none = ToolSuccess(data=None)
        assert res_none.data is None

    def test_success_dump(self):
        result = ToolSuccess(data="output", metadata={"key": "value"})
        assert result.model_dump() == {
            "status": "success",
            "data": "output",
            "metadata": {"key": "value"},
            "pagination": None,
            "recommended_next_tools": None,
        }


class TestToolError:
    """Validate ToolError behaviors."""

    def test_error_creation(self):
        result = ToolError(error_code="TEST", message="failure")
        assert result.status == "error"
        assert result.error_code == "TEST"
        assert result.message == "failure"
        assert result.hint is None
        assert result.details is None

    def test_error_with_hint_and_details(self):
        result = ToolError(
            error_code="VALIDATION_ERROR",
            message="invalid",
            hint="Check path",
            details={"path": "/tmp"},
        )
        dump = result.model_dump()
        assert dump["hint"] == "Check path"
        assert dump["details"] == {"path": "/tmp"}


class TestHelperFactories:
    """Ensure helper functions build the dataclasses correctly."""

    def test_success_helper_adds_metadata(self):
        result = success("done", bytes_read=512, elapsed=1.2)
        assert isinstance(result, ToolSuccess)
        assert result.data == "done"
        assert result.metadata == {"bytes_read": 512, "elapsed": 1.2}
        assert result.pagination is None

    def test_success_helper_with_pagination(self):
        meta = PaginationMeta(has_more=True, next_cursor="page:2")
        result = success({"items": [1, 2, 3]}, pagination=meta, total_count=3)
        assert result.pagination == meta
        assert result.metadata == {"total_count": 3}

    def test_success_helper_omits_empty_metadata(self):
        result = success("done")
        assert result.metadata is None
        assert result.pagination is None

    def test_failure_helper_full(self):
        result = failure(
            "TOOL_NOT_FOUND",
            "Tool not found",
            hint="Install via pip",
            tool="file",
        )
        assert isinstance(result, ToolError)
        assert result.error_code == "TOOL_NOT_FOUND"
        assert result.message == "Tool not found"
        assert result.hint == "Install via pip"
        assert result.details == {"tool": "file"}

    def test_failure_helper_minimal(self):
        result = failure("ERROR", "Something failed")
        assert result.details is None


class TestToolResultUnion:
    """Exercise the ToolResult union typing."""

    def test_tool_result_accepts_success_or_error(self):
        success_result: ToolResult = ToolSuccess(data="value")
        error_result: ToolResult = ToolError(error_code="ERR", message="bad")

        assert isinstance(success_result, ToolSuccess)
        assert isinstance(error_result, ToolError)


class TestSchemaOptimizationAndPagination:
    """Verify schema optimization, token efficiency formats, and pagination contracts."""

    def test_compact_disassembly_tuples(self):
        # Compact instruction format: [addr, mnemonic, operands, comment]
        insts = [
            ["0x401000", "push", "rbp", ""],
            ["0x401001", "mov", "rbp, rsp", "setup frame"],
            ["0x401004", "call", "sym.decrypt", "decrypt payload"],
        ]
        pagination = PaginationMeta(
            has_more=False,
            next_cursor=None,
            total_items=3,
            page=1,
            page_size=100,
            truncated=False,
        )
        res = success(
            {
                "format": "compact",
                "address": "0x401000",
                "instructions": insts,
            },
            pagination=pagination,
        )
        assert res.data["format"] == "compact"
        assert len(res.data["instructions"]) == 3
        assert res.data["instructions"][1] == [
            "0x401001",
            "mov",
            "rbp, rsp",
            "setup frame",
        ]
        assert res.pagination is not None
        assert res.pagination.total_items == 3

    def test_windowed_decompilation_schema(self):
        code_lines = [
            "int decrypt_payload(char *buf, int len) {",
            "    for (int i = 0; i < len; i++) {",
            "        buf[i] ^= 0x42;",
            "    }",
            "    return 0;",
            "}",
        ]
        window = "\n".join(code_lines[0:3])
        pagination = PaginationMeta(
            has_more=True,
            next_cursor="3",
            total_items=len(code_lines),
            page=1,
            page_size=3,
            truncated=True,
        )
        summary = {
            "function": "decrypt_payload",
            "signature": "int decrypt_payload(char *buf, int len) {",
            "total_lines": 6,
            "window_lines": "1-3",
        }
        res = success(
            {
                "function": "decrypt_payload",
                "summary": summary,
                "pseudo_c": window,
                "decompiler": "r2ghidra",
                "line_offset": 0,
                "max_lines": 3,
                "total_lines": 6,
                "has_more": True,
                "next_line_offset": 3,
            },
            pagination=pagination,
        )
        assert res.data["summary"]["signature"] == "int decrypt_payload(char *buf, int len) {"
        assert res.data["total_lines"] == 6
        assert res.data["has_more"] is True
        assert res.pagination.next_cursor == "3"

    def test_bounded_xrefs_and_callers_grouping(self):
        callers = {
            "main": ["0x401050", "0x401060"],
            "sym.worker": ["0x402000"],
        }
        xrefs_to = [
            {"from": "0x401050", "fcn_name": "main"},
            {"from": "0x401060", "fcn_name": "main"},
            {"from": "0x402000", "fcn_name": "sym.worker"},
        ]
        pagination = PaginationMeta(
            has_more=False,
            total_items=3,
            page_size=50,
            truncated=False,
        )
        res = success(
            {
                "address": "sym.decrypt",
                "xrefs_to": xrefs_to,
                "callers_by_function": callers,
                "total_refs_to": 3,
                "total_refs_from": 0,
                "limit": 50,
                "truncated": False,
            },
            pagination=pagination,
        )
        assert res.data["callers_by_function"]["main"] == ["0x401050", "0x401060"]
        assert res.data["total_refs_to"] == 3


class TestSerializationAndTokenEfficiency:
    """Verify high-speed JSON serialization and absence of double-encoding."""

    def test_native_dict_serialization_no_escaping(self):
        from reversecore_mcp.core import json_utils as json

        payload = {
            "similarity": 0.95,
            "summary": {
                "similarity_score": 0.95,
                "total_changes": 1,
                "added_blocks": 1,
            },
            "changes": [{"address": "0x401000", "type": "new_block"}],
        }
        res = success(payload)
        # Direct dict should be preserved as dict in data
        assert isinstance(res.data, dict)
        assert res.data["similarity"] == 0.95

        # Serialized JSON should not contain double-escaped strings like \"similarity\": 0.95
        serialized = json.dumps(res.model_dump())
        assert '\\"similarity\\"' not in serialized
        assert '"similarity":0.95' in serialized or '"similarity": 0.95' in serialized

    def test_orjson_fast_path_compatibility(self):
        from reversecore_mcp.core import json_utils as json

        large_payload = {
            "functions": [
                {
                    "name": f"sym.func_{i}",
                    "address": hex(0x400000 + i * 0x100),
                    "size": 128,
                    "callers": [f"sym.caller_{j}" for j in range(5)],
                }
                for i in range(1000)
            ]
        }
        json_bytes = json.dumps(large_payload)
        parsed = json.loads(json_bytes)
        assert len(parsed["functions"]) == 1000
        assert parsed["functions"][0]["name"] == "sym.func_0"
