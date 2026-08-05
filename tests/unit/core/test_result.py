"""Unit tests for ToolResult data models."""

from reversecore_mcp.core.result import (
    ToolError,
    ToolResult,
    ToolSuccess,
    failure,
    success,
)


class TestToolSuccess:
    """Validate ToolSuccess behaviors."""

    def test_success_creation(self):
        result = ToolSuccess(data="output")
        assert result.status == "success"
        assert result.data == "output"
        assert result.metadata is None

    def test_success_with_metadata(self):
        result = ToolSuccess(data={"key": "value"}, metadata={"bytes": 10})
        assert result.metadata == {"bytes": 10}

    def test_success_dump(self):
        result = ToolSuccess(data="output", metadata={"key": "value"})
        assert result.model_dump() == {
            "status": "success",
            "data": "output",
            "metadata": {"key": "value"},
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

    def test_success_helper_omits_empty_metadata(self):
        result = success("done")
        assert result.metadata is None

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
