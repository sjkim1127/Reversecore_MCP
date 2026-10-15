"""Unit tests for generic batch execution tool (Issue #327)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.tools.common.batch_operations import (
    MAX_BATCH_SIZE,
    batch_execute,
)


@pytest.mark.unit
@pytest.mark.asyncio
class TestBatchExecuteValidation:
    """Tests for input validation in batch_execute."""

    async def test_empty_operations_list(self):
        """Empty operations list returns structured EMPTY_BATCH error."""
        res = await batch_execute(operations=[])
        assert not res.ok
        assert res.error is not None
        assert res.error.code == "EMPTY_BATCH"
        assert "Batch cannot be empty" in res.error.message

    async def test_exceeds_max_batch_size(self):
        """Batch size greater than MAX_BATCH_SIZE returns BATCH_SIZE_EXCEEDED."""
        oversized = [{"tool": "run_file", "arguments": {}} for _ in range(MAX_BATCH_SIZE + 1)]
        res = await batch_execute(operations=oversized)
        assert not res.ok
        assert res.error is not None
        assert res.error.code == "BATCH_SIZE_EXCEEDED"
        assert str(MAX_BATCH_SIZE) in res.error.message

    async def test_invalid_operation_item(self):
        """Invalid operation format (missing tool or not a dict) is recorded in errors."""
        res = await batch_execute(
            operations=[
                {"id": "bad1", "tool": ""},  # empty tool
                "not-a-dict",  # invalid type
                {"id": "bad3"},  # missing tool
            ]
        )
        assert res.ok
        data = res.data
        assert data["requested"] == 3
        assert data["completed"] == 0
        assert data["failed"] == 3
        assert len(data["errors"]) == 3
        for err in data["errors"]:
            assert err["error"]["code"] == "INVALID_OPERATION_SPEC"

    async def test_disallowed_recursive_tool(self):
        """Invoking batch_execute recursively is prohibited."""
        res = await batch_execute(
            operations=[{"id": "recurse", "tool": "batch_execute", "arguments": {}}]
        )
        assert res.ok
        data = res.data
        assert data["failed"] == 1
        assert data["errors"][0]["error"]["code"] == "DISALLOWED_BATCH_TOOL"

    async def test_unknown_tool_rejection(self):
        """Unregistered or unpermitted tool returns TOOL_NOT_FOUND."""
        res = await batch_execute(
            operations=[{"id": "unknown", "tool": "nonexistent_tool_xyz", "arguments": {}}]
        )
        assert res.ok
        data = res.data
        assert data["failed"] == 1
        assert data["errors"][0]["error"]["code"] == "TOOL_NOT_FOUND"


@pytest.mark.unit
@pytest.mark.asyncio
class TestBatchExecuteExecution:
    """Tests for batch execution flows, concurrency, and partial failure isolation."""

    async def test_successful_homogeneous_batch(self):
        """Executing multiple valid operations in a batch succeeds deterministically."""
        from reversecore_mcp.core.security import get_workspace_config

        ws = get_workspace_config().workspace
        test_dir = ws / "test_batch_homo"
        test_dir.mkdir(parents=True, exist_ok=True)

        files = []
        for i in range(3):
            p = test_dir / f"test_{i}.txt"
            p.write_text(f"Hello test {i}")
            files.append(p)

        operations = [
            {"id": f"op_{i}", "tool": "run_file", "arguments": {"file_path": str(f)}}
            for i, f in enumerate(files)
        ]

        res = await batch_execute(operations=operations, max_concurrency=2)
        assert res.ok
        data = res.data
        assert data["requested"] == 3
        assert data["completed"] == 3
        assert data["failed"] == 0
        assert len(data["results"]) == 3

        # Verify ordering and IDs
        for i, item in enumerate(data["results"]):
            assert item["index"] == i
            assert item["id"] == f"op_{i}"
            assert item["tool"] == "run_file"
            assert item["status"] == "success"
            assert "file_type" in item["data"]

    async def test_partial_failure_isolation(self):
        """Failures in individual items are isolated and do not discard successful items."""
        from reversecore_mcp.core.security import get_workspace_config

        ws = get_workspace_config().workspace
        test_dir = ws / "test_batch_partial"
        test_dir.mkdir(parents=True, exist_ok=True)

        valid_file = test_dir / "valid.txt"
        valid_file.write_text("Valid content")
        nonexistent_file = ws / "nonexistent_missing_file_xyz.bin"

        operations = [
            {"id": "good_1", "tool": "run_file", "arguments": {"file_path": str(valid_file)}},
            {"id": "bad_1", "tool": "run_file", "arguments": {"file_path": str(nonexistent_file)}},
            {"id": "good_2", "tool": "run_file", "arguments": {"file_path": str(valid_file)}},
        ]

        res = await batch_execute(operations=operations, stop_on_error=False)
        assert res.ok
        data = res.data
        assert data["requested"] == 3
        assert data["completed"] == 2
        assert data["failed"] == 1

        assert len(data["results"]) == 2
        assert [r["index"] for r in data["results"]] == [0, 2]
        assert [r["id"] for r in data["results"]] == ["good_1", "good_2"]

        assert len(data["errors"]) == 1
        err = data["errors"][0]
        assert err["index"] == 1
        assert err["id"] == "bad_1"
        assert err["status"] == "error"

    async def test_stop_on_error_halts_execution(self):
        """Setting stop_on_error=True halts further executions after a failure."""
        from reversecore_mcp.core.security import get_workspace_config

        ws = get_workspace_config().workspace
        test_dir = ws / "test_batch_stop"
        test_dir.mkdir(parents=True, exist_ok=True)

        valid_file = test_dir / "valid.txt"
        valid_file.write_text("Valid content")
        nonexistent_file = ws / "nonexistent_missing_file_abc.bin"

        operations = [
            {"id": "op_0", "tool": "run_file", "arguments": {"file_path": str(nonexistent_file)}},
            {"id": "op_1", "tool": "run_file", "arguments": {"file_path": str(valid_file)}},
            {"id": "op_2", "tool": "run_file", "arguments": {"file_path": str(valid_file)}},
        ]

        # Use concurrency=1 so op_0 fails first and triggers stop_event
        res = await batch_execute(operations=operations, max_concurrency=1, stop_on_error=True)
        assert res.ok
        data = res.data
        assert data["requested"] == 3
        assert data["failed"] >= 1
        # op_1 or op_2 halted
        halted = [e for e in data["errors"] if e.get("error", {}).get("code") == "BATCH_HALTED"]
        assert len(halted) > 0

    async def test_item_timeout_handling(self):
        """Per-item timeout fires when an individual operation exceeds item_timeout."""
        mock_tool = AsyncMock()

        async def _hang(*args, **kwargs):
            await asyncio.sleep(5)
            return {"status": "success"}

        mock_tool.name = "mock_hang_tool"
        mock_tool.run = _hang

        with patch("reversecore_mcp.tools.common.batch_operations._resolve_server") as mock_resolve:
            mock_server = AsyncMock()
            mock_server.list_tools.return_value = [mock_tool]
            mock_resolve.return_value = mock_server

            res = await batch_execute(
                operations=[{"id": "hang", "tool": "mock_hang_tool", "arguments": {}}],
                item_timeout=1,
            )

            assert res.ok
            data = res.data
            assert data["failed"] == 1
            assert data["errors"][0]["error"]["code"] == "ITEM_TIMEOUT"
            assert data["errors"][0]["error"]["retryable"] is True
