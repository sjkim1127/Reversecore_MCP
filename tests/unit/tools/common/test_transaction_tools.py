"""Unit tests for transaction MCP tools and atomic batch execution integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.transaction import TransactionManager
from reversecore_mcp.tools.common.batch_operations import batch_execute
from reversecore_mcp.tools.common.transaction_tools import (
    transaction_begin,
    transaction_commit,
    transaction_redo,
    transaction_rollback,
    transaction_status,
    transaction_undo,
)
from reversecore_mcp.tools.radare2.r2_db import r2_add_bookmark, r2_list_bookmarks


@pytest.fixture(autouse=True)
def clean_transaction_manager():
    """Ensure TransactionManager is cleanly reset before and after every test."""
    TransactionManager.reset_instance()
    yield
    TransactionManager.reset_instance()


class TestTransactionMcpTools:
    """Tests for transaction MCP tool endpoints."""

    @pytest.mark.asyncio
    async def test_transaction_begin_and_commit(self):
        """Test begin, inspect status, and commit tools."""
        res_begin = await transaction_begin(name="my_tx", description="Testing begin tool")
        assert res_begin.ok
        assert res_begin.data["name"] == "my_tx"
        tx_id = res_begin.data["transaction_id"]

        res_status = await transaction_status()
        assert res_status.ok
        assert res_status.data["has_active_transaction"]
        assert res_status.data["active_transaction"]["transaction_id"] == tx_id

        res_commit = await transaction_commit()
        assert res_commit.ok
        assert res_commit.data["state"] == "committed"

        res_status_after = await transaction_status()
        assert not res_status_after.data["has_active_transaction"]
        assert res_status_after.data["undo_depth"] == 1

    @pytest.mark.asyncio
    async def test_transaction_begin_already_active_error(self):
        """Beginning another transaction when one is active returns structured failure."""
        await transaction_begin(name="first")
        res_second = await transaction_begin(name="second")
        assert not res_second.ok
        assert res_second.error_code == "TRANSACTION_ALREADY_ACTIVE"
        await transaction_rollback()

    @pytest.mark.asyncio
    async def test_transaction_commit_no_active_error(self):
        """Committing when no transaction is active returns NO_ACTIVE_TRANSACTION error."""
        res = await transaction_commit()
        assert not res.ok
        assert res.error_code == "NO_ACTIVE_TRANSACTION"

    @pytest.mark.asyncio
    async def test_transaction_rollback_no_active_error(self):
        """Rolling back when no transaction is active returns NO_ACTIVE_TRANSACTION error."""
        res = await transaction_rollback()
        assert not res.ok
        assert res.error_code == "NO_ACTIVE_TRANSACTION"

    @pytest.mark.asyncio
    async def test_transaction_rollback_success(self):
        """Rolling back an active transaction restores state."""
        await transaction_begin(name="abort_me")
        res_rb = await transaction_rollback(reason="Rollback test")
        assert res_rb.ok
        assert res_rb.data["state"] == "rolled_back"
        assert res_rb.data["reason"] == "Rollback test"

    @pytest.mark.asyncio
    async def test_transaction_undo_and_redo_tools(self):
        """Test undo and redo tool endpoints."""
        await transaction_begin(name="tx1")
        await transaction_commit()

        # Undo
        res_undo = await transaction_undo(steps=1)
        assert res_undo.ok
        assert res_undo.data["undone_count"] == 1
        assert res_undo.data["undo_depth"] == 0
        assert res_undo.data["redo_depth"] == 1

        # Redo
        res_redo = await transaction_redo(steps=1)
        assert res_redo.ok
        assert res_redo.data["redone_count"] == 1
        assert res_redo.data["undo_depth"] == 1
        assert res_redo.data["redo_depth"] == 0

    @pytest.mark.asyncio
    async def test_transaction_undo_empty_error(self):
        """Undoing when history is empty returns NOTHING_TO_UNDO error."""
        res = await transaction_undo(steps=1)
        assert not res.ok
        assert res.error_code == "NOTHING_TO_UNDO"

    @pytest.mark.asyncio
    async def test_transaction_redo_empty_error(self):
        """Redoing when redo stack is empty returns NOTHING_TO_REDO error."""
        res = await transaction_redo(steps=1)
        assert not res.ok
        assert res.error_code == "NOTHING_TO_REDO"


class TestAtomicBatchExecution:
    """Tests for batch_execute with atomic=True."""

    @pytest.mark.asyncio
    async def test_atomic_batch_all_success(self):
        """Atomic batch execution commits when all operations succeed."""
        op1 = {"tool": "dummy_ok", "arguments": {"x": 1}}
        op2 = {"tool": "dummy_ok", "arguments": {"x": 2}}

        mock_tool = AsyncMock()
        mock_tool.name = "dummy_ok"
        mock_tool.run = AsyncMock(return_value={"ok": True, "result": "done"})

        with patch("reversecore_mcp.tools.common.batch_operations._resolve_server") as mock_resolve:
            mock_server = AsyncMock()
            mock_server.list_tools = AsyncMock(return_value=[mock_tool])
            mock_resolve.return_value = mock_server

            res = await batch_execute(operations=[op1, op2], atomic=True)

        assert res.ok
        assert res.data["completed"] == 2
        assert res.data["failed"] == 0
        assert res.data["transaction_status"] == "COMMITTED"
        assert res.data["transaction_id"].startswith("tx_")

    @pytest.mark.asyncio
    async def test_atomic_batch_partial_failure_rolls_back(self):
        """Atomic batch execution rolls back transaction if any item fails."""
        op1 = {"tool": "dummy_ok", "arguments": {"x": 1}}
        op2 = {"tool": "dummy_fail", "arguments": {"x": 2}}

        tool_ok = AsyncMock()
        tool_ok.name = "dummy_ok"
        tool_ok.run = AsyncMock(return_value={"ok": True, "result": "done"})

        tool_fail = AsyncMock()
        tool_fail.name = "dummy_fail"
        tool_fail.run = AsyncMock(
            return_value={"ok": False, "error": {"code": "FAIL", "message": "boom"}}
        )

        with patch("reversecore_mcp.tools.common.batch_operations._resolve_server") as mock_resolve:
            mock_server = AsyncMock()
            mock_server.list_tools = AsyncMock(return_value=[tool_ok, tool_fail])
            mock_resolve.return_value = mock_server

            res = await batch_execute(operations=[op1, op2], atomic=True)

        assert res.ok
        assert res.data["completed"] == 1
        assert res.data["failed"] == 1
        assert res.data["transaction_status"] == "ROLLED_BACK"

    @pytest.mark.asyncio
    async def test_multiple_annotations_atomic_commit_rollback_and_undo(self, tmp_path):
        """Acceptance test: Multiple annotations committed atomically, rolled back, and undone."""
        from reversecore_mcp.core.config import get_config

        ws_dir = get_config().workspace
        sample_bin = ws_dir / "tx_sample.bin"
        sample_bin.write_bytes(b"\x90" * 4096)

        db_file = tmp_path / "test_annotations.r2db"

        with (
            patch("reversecore_mcp.tools.radare2.r2_db._DB_PATH", db_file),
            patch("reversecore_mcp.core.transaction._get_r2db_path", return_value=db_file),
        ):
            from reversecore_mcp.tools.radare2.r2_db import _ensure_schema_initialized

            _ensure_schema_initialized(db_file)

            # 1. Start transaction and add annotations
            res_begin = await transaction_begin(name="speculative_annotations")
            assert res_begin.ok

            add1 = await r2_add_bookmark(str(sample_bin), "0x1000", "Entry point")
            assert add1.ok
            add2 = await r2_add_bookmark(str(sample_bin), "0x2000", "Critical function")
            assert add2.ok

            # Status should show 2 mutations
            status = await transaction_status()
            assert status.data["active_transaction"]["mutations_count"] == 2

            # Rollback
            res_rb = await transaction_rollback()
            assert res_rb.ok

            # Verify bookmarks do not exist after rollback
            list_res = await r2_list_bookmarks(str(sample_bin))
            assert list_res.ok
            assert list_res.data["count"] == 0

            # 2. Start new transaction and commit annotations
            res_begin2 = await transaction_begin(name="permanent_annotations")
            assert res_begin2.ok

            await r2_add_bookmark(str(sample_bin), "0x1000", "Entry point")
            await r2_add_bookmark(str(sample_bin), "0x2000", "Critical function")

            res_commit = await transaction_commit()
            assert res_commit.ok

            # Both bookmarks exist after commit
            list_res = await r2_list_bookmarks(str(sample_bin))
            assert list_res.ok
            assert list_res.data["count"] == 2

            # 3. Undo restores pre-transaction state
            res_undo = await transaction_undo(steps=1)
            assert res_undo.ok

            list_res = await r2_list_bookmarks(str(sample_bin))
            assert list_res.ok
            assert list_res.data["count"] == 0

            # 4. Redo restores committed state
            res_redo = await transaction_redo(steps=1)
            assert res_redo.ok

            list_res = await r2_list_bookmarks(str(sample_bin))
            assert list_res.ok
            assert list_res.data["count"] == 2
