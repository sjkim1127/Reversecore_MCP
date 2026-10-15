"""Unit tests for TransactionManager and Reversecore transaction infrastructure."""

from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from reversecore_mcp.core.exceptions import (
    NoActiveTransactionError,
    NonReversibleOperationError,
    TransactionError,
)
from reversecore_mcp.core.transaction import (
    MutationClass,
    TransactionManager,
    TransactionState,
    get_transaction_manager,
)


@pytest.fixture(autouse=True)
def clean_transaction_manager():
    """Ensure TransactionManager is cleanly reset before and after every test."""
    TransactionManager.reset_instance()
    yield
    TransactionManager.reset_instance()


class TestTransactionManagerLifecycle:
    """Tests for basic transaction lifecycle: begin, commit, rollback."""

    def test_singleton(self):
        """TransactionManager is a singleton."""
        mgr1 = get_transaction_manager()
        mgr2 = get_transaction_manager()
        assert mgr1 is mgr2

    def test_begin_and_commit(self):
        """Test beginning and committing a transaction."""
        mgr = get_transaction_manager()
        assert not mgr.has_active_transaction()

        tx = mgr.begin(name="test_tx", description="Testing lifecycle")
        assert mgr.has_active_transaction()
        assert tx.name == "test_tx"
        assert tx.state == TransactionState.ACTIVE

        committed = mgr.commit(tx_id=tx.id)
        assert committed.state == TransactionState.COMMITTED
        assert not mgr.has_active_transaction()

        status = mgr.status()
        assert status["undo_depth"] == 1
        assert status["redo_depth"] == 0

    def test_begin_already_active_raises(self):
        """Beginning a transaction while one is active raises TransactionError."""
        mgr = get_transaction_manager()
        mgr.begin(name="first")
        with pytest.raises(TransactionError, match="already active"):
            mgr.begin(name="second")

    def test_commit_no_active_raises(self):
        """Committing when no transaction is active raises NoActiveTransactionError."""
        mgr = get_transaction_manager()
        with pytest.raises(NoActiveTransactionError):
            mgr.commit()

    def test_rollback_no_active_raises(self):
        """Rolling back when no transaction is active raises NoActiveTransactionError."""
        mgr = get_transaction_manager()
        with pytest.raises(NoActiveTransactionError):
            mgr.rollback()

    def test_id_mismatch_raises(self):
        """Commit or rollback with incorrect tx_id raises TransactionError."""
        mgr = get_transaction_manager()
        tx = mgr.begin(name="tx1")
        with pytest.raises(TransactionError, match="Transaction ID mismatch"):
            mgr.commit(tx_id="tx_invalid")
        with pytest.raises(TransactionError, match="Transaction ID mismatch"):
            mgr.rollback(tx_id="tx_invalid")
        # Clean up
        mgr.rollback(tx_id=tx.id)

    def test_rollback_restores_clean_state(self):
        """Test rollback transitions state to ROLLED_BACK with reason."""
        mgr = get_transaction_manager()
        mgr.begin(name="will_abort")
        rolled_back = mgr.rollback(reason="Test failure")
        assert rolled_back.state == TransactionState.ROLLED_BACK
        assert any("Test failure" in w for w in rolled_back.warnings)
        assert not mgr.has_active_transaction()


class TestTransactionMutations:
    """Tests for mutation recording, reversible vs non-reversible actions."""

    def test_record_reversible_mutation(self):
        """Reversible mutations are recorded without warnings."""
        mgr = get_transaction_manager()
        tx = mgr.begin()
        mgr.record_mutation(
            MutationClass.ANNOTATION,
            resource="structure:MyStruct",
            action="r2_create_structure",
            details={"field_count": 2},
            reversible=True,
        )
        assert len(tx.mutations) == 1
        assert tx.mutations[0].action == "r2_create_structure"
        assert not tx.has_unreversible_actions
        assert not tx.warnings
        mgr.commit()

    def test_record_non_reversible_non_strict(self):
        """Non-reversible actions in non-strict mode mark transaction with warnings."""
        mgr = get_transaction_manager()
        tx = mgr.begin(strict=False)
        mgr.record_mutation(
            MutationClass.EXTERNAL,
            resource="proc:1234",
            action="run_file",
            reversible=False,
        )
        assert tx.has_unreversible_actions
        assert len(tx.warnings) == 1
        assert "Non-reversible action" in tx.warnings[0]
        committed = mgr.commit()
        assert not committed.to_dict()["is_clean_reversible"]

    def test_record_non_reversible_strict_raises(self):
        """Non-reversible actions in strict mode raise NonReversibleOperationError."""
        mgr = get_transaction_manager()
        mgr.begin(strict=True, auto_rollback_on_error=False)
        with pytest.raises(NonReversibleOperationError, match="is non-reversible"):
            mgr.record_mutation(
                MutationClass.EXTERNAL,
                resource="file:target",
                action="execute_command",
                reversible=False,
            )
        mgr.rollback()

    def test_record_non_reversible_strict_auto_rollback(self):
        """Strict mode with auto_rollback_on_error automatically rolls back upon rejection."""
        mgr = get_transaction_manager()
        mgr.begin(strict=True, auto_rollback_on_error=True)
        with pytest.raises(NonReversibleOperationError):
            mgr.record_mutation(
                MutationClass.EXTERNAL,
                resource="file:target",
                action="execute_command",
                reversible=False,
            )
        # Should already be rolled back
        assert not mgr.has_active_transaction()


class TestStateRollbackAndUndoRedo:
    """Tests for database state rollback, workspace files, and undo/redo stacks."""

    def test_r2db_rollback(self, tmp_path):
        """Rollback restores SQLite annotation database to pre-transaction content."""
        db_file = tmp_path / ".r2db"
        # Pre-populate with initial structure
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE structures (name TEXT PRIMARY KEY);")
        conn.execute("INSERT INTO structures VALUES ('InitialStruct');")
        conn.commit()
        conn.close()

        mgr = get_transaction_manager()
        with patch("reversecore_mcp.core.transaction._get_r2db_path", return_value=db_file):
            tx = mgr.begin(name="db_test")

            # Mutate database during transaction
            conn = sqlite3.connect(str(db_file))
            conn.execute("INSERT INTO structures VALUES ('MutatedStruct');")
            conn.commit()
            conn.close()

            # Verify mutated state
            conn = sqlite3.connect(str(db_file))
            rows = [r[0] for r in conn.execute("SELECT name FROM structures").fetchall()]
            conn.close()
            assert "MutatedStruct" in rows

            # Roll back
            mgr.rollback(tx_id=tx.id)

            # Verify restored state
            conn = sqlite3.connect(str(db_file))
            restored_rows = [r[0] for r in conn.execute("SELECT name FROM structures").fetchall()]
            conn.close()
            assert restored_rows == ["InitialStruct"]

    def test_workspace_file_created_rollback(self, tmp_path):
        """Rollback unlinks newly created workspace files."""
        mgr = get_transaction_manager()
        mgr.begin(name="file_create_test")

        new_file = tmp_path / "generated_patch.diff"
        new_file.write_text("patch content")
        mgr.record_workspace_file_created(new_file)
        assert new_file.exists()

        mgr.rollback()
        assert not new_file.exists()

    def test_workspace_file_modified_rollback(self, tmp_path):
        """Rollback restores pre-modification workspace file contents."""
        orig_file = tmp_path / "analysis.txt"
        orig_file.write_text("original content")

        mgr = get_transaction_manager()
        mgr.begin(name="file_mod_test")

        mgr.record_workspace_file_modified(orig_file)
        orig_file.write_text("tampered content")
        assert orig_file.read_text() == "tampered content"

        mgr.rollback()
        assert orig_file.read_text() == "original content"

    def test_undo_and_redo_stack(self, tmp_path):
        """Test undo and redo stack behavior."""
        db_file = tmp_path / ".r2db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE notes (text TEXT);")
        conn.execute("INSERT INTO notes VALUES ('BaseNote');")
        conn.commit()
        conn.close()

        mgr = get_transaction_manager()
        with patch("reversecore_mcp.core.transaction._get_r2db_path", return_value=db_file):
            # 1. Commit a mutation
            mgr.begin(name="tx1")
            conn = sqlite3.connect(str(db_file))
            conn.execute("INSERT INTO notes VALUES ('Note1');")
            conn.commit()
            conn.close()
            mgr.commit()

            # 2. Undo tx1
            undone = mgr.undo(steps=1)
            assert len(undone) == 1
            conn = sqlite3.connect(str(db_file))
            rows = [r[0] for r in conn.execute("SELECT text FROM notes").fetchall()]
            conn.close()
            assert rows == ["BaseNote"]

            # 3. Redo tx1
            redone = mgr.redo(steps=1)
            assert len(redone) == 1
            conn = sqlite3.connect(str(db_file))
            rows = [r[0] for r in conn.execute("SELECT text FROM notes").fetchall()]
            conn.close()
            assert rows == ["BaseNote", "Note1"]
