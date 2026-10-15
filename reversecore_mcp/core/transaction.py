"""Transaction and undo/rollback infrastructure for state-modifying operations.

Provides explicit transaction boundaries, snapshotting, and rollback capabilities
for Reversecore-owned state (annotation database, memory sessions, report sessions,
and tracked workspace file artifacts).
"""

from __future__ import annotations

import copy
import shutil
import sqlite3
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from reversecore_mcp.core.audit import AuditAction, AuditLogger
from reversecore_mcp.core.exceptions import (
    NoActiveTransactionError,
    NonReversibleOperationError,
    TransactionError,
)
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class MutationClass(str, Enum):
    """Classes of mutations supported in Reversecore transactions."""

    ANNOTATION = "annotation"
    MEMORY = "memory"
    REPORT_SESSION = "report_session"
    WORKSPACE_ARTIFACT = "workspace_artifact"
    EXTERNAL = "external"


class TransactionState(str, Enum):
    """Lifecycle states of a transaction."""

    ACTIVE = "active"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    UNDONE = "undone"


@dataclass
class MutationRecord:
    """Record of a single mutation within a transaction."""

    mutation_class: str
    resource: str
    action: str
    reversible: bool
    timestamp: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TransactionSnapshot:
    """Checkpoint metadata and saved file paths for rolling back a transaction."""

    id: str
    name: str
    description: str
    state: TransactionState
    started_at: str
    ended_at: str | None = None
    strict: bool = False
    auto_rollback_on_error: bool = False
    mutations: list[MutationRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    has_unreversible_actions: bool = False

    # Checkpoint paths and state
    checkpoint_dir: Path | None = None
    r2db_backup: Path | None = None
    r2db_existed: bool = False
    memory_backup: Path | None = None
    memory_existed: bool = False
    report_sessions_backup: dict[str, Any] | None = None
    workspace_files_created: set[str] = field(default_factory=set)
    workspace_files_modified: dict[str, str] = field(default_factory=dict)

    # Post-commit checkpoint for redo
    post_commit_r2db_backup: Path | None = None
    post_commit_memory_backup: Path | None = None
    post_commit_report_sessions: dict[str, Any] | None = None

    def affected_resources(self) -> list[str]:
        """Return unique resource identifiers modified in this transaction."""
        resources: set[str] = {m.resource for m in self.mutations}
        if self.r2db_existed or self.r2db_backup:
            resources.add("database:r2db")
        if self.memory_existed or self.memory_backup:
            resources.add("database:memory")
        if self.report_sessions_backup is not None:
            resources.add("session:report_sessions")
        for f in self.workspace_files_created:
            resources.add(f"file_created:{f}")
        for f in self.workspace_files_modified:
            resources.add(f"file_modified:{f}")
        return sorted(resources)

    def to_dict(self) -> dict[str, Any]:
        """Convert transaction snapshot to structured dictionary."""
        return {
            "transaction_id": self.id,
            "name": self.name,
            "description": self.description,
            "state": self.state.value
            if isinstance(self.state, TransactionState)
            else str(self.state),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "strict": self.strict,
            "auto_rollback_on_error": self.auto_rollback_on_error,
            "mutations_count": len(self.mutations),
            "mutations": [asdict(m) for m in self.mutations],
            "affected_resources": self.affected_resources(),
            "warnings": list(self.warnings),
            "is_clean_reversible": not self.has_unreversible_actions,
        }


def _get_r2db_path() -> Path:
    from reversecore_mcp.tools.radare2 import r2_db

    return Path(r2_db._DB_PATH).resolve()


def _get_memory_db_path() -> Path:
    from reversecore_mcp.core import memory

    return Path(memory.DEFAULT_MEMORY_DB_PATH).resolve()


def _get_report_sessions_dict() -> dict[str, Any] | None:
    try:
        from typing import cast

        from reversecore_mcp.tools.report.report_tools import get_report_tools

        sessions = get_report_tools().sessions
        return cast(dict[str, Any], sessions)
    except Exception:
        return None


def _checkpoint_sqlite_file(source_path: Path, target_path: Path) -> bool:
    """Safely back up SQLite database to target path using sqlite3 online backup API."""
    if not source_path.exists():
        return False
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        src = sqlite3.connect(str(source_path), timeout=10.0)
        dst = sqlite3.connect(str(target_path), timeout=10.0)
        try:
            src.backup(dst)
            return True
        finally:
            dst.close()
            src.close()
    except Exception as exc:
        logger.warning(f"SQLite online backup failed for {source_path}: {exc}")
        return False


def _restore_sqlite_file(
    source_backup: Path | None, target_path: Path, existed_before: bool
) -> None:
    """Restore SQLite database file using online backup API or remove if it did not exist before."""
    if existed_before and source_backup and source_backup.exists():
        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            src = sqlite3.connect(str(source_backup), timeout=10.0)
            dst = sqlite3.connect(str(target_path), timeout=10.0)
            try:
                src.backup(dst)
                return
            finally:
                dst.close()
                src.close()
        except Exception as exc:
            logger.warning(f"SQLite online restore failed for {target_path}: {exc}")
    else:
        if target_path.exists():
            try:
                target_path.unlink(missing_ok=True)
            except OSError:
                pass
        wal = target_path.with_name(target_path.name + "-wal")
        shm = target_path.with_name(target_path.name + "-shm")
        if wal.exists():
            wal.unlink(missing_ok=True)
        if shm.exists():
            shm.unlink(missing_ok=True)
        try:
            from reversecore_mcp.tools.radare2 import r2_db

            path_key = str(target_path.resolve()) if target_path.exists() else str(target_path)
            r2_db._initialized_db_paths.discard(path_key)
            r2_db._initialized_db_paths.discard(str(target_path))
        except Exception:
            pass


class TransactionManager:
    """Manages active transactions, state checkpoints, rollback, and undo/redo history."""

    _instance: TransactionManager | None = None
    _init_lock = threading.Lock()

    def __new__(cls) -> TransactionManager:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._lock = threading.RLock()
        self._active_transaction: TransactionSnapshot | None = None
        self._undo_stack: list[TransactionSnapshot] = []
        self._redo_stack: list[TransactionSnapshot] = []
        self._max_history: int = 20
        self._base_storage_dir: Path = Path(tempfile.gettempdir()) / "reversecore_tx"
        self._base_storage_dir.mkdir(parents=True, exist_ok=True)
        self._audit = AuditLogger()
        self._initialized = True

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton state (primarily for isolated test executions)."""
        with cls._init_lock:
            if cls._instance is not None:
                with cls._instance._lock:
                    cls._instance._active_transaction = None
                    cls._instance._undo_stack.clear()
                    cls._instance._redo_stack.clear()
            cls._instance = None

    @property
    def active_transaction(self) -> TransactionSnapshot | None:
        """Return the currently active transaction, if any."""
        with self._lock:
            return self._active_transaction

    def has_active_transaction(self) -> bool:
        """Check whether a transaction is currently active."""
        with self._lock:
            return self._active_transaction is not None

    def begin(
        self,
        name: str | None = None,
        description: str | None = None,
        strict: bool = False,
        auto_rollback_on_error: bool = False,
    ) -> TransactionSnapshot:
        """Begin a new transaction and checkpoint current Reversecore state."""
        with self._lock:
            if self._active_transaction is not None:
                raise TransactionError(
                    f"A transaction is already active ({self._active_transaction.id}). "
                    "Commit or roll back before beginning a new transaction."
                )

            tx_id = f"tx_{uuid.uuid4().hex[:12]}"
            tx_name = name or tx_id
            tx_desc = (
                description or f"Transaction started at {datetime.now(timezone.utc).isoformat()}"
            )
            checkpoint_dir = self._base_storage_dir / tx_id
            checkpoint_dir.mkdir(parents=True, exist_ok=True)

            # 1. Snapshot r2_db
            r2db_path = _get_r2db_path()
            r2db_backup = checkpoint_dir / "r2db.sqlite"
            r2db_existed = _checkpoint_sqlite_file(r2db_path, r2db_backup)

            # 2. Snapshot memory db
            mem_path = _get_memory_db_path()
            mem_backup = checkpoint_dir / "memory.sqlite"
            mem_existed = _checkpoint_sqlite_file(mem_path, mem_backup)

            # 3. Snapshot report sessions
            report_sessions = _get_report_sessions_dict()
            report_backup = copy.deepcopy(report_sessions) if report_sessions is not None else None

            now_iso = datetime.now(timezone.utc).isoformat()
            tx = TransactionSnapshot(
                id=tx_id,
                name=tx_name,
                description=tx_desc,
                state=TransactionState.ACTIVE,
                started_at=now_iso,
                strict=strict,
                auto_rollback_on_error=auto_rollback_on_error,
                checkpoint_dir=checkpoint_dir,
                r2db_backup=r2db_backup if r2db_existed else None,
                r2db_existed=r2db_existed,
                memory_backup=mem_backup if mem_existed else None,
                memory_existed=mem_existed,
                report_sessions_backup=report_backup,
            )

            self._active_transaction = tx
            try:
                self._audit.log_event(
                    action=AuditAction.TRANSACTION_BEGIN,
                    resource=tx_id,
                    status="SUCCESS",
                    details={
                        "name": tx_name,
                        "strict": strict,
                        "auto_rollback": auto_rollback_on_error,
                    },
                )
            except Exception as exc:
                logger.debug(f"Audit log error during transaction.begin: {exc}")

            logger.info(f"Started transaction {tx_id} ({tx_name})")
            return tx

    def commit(self, tx_id: str | None = None) -> TransactionSnapshot:
        """Commit the active transaction and push to the undo history."""
        with self._lock:
            if self._active_transaction is None:
                raise NoActiveTransactionError("No active transaction to commit.")

            tx = self._active_transaction
            if tx_id is not None and tx.id != tx_id:
                raise TransactionError(
                    f"Transaction ID mismatch: active is {tx.id}, requested {tx_id}."
                )

            tx.state = TransactionState.COMMITTED
            tx.ended_at = datetime.now(timezone.utc).isoformat()

            # Take post-commit snapshot for redo support
            if tx.checkpoint_dir:
                post_r2db = tx.checkpoint_dir / "post_r2db.sqlite"
                if _checkpoint_sqlite_file(_get_r2db_path(), post_r2db):
                    tx.post_commit_r2db_backup = post_r2db

                post_mem = tx.checkpoint_dir / "post_memory.sqlite"
                if _checkpoint_sqlite_file(_get_memory_db_path(), post_mem):
                    tx.post_commit_memory_backup = post_mem

                report_sessions = _get_report_sessions_dict()
                if report_sessions is not None:
                    tx.post_commit_report_sessions = copy.deepcopy(report_sessions)

            # Push to undo stack
            self._undo_stack.append(tx)
            if len(self._undo_stack) > self._max_history:
                oldest = self._undo_stack.pop(0)
                if oldest.checkpoint_dir and oldest.checkpoint_dir.exists():
                    shutil.rmtree(oldest.checkpoint_dir, ignore_errors=True)

            # Redo stack is cleared on new commit
            self._redo_stack.clear()
            self._active_transaction = None

            try:
                self._audit.log_event(
                    action=AuditAction.TRANSACTION_COMMIT,
                    resource=tx.id,
                    status="SUCCESS",
                    details={
                        "mutations_count": len(tx.mutations),
                        "affected_resources": tx.affected_resources(),
                        "has_unreversible_actions": tx.has_unreversible_actions,
                    },
                )
            except Exception as exc:
                logger.debug(f"Audit log error during transaction.commit: {exc}")

            logger.info(f"Committed transaction {tx.id} with {len(tx.mutations)} mutations.")
            return tx

    def rollback(self, tx_id: str | None = None, reason: str | None = None) -> TransactionSnapshot:
        """Roll back the active transaction and restore pre-transaction state."""
        with self._lock:
            if self._active_transaction is None:
                raise NoActiveTransactionError("No active transaction to roll back.")

            tx = self._active_transaction
            if tx_id is not None and tx.id != tx_id:
                raise TransactionError(
                    f"Transaction ID mismatch: active is {tx.id}, requested {tx_id}."
                )

            # 1. Restore r2_db
            r2db_path = _get_r2db_path()
            _restore_sqlite_file(tx.r2db_backup, r2db_path, tx.r2db_existed)

            # 2. Restore memory db
            mem_path = _get_memory_db_path()
            _restore_sqlite_file(tx.memory_backup, mem_path, tx.memory_existed)

            # 3. Restore report sessions
            report_sessions = _get_report_sessions_dict()
            if report_sessions is not None and tx.report_sessions_backup is not None:
                report_sessions.clear()
                report_sessions.update(copy.deepcopy(tx.report_sessions_backup))

            # 4. Restore workspace files
            for created_path_str in list(tx.workspace_files_created):
                created_path = Path(created_path_str)
                if created_path.exists():
                    try:
                        created_path.unlink(missing_ok=True)
                    except OSError as exc:
                        logger.warning(
                            f"Failed to remove created workspace artifact {created_path}: {exc}"
                        )

            for orig_path_str, backup_path_str in tx.workspace_files_modified.items():
                orig_path = Path(orig_path_str)
                backup_path = Path(backup_path_str)
                if backup_path.exists():
                    try:
                        orig_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(backup_path, orig_path)
                    except OSError as exc:
                        logger.warning(
                            f"Failed to restore modified workspace artifact {orig_path}: {exc}"
                        )

            tx.state = TransactionState.ROLLED_BACK
            tx.ended_at = datetime.now(timezone.utc).isoformat()
            if reason:
                tx.warnings.append(f"Rollback reason: {reason}")

            self._active_transaction = None

            try:
                self._audit.log_event(
                    action=AuditAction.TRANSACTION_ROLLBACK,
                    resource=tx.id,
                    status="SUCCESS",
                    details={
                        "reason": reason or "explicit_rollback",
                        "affected_resources": tx.affected_resources(),
                    },
                )
            except Exception as exc:
                logger.debug(f"Audit log error during transaction.rollback: {exc}")

            logger.info(f"Rolled back transaction {tx.id}. Pre-transaction state restored.")
            return tx

    def undo(self, steps: int = 1) -> list[dict[str, Any]]:
        """Undo the last `steps` committed transactions."""
        with self._lock:
            if self._active_transaction is not None:
                raise TransactionError(
                    "Cannot perform undo while a transaction is currently active."
                )
            if not self._undo_stack:
                raise TransactionError("Undo stack is empty; nothing to undo.")

            undone: list[dict[str, Any]] = []
            for _ in range(min(steps, len(self._undo_stack))):
                tx = self._undo_stack.pop()

                # Restore pre-transaction state
                _restore_sqlite_file(tx.r2db_backup, _get_r2db_path(), tx.r2db_existed)
                _restore_sqlite_file(tx.memory_backup, _get_memory_db_path(), tx.memory_existed)
                report_sessions = _get_report_sessions_dict()
                if report_sessions is not None and tx.report_sessions_backup is not None:
                    report_sessions.clear()
                    report_sessions.update(copy.deepcopy(tx.report_sessions_backup))

                tx.state = TransactionState.UNDONE
                self._redo_stack.append(tx)
                undone.append(tx.to_dict())

            return undone

    def redo(self, steps: int = 1) -> list[dict[str, Any]]:
        """Redo the last `steps` undone transactions."""
        with self._lock:
            if self._active_transaction is not None:
                raise TransactionError(
                    "Cannot perform redo while a transaction is currently active."
                )
            if not self._redo_stack:
                raise TransactionError("Redo stack is empty; nothing to redo.")

            redone: list[dict[str, Any]] = []
            for _ in range(min(steps, len(self._redo_stack))):
                tx = self._redo_stack.pop()

                # Restore post-commit state
                if tx.post_commit_r2db_backup and tx.post_commit_r2db_backup.exists():
                    _restore_sqlite_file(
                        tx.post_commit_r2db_backup, _get_r2db_path(), existed_before=True
                    )
                if tx.post_commit_memory_backup and tx.post_commit_memory_backup.exists():
                    _restore_sqlite_file(
                        tx.post_commit_memory_backup, _get_memory_db_path(), existed_before=True
                    )
                report_sessions = _get_report_sessions_dict()
                if report_sessions is not None and tx.post_commit_report_sessions is not None:
                    report_sessions.clear()
                    report_sessions.update(copy.deepcopy(tx.post_commit_report_sessions))

                tx.state = TransactionState.COMMITTED
                self._undo_stack.append(tx)
                redone.append(tx.to_dict())

            return redone

    def status(self, tx_id: str | None = None) -> dict[str, Any]:
        """Inspect the current transaction and undo/redo history."""
        with self._lock:
            active_info = None
            if self._active_transaction is not None:
                if tx_id is None or self._active_transaction.id == tx_id:
                    active_info = self._active_transaction.to_dict()

            return {
                "active_transaction": active_info,
                "has_active_transaction": self._active_transaction is not None,
                "undo_depth": len(self._undo_stack),
                "redo_depth": len(self._redo_stack),
                "supported_mutation_classes": [c.value for c in MutationClass],
                "recent_committed_transactions": [tx.to_dict() for tx in self._undo_stack[-5:]],
            }

    def record_mutation(
        self,
        mutation_class: MutationClass | str,
        resource: str,
        action: str,
        details: dict[str, Any] | None = None,
        reversible: bool = True,
    ) -> None:
        """Record a mutation within the active transaction (no-op if no active transaction)."""
        with self._lock:
            if self._active_transaction is None:
                return

            m_class = (
                mutation_class.value
                if isinstance(mutation_class, MutationClass)
                else str(mutation_class)
            )
            now_iso = datetime.now(timezone.utc).isoformat()

            if not reversible:
                if self._active_transaction.strict:
                    tx_id = self._active_transaction.id
                    if self._active_transaction.auto_rollback_on_error:
                        self.rollback(
                            tx_id,
                            reason=f"Strict transaction rejected non-reversible action {action} on {resource}",
                        )
                    raise NonReversibleOperationError(
                        f"Operation '{action}' on resource '{resource}' is non-reversible, "
                        f"and transaction '{tx_id}' was started in strict mode."
                    )
                self._active_transaction.has_unreversible_actions = True
                warning_msg = (
                    f"Non-reversible action '{action}' on '{resource}' performed. "
                    "External side effects cannot be guaranteed to roll back."
                )
                if warning_msg not in self._active_transaction.warnings:
                    self._active_transaction.warnings.append(warning_msg)

            self._active_transaction.mutations.append(
                MutationRecord(
                    mutation_class=m_class,
                    resource=resource,
                    action=action,
                    reversible=reversible,
                    timestamp=now_iso,
                    details=details or {},
                )
            )

    def record_workspace_file_created(self, file_path: str | Path) -> None:
        """Track a created workspace artifact for automatic deletion on rollback."""
        with self._lock:
            if self._active_transaction is None:
                return
            p = str(Path(file_path).resolve())
            self._active_transaction.workspace_files_created.add(p)
            self.record_mutation(
                MutationClass.WORKSPACE_ARTIFACT,
                resource=f"file:{p}",
                action="create_file",
                reversible=True,
            )

    def record_workspace_file_modified(self, file_path: str | Path) -> None:
        """Track a modified workspace artifact by snapshotting its pre-modification state."""
        with self._lock:
            if self._active_transaction is None:
                return
            p = Path(file_path).resolve()
            p_str = str(p)
            if p_str in self._active_transaction.workspace_files_modified:
                return
            if p.exists() and self._active_transaction.checkpoint_dir:
                backup_name = (
                    f"mod_{len(self._active_transaction.workspace_files_modified)}_{p.name}"
                )
                backup_path = self._active_transaction.checkpoint_dir / backup_name
                shutil.copy2(p, backup_path)
                self._active_transaction.workspace_files_modified[p_str] = str(backup_path)
                self.record_mutation(
                    MutationClass.WORKSPACE_ARTIFACT,
                    resource=f"file:{p_str}",
                    action="modify_file",
                    reversible=True,
                )


def get_transaction_manager() -> TransactionManager:
    """Return the global TransactionManager instance."""
    return TransactionManager()


__all__ = [
    "MutationClass",
    "MutationRecord",
    "TransactionManager",
    "TransactionSnapshot",
    "TransactionState",
    "get_transaction_manager",
]
