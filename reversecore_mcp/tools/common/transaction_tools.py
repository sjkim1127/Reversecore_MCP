"""MCP tools for transaction and undo/rollback operations on Reversecore state.

Provides explicit transaction boundaries (begin, commit, rollback), status inspection,
and undo/redo history for agent-driven state mutation.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import (
    NoActiveTransactionError,
    TransactionError,
)
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.transaction import get_transaction_manager


@log_execution(tool_name="transaction_begin")
@track_metrics("transaction_begin")
@handle_tool_errors
async def transaction_begin(
    name: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional human-readable name or intent for the transaction (e.g. 'patch_function_auth').",
        ),
    ] = None,
    description: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional detailed description of the intended mutations.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        Field(
            default=False,
            description="If True, any non-reversible action (e.g., external subprocess execution) is rejected immediately.",
        ),
    ] = False,
    auto_rollback_on_error: Annotated[
        bool,
        Field(
            default=False,
            description="If True, encountering a non-reversible action in strict mode automatically triggers rollback.",
        ),
    ] = False,
) -> ToolResult:
    """Begin a new state mutation transaction.

    Checkpoints current Reversecore state (annotation database, memory sessions,
    report sessions, and reversible workspace artifacts). Subsequent mutations
    can be committed atomically or rolled back cleanly to this checkpoint.

    Args:
        name: Optional label for the transaction.
        description: Optional notes or reasoning for the transaction.
        strict: If True, rejects operations that cannot be safely rolled back.
        auto_rollback_on_error: If True, automatically rolls back on strict violation.

    Returns:
        ToolResult with status='success' and transaction details, or error.
    """
    mgr = get_transaction_manager()
    try:
        tx = mgr.begin(
            name=name,
            description=description,
            strict=strict,
            auto_rollback_on_error=auto_rollback_on_error,
        )
        return success(
            {
                "transaction_id": tx.id,
                "name": tx.name,
                "state": tx.state.value,
                "started_at": tx.started_at,
                "strict": tx.strict,
                "auto_rollback_on_error": tx.auto_rollback_on_error,
                "message": f"Transaction '{tx.id}' started successfully.",
            }
        )
    except TransactionError as exc:
        return failure("TRANSACTION_ALREADY_ACTIVE", str(exc))


@log_execution(tool_name="transaction_commit")
@track_metrics("transaction_commit")
@handle_tool_errors
async def transaction_commit(
    transaction_id: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional ID of the transaction to commit. If omitted, commits the currently active transaction.",
        ),
    ] = None,
) -> ToolResult:
    """Commit the active transaction and persist changes into the undo history.

    Atomically commits all mutations executed since transaction_begin, records
    affected objects in the security audit trail, and adds the transaction to
    the undo stack.

    Args:
        transaction_id: Optional transaction ID to commit.

    Returns:
        ToolResult with commit summary and list of affected resources.
    """
    mgr = get_transaction_manager()
    try:
        tx = mgr.commit(tx_id=transaction_id)
        return success(
            {
                "transaction_id": tx.id,
                "name": tx.name,
                "state": tx.state.value,
                "mutations_count": len(tx.mutations),
                "affected_resources": tx.affected_resources(),
                "warnings": tx.warnings,
                "is_clean_reversible": not tx.has_unreversible_actions,
                "message": f"Transaction '{tx.id}' committed successfully with {len(tx.mutations)} mutations.",
            }
        )
    except NoActiveTransactionError as exc:
        return failure("NO_ACTIVE_TRANSACTION", str(exc))
    except TransactionError as exc:
        return failure("TRANSACTION_ERROR", str(exc))


@log_execution(tool_name="transaction_rollback")
@track_metrics("transaction_rollback")
@handle_tool_errors
async def transaction_rollback(
    transaction_id: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional ID of the transaction to roll back. If omitted, rolls back the currently active transaction.",
        ),
    ] = None,
    reason: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional reason for the rollback (e.g. 'verification check failed').",
        ),
    ] = None,
) -> ToolResult:
    """Roll back the active transaction and restore pre-transaction Reversecore state.

    Restores the SQLite annotation database, memory sessions, report session
    metadata, and tracked workspace artifacts to their exact pre-transaction state.

    Args:
        transaction_id: Optional transaction ID to roll back.
        reason: Optional explanation for why the transaction is being rolled back.

    Returns:
        ToolResult confirming rollback and listing restored objects.
    """
    mgr = get_transaction_manager()
    try:
        tx = mgr.rollback(tx_id=transaction_id, reason=reason)
        return success(
            {
                "transaction_id": tx.id,
                "name": tx.name,
                "state": tx.state.value,
                "reason": reason or "explicit_rollback",
                "restored_resources": tx.affected_resources(),
                "warnings": tx.warnings,
                "message": f"Transaction '{tx.id}' rolled back. Pre-transaction state restored.",
            }
        )
    except NoActiveTransactionError as exc:
        return failure("NO_ACTIVE_TRANSACTION", str(exc))
    except TransactionError as exc:
        return failure("TRANSACTION_ERROR", str(exc))


@log_execution(tool_name="transaction_status")
@track_metrics("transaction_status")
@handle_tool_errors
async def transaction_status(
    transaction_id: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional transaction ID to query. If omitted, returns active transaction status and history.",
        ),
    ] = None,
) -> ToolResult:
    """Inspect current transaction state, uncommitted mutations, and undo/redo history.

    Provides visibility into active transaction status, affected resources,
    whether non-reversible actions have occurred, and available undo/redo steps.

    Args:
        transaction_id: Optional transaction ID to inspect.

    Returns:
        ToolResult with active transaction details and history depth.
    """
    mgr = get_transaction_manager()
    status_data = mgr.status(tx_id=transaction_id)
    return success(status_data)


@log_execution(tool_name="transaction_undo")
@track_metrics("transaction_undo")
@handle_tool_errors
async def transaction_undo(
    steps: Annotated[
        int,
        Field(
            default=1,
            description="Number of committed transactions to undo (default 1).",
        ),
    ] = 1,
) -> ToolResult:
    """Undo the last committed transaction(s).

    Restores Reversecore state to the checkpoint prior to the committed transaction,
    and moves the undone transaction to the redo stack.

    Args:
        steps: Number of transactions to undo.

    Returns:
        ToolResult with details of undone transactions and remaining history depth.
    """
    if steps < 1:
        return failure("VALIDATION_ERROR", "steps must be greater than or equal to 1.")

    mgr = get_transaction_manager()
    try:
        undone = mgr.undo(steps=steps)
        status_info = mgr.status()
        return success(
            {
                "undone_count": len(undone),
                "undone_transactions": undone,
                "undo_depth": status_info["undo_depth"],
                "redo_depth": status_info["redo_depth"],
                "message": f"Successfully undid {len(undone)} transaction(s).",
            }
        )
    except TransactionError as exc:
        return failure(
            "NOTHING_TO_UNDO" if "empty" in str(exc).lower() else "TRANSACTION_ERROR", str(exc)
        )


@log_execution(tool_name="transaction_redo")
@track_metrics("transaction_redo")
@handle_tool_errors
async def transaction_redo(
    steps: Annotated[
        int,
        Field(
            default=1,
            description="Number of undone transactions to redo (default 1).",
        ),
    ] = 1,
) -> ToolResult:
    """Redo the last undone transaction(s).

    Re-applies the committed state of previously undone transactions.

    Args:
        steps: Number of transactions to redo.

    Returns:
        ToolResult with details of redone transactions and updated history depth.
    """
    if steps < 1:
        return failure("VALIDATION_ERROR", "steps must be greater than or equal to 1.")

    mgr = get_transaction_manager()
    try:
        redone = mgr.redo(steps=steps)
        status_info = mgr.status()
        return success(
            {
                "redone_count": len(redone),
                "redone_transactions": redone,
                "undo_depth": status_info["undo_depth"],
                "redo_depth": status_info["redo_depth"],
                "message": f"Successfully redid {len(redone)} transaction(s).",
            }
        )
    except TransactionError as exc:
        return failure(
            "NOTHING_TO_REDO" if "empty" in str(exc).lower() else "TRANSACTION_ERROR", str(exc)
        )


__all__ = [
    "transaction_begin",
    "transaction_commit",
    "transaction_redo",
    "transaction_rollback",
    "transaction_status",
    "transaction_undo",
]
