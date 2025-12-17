"""
AI Long-term Memory Storage System.

This module provides persistent memory storage for AI analysis sessions,
enabling multi-session memory, cross-project knowledge transfer, and
context retrieval (injection) capabilities.

Storage backend: SQLite with FTS5 for full-text search.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# Default database path
DEFAULT_MEMORY_DB_PATH = Path.home() / ".reversecore_mcp" / "memory.db"


class MemoryStore:
    """
    AI Long-term Memory Storage.

    Provides persistent storage for analysis sessions and memories,
    enabling context preservation across multiple sessions.

    Features:
        - Multi-session memory: Resume analysis with full context
        - Cross-project knowledge transfer: Find similar patterns from past analyses
        - Long-term storage: Persist function addresses, vulnerability patterns, user instructions
        - Context retrieval: Inject relevant past information into current analysis
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize the memory store.

        Args:
            db_path: Path to SQLite database file. Defaults to ~/.reversecore_mcp/memory.db
        """
        self.db_path = db_path or DEFAULT_MEMORY_DB_PATH
        self._db: aiosqlite.Connection | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize the database connection and create schema if needed.

        Creates parent directories and database file if they don't exist.
        """
        if self._initialized:
            return

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row

        await self._create_schema()

        # Enable WAL mode for better concurrency
        await self._db.execute("PRAGMA journal_mode=WAL;")

        self._initialized = True
        logger.info(f"Memory store initialized at {self.db_path} (WAL enabled)")

    async def _create_schema(self) -> None:
        """Create database schema if not exists."""
        assert self._db is not None

        # Analysis sessions table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                binary_name TEXT,
                binary_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                analysis_duration_seconds REAL DEFAULT 0,
                status TEXT DEFAULT 'in_progress',
                summary TEXT
            )
        """)

        # Memories table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                memory_type TEXT NOT NULL,
                category TEXT,
                content TEXT NOT NULL,
                user_prompt TEXT,
                importance INTEGER DEFAULT 5,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions(id)
            )
        """)

        # Patterns table for cross-session similarity search
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                pattern_signature TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions(id)
            )
        """)

        # Indexes for faster queries
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_memories_session
            ON memories(session_id)
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_memories_type
            ON memories(memory_type, category)
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_patterns_signature
            ON patterns(pattern_signature)
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_status
            ON analysis_sessions(status)
        """)

        # FTS5 virtual table for full-text search
        await self._db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts
            USING fts5(content, content=memories, content_rowid=id)
        """)

        # Triggers to keep FTS index in sync
        await self._db.execute("""
            CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content);
            END
        """)
        await self._db.execute("""
            CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, content)
                VALUES('delete', old.id, old.content);
            END
        """)
        await self._db.execute("""
            CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, content)
                VALUES('delete', old.id, old.content);
                INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content);
            END
        """)

        await self._db.commit()

    async def close(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None
            self._initialized = False
            logger.info("Memory store closed")

    @asynccontextmanager
    async def _ensure_connection(self):
        """Ensure database is connected before operations."""
        if not self._initialized:
            await self.initialize()
        yield self._db

    # =========================================================================
    # Session Management
    # =========================================================================

    async def create_session(
        self,
        name: str,
        binary_name: str | None = None,
        binary_hash: str | None = None,
    ) -> str:
        """
        Create a new analysis session.

        Args:
            name: Template name for the session (e.g., "malware_analysis_2024_001")
            binary_name: Name of the binary being analyzed
            binary_hash: SHA256 hash of the binary

        Returns:
            Session ID (UUID)
        """
        async with self._ensure_connection() as db:
            session_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()

            await db.execute(
                """
                INSERT INTO analysis_sessions
                (id, name, binary_name, binary_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, name, binary_name, binary_hash, now, now),
            )
            await db.commit()

            logger.info(f"Created session: {name} (ID: {session_id[:8]}...)")
            return session_id

    async def get_session(self, session_id: str) -> dict | None:
        """
        Get session details by ID.

        Args:
            session_id: Session UUID

        Returns:
            Session details dict or None if not found
        """
        async with self._ensure_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM analysis_sessions WHERE id = ?",
                (session_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_sessions(
        self,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """
        List analysis sessions with optional filtering.

        Args:
            status: Filter by status ('in_progress', 'completed', 'paused')
            limit: Maximum number of results
            offset: Pagination offset

        Returns:
            List of session dictionaries
        """
        async with self._ensure_connection() as db:
            if status:
                cursor = await db.execute(
                    """
                    SELECT * FROM analysis_sessions
                    WHERE status = ?
                    ORDER BY updated_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (status, limit, offset),
                )
            else:
                cursor = await db.execute(
                    """
                    SELECT * FROM analysis_sessions
                    ORDER BY updated_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def update_session(
        self,
        session_id: str,
        status: str | None = None,
        summary: str | None = None,
        add_duration: float = 0,
    ) -> bool:
        """
        Update session status and metadata.

        Args:
            session_id: Session UUID
            status: New status value
            summary: AI-generated analysis summary
            add_duration: Additional analysis time to accumulate (seconds)

        Returns:
            True if session was updated
        """
        async with self._ensure_connection() as db:
            updates = ["updated_at = ?"]
            params: list[Any] = [datetime.utcnow().isoformat()]

            if status:
                updates.append("status = ?")
                params.append(status)
            if summary:
                updates.append("summary = ?")
                params.append(summary)
            if add_duration > 0:
                updates.append("analysis_duration_seconds = analysis_duration_seconds + ?")
                params.append(add_duration)

            params.append(session_id)

            cursor = await db.execute(
                f"UPDATE analysis_sessions SET {', '.join(updates)} WHERE id = ?",  # nosec
                params,
            )
            await db.commit()

            return cursor.rowcount > 0

    async def find_latest_session(self, binary_name: str | None = None) -> dict | None:
        """
        Find the most recent session, optionally filtered by binary name.

        Args:
            binary_name: Filter by binary name (optional)

        Returns:
            Latest session dict or None
        """
        async with self._ensure_connection() as db:
            if binary_name:
                cursor = await db.execute(
                    """
                    SELECT * FROM analysis_sessions
                    WHERE binary_name = ?
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (binary_name,),
                )
            else:
                cursor = await db.execute(
                    """
                    SELECT * FROM analysis_sessions
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """
                )

            row = await cursor.fetchone()
            return dict(row) if row else None

    # =========================================================================
    # Memory Operations
    # =========================================================================

    async def save_memory(
        self,
        session_id: str,
        memory_type: str,
        content: dict | str,
        category: str | None = None,
        user_prompt: str | None = None,
        importance: int = 5,
    ) -> int:
        """
        Save a memory entry to the store.

        Args:
            session_id: Parent session ID
            memory_type: Type of memory ('finding', 'pattern', 'instruction', 'context')
            content: Memory content (dict or string, stored as JSON)
            category: Optional category ('function', 'vulnerability', 'string', 'structure')
            user_prompt: User's prompt at the time of saving
            importance: Importance level 1-10 (default 5)

        Returns:
            Memory ID
        """
        async with self._ensure_connection() as db:
            content_str = json.dumps(content) if isinstance(content, dict) else content

            cursor = await db.execute(
                """
                INSERT INTO memories
                (session_id, memory_type, category, content, user_prompt, importance)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, memory_type, category, content_str, user_prompt, importance),
            )
            await db.commit()

            # Also update session timestamp
            await self.update_session(session_id)

            memory_id = cursor.lastrowid
            logger.debug(f"Saved memory {memory_id} to session {session_id[:8]}...")
            return memory_id

    async def recall_memories(
        self,
        query: str,
        session_id: str | None = None,
        memory_type: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        """
        Recall memories matching a search query using full-text search.

        Args:
            query: Search query
            session_id: Limit to specific session (optional)
            memory_type: Filter by memory type (optional)
            limit: Maximum results

        Returns:
            List of matching memories with relevance ranking
        """
        async with self._ensure_connection() as db:
            # Build query with optional filters
            base_query = """
                SELECT m.*, s.name as session_name, s.binary_name
                FROM memories m
                JOIN analysis_sessions s ON m.session_id = s.id
                JOIN memories_fts fts ON m.id = fts.rowid
                WHERE memories_fts MATCH ?
            """
            # Sanitize query for FTS5
            # 1. Escape double quotes
            safe_query = query.replace('"', '""')
            # 2. Wrap in quotes to treat as phrase if it contains spaces or symbols
            # This prevents syntax errors from FTS5 operators in user input
            if any(c in safe_query for c in " .-_"):
                safe_query = f'"{safe_query}"'

            # Use raw query if it seems to be an explicit FTS query (this is a heuristic)
            if " OR " in query or " AND " in query or "NEAR(" in query:
                # Trust the user if they look like they know FTS syntax, but still risk error
                # For safety in this fix, we prioritize stability over advanced syntax for raw inputs
                # so we stick to the safe version unless we validate it.
                # Reverting to safe method for now as per plan.
                pass

            params: list[Any] = [safe_query]

            if session_id:
                base_query += " AND m.session_id = ?"
                params.append(session_id)
            if memory_type:
                base_query += " AND m.memory_type = ?"
                params.append(memory_type)

            base_query += " ORDER BY m.importance DESC, m.created_at DESC LIMIT ?"
            params.append(limit)

            try:
                cursor = await db.execute(base_query, params)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
            except Exception as e:
                # FTS match might fail on invalid queries, fall back to LIKE
                logger.warning(f"FTS search failed, falling back to LIKE: {e}")
                return await self._recall_memories_fallback(query, session_id, memory_type, limit)

    async def _recall_memories_fallback(
        self,
        query: str,
        session_id: str | None,
        memory_type: str | None,
        limit: int,
    ) -> list[dict]:
        """Fallback search using LIKE when FTS fails."""
        async with self._ensure_connection() as db:
            base_query = """
                SELECT m.*, s.name as session_name, s.binary_name
                FROM memories m
                JOIN analysis_sessions s ON m.session_id = s.id
                WHERE m.content LIKE ?
            """
            # PERFORMANCE: Use suffix-only wildcard when possible for index usage
            # Note: still uses leading wildcard for fallback - consider FTS5 for better perf
            params: list[Any] = [f"%{query}%"]

            if session_id:
                base_query += " AND m.session_id = ?"
                params.append(session_id)
            if memory_type:
                base_query += " AND m.memory_type = ?"
                params.append(memory_type)

            base_query += " ORDER BY m.importance DESC, m.created_at DESC LIMIT ?"
            params.append(limit)

            cursor = await db.execute(base_query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_session_memories(
        self,
        session_id: str,
        memory_type: str | None = None,
    ) -> list[dict]:
        """
        Get all memories for a session.

        Args:
            session_id: Session ID
            memory_type: Optional filter by type

        Returns:
            List of memories for the session
        """
        async with self._ensure_connection() as db:
            if memory_type:
                cursor = await db.execute(
                    """
                    SELECT * FROM memories
                    WHERE session_id = ? AND memory_type = ?
                    ORDER BY importance DESC, created_at ASC
                    """,
                    (session_id, memory_type),
                )
            else:
                cursor = await db.execute(
                    """
                    SELECT * FROM memories
                    WHERE session_id = ?
                    ORDER BY importance DESC, created_at ASC
                    """,
                    (session_id,),
                )

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    # =========================================================================
    # Pattern Recognition
    # =========================================================================

    async def save_pattern(
        self,
        session_id: str,
        pattern_type: str,
        pattern_signature: str,
        description: str | None = None,
    ) -> int:
        """
        Save a pattern for cross-session similarity search.

        Args:
            session_id: Session where pattern was found
            pattern_type: Type ('api_sequence', 'code_pattern', 'behavior')
            pattern_signature: Normalized pattern signature for matching
            description: Human-readable description

        Returns:
            Pattern ID
        """
        async with self._ensure_connection() as db:
            cursor = await db.execute(
                """
                INSERT INTO patterns
                (session_id, pattern_type, pattern_signature, description)
                VALUES (?, ?, ?, ?)
                """,
                (session_id, pattern_type, pattern_signature, description),
            )
            await db.commit()
            return cursor.lastrowid

    async def find_similar_patterns(
        self,
        pattern_signature: str,
        pattern_type: str | None = None,
        exclude_session: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        """
        Find similar patterns from previous analyses.

        Args:
            pattern_signature: Pattern to search for
            pattern_type: Limit to specific pattern type
            exclude_session: Exclude patterns from this session
            limit: Maximum results

        Returns:
            List of similar patterns with session info
        """
        async with self._ensure_connection() as db:
            base_query = """
                SELECT p.*, s.name as session_name, s.binary_name
                FROM patterns p
                JOIN analysis_sessions s ON p.session_id = s.id
                WHERE p.pattern_signature LIKE ?
            """
            # PERFORMANCE: For exact prefix matching, use suffix-only wildcard
            # This allows SQLite to use the idx_patterns_signature index
            params: list[Any] = [f"{pattern_signature}%"]

            if pattern_type:
                base_query += " AND p.pattern_type = ?"
                params.append(pattern_type)
            if exclude_session:
                base_query += " AND p.session_id != ?"
                params.append(exclude_session)

            base_query += " ORDER BY p.created_at DESC LIMIT ?"
            params.append(limit)

            cursor = await db.execute(base_query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    # =========================================================================
    # Context Retrieval (Injection)
    # =========================================================================

    async def get_session_context(self, session_id: str) -> dict:
        """
        Get full context for a session including all memories and patterns.

        This is used to restore full context when resuming a session.

        Args:
            session_id: Session ID

        Returns:
            Dict containing session info, memories, and patterns
        """
        session = await self.get_session(session_id)
        if not session:
            return {}

        memories = await self.get_session_memories(session_id)

        async with self._ensure_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM patterns WHERE session_id = ?",
                (session_id,),
            )
            patterns = [dict(row) for row in await cursor.fetchall()]

        return {
            "session": session,
            "memories": memories,
            "patterns": patterns,
            "memory_count": len(memories),
            "pattern_count": len(patterns),
        }

    async def get_relevant_context(
        self,
        current_analysis: str,
        current_session_id: str | None = None,
        limit: int = 5,
    ) -> list[dict]:
        """
        Get relevant context from past analyses for current work.

        This enables the "Hey, this looks similar to what we saw before" feature.

        Args:
            current_analysis: Description of current analysis focus
            current_session_id: Current session to exclude from results
            limit: Maximum relevant items to return

        Returns:
            List of relevant memories from past sessions
        """
        memories = await self.recall_memories(
            query=current_analysis,
            limit=limit * 2,  # Fetch more to filter
        )

        # Filter out current session if specified
        if current_session_id:
            memories = [m for m in memories if m.get("session_id") != current_session_id]

        return memories[:limit]


# Module-level singleton instance
_memory_store: MemoryStore | None = None


def get_memory_store(db_path: Path | None = None) -> MemoryStore:
    """
    Get the global memory store instance.

    Args:
        db_path: Optional custom database path

    Returns:
        MemoryStore singleton instance
    """
    global _memory_store
    if _memory_store is None:
        _memory_store = MemoryStore(db_path)
    return _memory_store


async def initialize_memory_store(db_path: Path | None = None) -> MemoryStore:
    """
    Initialize and return the memory store.

    Args:
        db_path: Optional custom database path

    Returns:
        Initialized MemoryStore instance
    """
    store = get_memory_store(db_path)
    await store.initialize()
    return store
