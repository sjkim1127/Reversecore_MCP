"""
MCP Memory Tools for AI Long-term Memory.

This module provides MCP-compatible tools for managing AI analysis memories,
enabling multi-session memory persistence and cross-project knowledge transfer.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.memory import get_memory_store, initialize_memory_store
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class MemoryToolsPlugin(Plugin):
    """Plugin for AI memory management tools."""

    name = "memory_tools"
    description = "AI long-term memory management for analysis sessions"

    def register(self, mcp: FastMCP) -> None:
        """Register all memory tools with the MCP server."""

        @mcp.tool()
        async def create_analysis_session(
            name: str,
            binary_name: str | None = None,
            binary_path: str | None = None,
        ) -> dict[str, Any]:
            """
            Create a new analysis session to store memories.

            Use this when starting a new reverse engineering analysis.
            The session name should be descriptive and follow a template format
            like 'malware_analysis_2024_001' or 'game_cheat_detection'.

            Args:
                name: Template name for the session (e.g., 'malware_sample_001')
                binary_name: Name of the binary being analyzed (optional)
                binary_path: Path to binary for automatic hash calculation (optional)

            Returns:
                Session information including ID for future reference
            """
            store = get_memory_store()
            await store.initialize()

            # Calculate hash if path provided
            binary_hash = None
            if binary_path:
                try:
                    path = Path(binary_path)
                    if path.exists():
                        binary_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                        if not binary_name:
                            binary_name = path.name
                except Exception as e:
                    logger.warning(f"Could not hash binary: {e}")

            session_id = await store.create_session(
                name=name,
                binary_name=binary_name,
                binary_hash=binary_hash,
            )

            return {
                "status": "success",
                "session_id": session_id,
                "name": name,
                "binary_name": binary_name,
                "binary_hash": binary_hash,
                "message": f"Analysis session '{name}' created. Use this session_id to save memories.",
            }

        @mcp.tool()
        async def save_analysis_memory(
            session_id: str,
            memory_type: str,
            content: str,
            category: str | None = None,
            user_prompt: str | None = None,
            importance: int = 5,
        ) -> dict[str, Any]:
            """
            Save important information to long-term memory.

            Use this to remember:
            - Function addresses and their purposes
            - Vulnerability patterns discovered
            - API call sequences
            - User instructions and preferences
            - Interesting strings or structures

            Args:
                session_id: Session ID from create_analysis_session
                memory_type: Type of memory:
                    - 'finding': Analysis discoveries
                    - 'pattern': Code/behavior patterns
                    - 'instruction': User preferences/instructions
                    - 'context': General context information
                category: Optional category:
                    - 'function': Function-related info
                    - 'vulnerability': Security issues
                    - 'string': Important strings
                    - 'structure': Data structures
                    - 'api': API usage patterns
                content: The actual content to remember (text or JSON string)
                user_prompt: The user's prompt when this was discovered (optional)
                importance: Importance level 1-10 (default 5, higher = more important)

            Returns:
                Confirmation with memory ID
            """
            store = get_memory_store()
            await store.initialize()

            memory_id = await store.save_memory(
                session_id=session_id,
                memory_type=memory_type,
                content=content,
                category=category,
                user_prompt=user_prompt,
                importance=importance,
            )

            return {
                "status": "success",
                "memory_id": memory_id,
                "message": f"Memory saved (ID: {memory_id}, importance: {importance}/10)",
            }

        @mcp.tool()
        async def recall_analysis_memory(
            query: str,
            session_id: str | None = None,
            memory_type: str | None = None,
            limit: int = 10,
        ) -> dict[str, Any]:
            """
            Search and recall memories from past analyses.

            Use this when you need to remember something from earlier,
            or when the user asks about previous findings.

            Args:
                query: Search query (keywords or phrases)
                session_id: Limit search to specific session (optional)
                memory_type: Filter by type ('finding', 'pattern', 'instruction', 'context')
                limit: Maximum number of results (default 10)

            Returns:
                List of matching memories with context
            """
            store = get_memory_store()
            await store.initialize()

            memories = await store.recall_memories(
                query=query,
                session_id=session_id,
                memory_type=memory_type,
                limit=limit,
            )

            return {
                "status": "success",
                "count": len(memories),
                "memories": memories,
                "message": f"Found {len(memories)} relevant memories",
            }

        @mcp.tool()
        async def list_analysis_sessions(
            status: str | None = None,
            limit: int = 20,
        ) -> dict[str, Any]:
            """
            List all analysis sessions with timestamps and status.

            Use this to see what analyses have been done before,
            or to find a session to resume.

            Args:
                status: Filter by status ('in_progress', 'completed', 'paused')
                limit: Maximum number of sessions to return

            Returns:
                List of sessions with metadata
            """
            store = get_memory_store()
            await store.initialize()

            sessions = await store.list_sessions(status=status, limit=limit)

            # Format timestamps for readability
            for session in sessions:
                if session.get("analysis_duration_seconds"):
                    duration = session["analysis_duration_seconds"]
                    hours = int(duration // 3600)
                    minutes = int((duration % 3600) // 60)
                    session["analysis_duration_formatted"] = f"{hours}h {minutes}m"

            return {
                "status": "success",
                "count": len(sessions),
                "sessions": sessions,
            }

        @mcp.tool()
        async def get_session_detail(
            session_id: str,
        ) -> dict[str, Any]:
            """
            Get complete details and context for a specific session.

            Use this when resuming an analysis or reviewing past work.
            Returns all memories and patterns associated with the session.

            Args:
                session_id: Session ID to retrieve

            Returns:
                Full session context including all memories and patterns
            """
            store = get_memory_store()
            await store.initialize()

            context = await store.get_session_context(session_id)

            if not context:
                return {
                    "status": "error",
                    "message": f"Session '{session_id}' not found",
                }

            return {
                "status": "success",
                "session": context["session"],
                "memories": context["memories"],
                "patterns": context["patterns"],
                "summary": {
                    "memory_count": context["memory_count"],
                    "pattern_count": context["pattern_count"],
                },
                "message": "Session context retrieved. Use this to resume analysis.",
            }

        @mcp.tool()
        async def resume_session(
            session_id: str | None = None,
            binary_name: str | None = None,
        ) -> dict[str, Any]:
            """
            Resume a previous analysis session with full context restoration.

            Use this when the user says "continue where we left off" or
            "resume yesterday's analysis".

            Args:
                session_id: Specific session ID to resume (optional)
                binary_name: Find latest session for this binary (optional)

            Returns:
                Full session context for resumption

            Note:
                If neither argument provided, resumes the most recent session.
            """
            store = get_memory_store()
            await store.initialize()

            # Find session to resume
            if session_id:
                session = await store.get_session(session_id)
            else:
                session = await store.find_latest_session(binary_name)

            if not session:
                return {
                    "status": "error",
                    "message": "No session found to resume. Start a new session with create_analysis_session.",
                }

            # Update session status
            await store.update_session(session["id"], status="in_progress")

            # Get full context
            context = await store.get_session_context(session["id"])

            return {
                "status": "success",
                "message": f"Resuming session '{session['name']}' with {context['memory_count']} memories",
                "session": context["session"],
                "memories": context["memories"],
                "patterns": context["patterns"],
                "instructions": [
                    m for m in context["memories"] if m.get("memory_type") == "instruction"
                ],
            }

        @mcp.tool()
        async def complete_session(
            session_id: str,
            summary: str,
        ) -> dict[str, Any]:
            """
            Mark an analysis session as completed with a summary.

            Use this when finishing an analysis to save a summary
            for future reference.

            Args:
                session_id: Session ID to complete
                summary: AI-generated summary of the analysis findings

            Returns:
                Confirmation of completion
            """
            store = get_memory_store()
            await store.initialize()

            success = await store.update_session(
                session_id=session_id,
                status="completed",
                summary=summary,
            )

            if not success:
                return {
                    "status": "error",
                    "message": f"Session '{session_id}' not found",
                }

            return {
                "status": "success",
                "message": "Session marked as completed",
                "summary": summary,
            }

        @mcp.tool()
        async def save_pattern(
            session_id: str,
            pattern_type: str,
            pattern_signature: str,
            description: str | None = None,
        ) -> dict[str, Any]:
            """
            Save a code/behavior pattern for cross-session similarity search.

            Use this when you discover a notable pattern that might appear
            in other samples. This enables "Hey, this looks similar to before!"

            Args:
                session_id: Current session ID
                pattern_type: Type of pattern:
                    - 'api_sequence': Sequence of API calls
                    - 'code_pattern': Assembly/code pattern
                    - 'behavior': Behavioral pattern
                pattern_signature: Normalized pattern signature for matching
                    Example: "VirtualAlloc,WriteProcessMemory,CreateRemoteThread"
                description: Human-readable description of the pattern

            Returns:
                Confirmation with pattern ID
            """
            store = get_memory_store()
            await store.initialize()

            pattern_id = await store.save_pattern(
                session_id=session_id,
                pattern_type=pattern_type,
                pattern_signature=pattern_signature,
                description=description,
            )

            return {
                "status": "success",
                "pattern_id": pattern_id,
                "message": f"Pattern saved for cross-session matching",
            }

        @mcp.tool()
        async def find_similar_patterns(
            pattern_signature: str,
            pattern_type: str | None = None,
            current_session_id: str | None = None,
            limit: int = 10,
        ) -> dict[str, Any]:
            """
            Find similar patterns from previous analyses.

            Use this to check if current findings match anything
            from past analyses. Enables knowledge transfer across projects.

            Args:
                pattern_signature: Pattern to search for
                pattern_type: Limit to specific type (optional)
                current_session_id: Exclude current session from results
                limit: Maximum results

            Returns:
                List of similar patterns with session context
            """
            store = get_memory_store()
            await store.initialize()

            similar = await store.find_similar_patterns(
                pattern_signature=pattern_signature,
                pattern_type=pattern_type,
                exclude_session=current_session_id,
                limit=limit,
            )

            if similar:
                message = f"Found {len(similar)} similar patterns from previous analyses!"
            else:
                message = "No similar patterns found in previous analyses."

            return {
                "status": "success",
                "count": len(similar),
                "similar_patterns": similar,
                "message": message,
            }

        @mcp.tool()
        async def get_relevant_context(
            description: str,
            current_session_id: str | None = None,
            limit: int = 5,
        ) -> dict[str, Any]:
            """
            Get relevant context from past analyses for current work.

            Use this proactively when analyzing something new to check
            if there's relevant knowledge from previous sessions.

            Args:
                description: Description of what you're currently analyzing
                current_session_id: Current session to exclude
                limit: Maximum relevant items

            Returns:
                Relevant memories from past sessions
            """
            store = get_memory_store()
            await store.initialize()

            relevant = await store.get_relevant_context(
                current_analysis=description,
                current_session_id=current_session_id,
                limit=limit,
            )

            if relevant:
                message = f"Found {len(relevant)} relevant memories from past analyses"
            else:
                message = "No relevant past context found"

            return {
                "status": "success",
                "count": len(relevant),
                "relevant_memories": relevant,
                "message": message,
            }

        @mcp.tool()
        async def update_analysis_time(
            session_id: str,
            duration_seconds: float,
        ) -> dict[str, Any]:
            """
            Update the cumulative analysis time for a session.

            Call this periodically to track how long an analysis takes.

            Args:
                session_id: Session ID
                duration_seconds: Additional time to add (in seconds)

            Returns:
                Confirmation
            """
            store = get_memory_store()
            await store.initialize()

            success = await store.update_session(
                session_id=session_id,
                add_duration=duration_seconds,
            )

            return {
                "status": "success" if success else "error",
                "message": f"Added {duration_seconds:.1f}s to analysis time",
            }

        logger.info(f"Registered {self.name} plugin with 11 tools")


def register_memory_tools(mcp: FastMCP) -> None:
    """
    Register memory tools with an MCP server instance.

    Args:
        mcp: FastMCP server instance
    """
    plugin = MemoryToolsPlugin()
    plugin.register(mcp)
