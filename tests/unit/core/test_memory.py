"""Unit tests for the AI memory store module."""

import pytest
import pytest_asyncio

from reversecore_mcp.core.memory import MemoryStore


@pytest_asyncio.fixture
async def memory_store(tmp_path):
    """Create a temporary memory store for testing."""
    db_path = tmp_path / "test_memory.db"
    store = MemoryStore(db_path)
    await store.initialize()
    yield store
    await store.close()


class TestMemoryStoreInitialization:
    """Tests for memory store initialization and schema creation."""

    @pytest.mark.asyncio
    async def test_initialize_creates_database(self, tmp_path):
        """Database file should be created on initialization."""
        db_path = tmp_path / "new_memory.db"
        store = MemoryStore(db_path)

        assert not db_path.exists()
        await store.initialize()
        assert db_path.exists()
        await store.close()

    @pytest.mark.asyncio
    async def test_initialize_creates_parent_dirs(self, tmp_path):
        """Parent directories should be created if they don't exist."""
        db_path = tmp_path / "subdir" / "deeper" / "memory.db"
        store = MemoryStore(db_path)

        await store.initialize()
        assert db_path.exists()
        await store.close()

    @pytest.mark.asyncio
    async def test_double_initialization_is_safe(self, tmp_path):
        """Calling initialize twice should be a no-op."""
        db_path = tmp_path / "memory.db"
        store = MemoryStore(db_path)

        await store.initialize()
        await store.initialize()  # Should not raise
        await store.close()


class TestSessionManagement:
    """Tests for analysis session CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_session(self, memory_store):
        """Creating a session should return a valid UUID."""
        session_id = await memory_store.create_session(
            name="test_malware_001",
            binary_name="evil.exe",
            binary_hash="abc123",
        )

        assert session_id is not None
        assert len(session_id) == 36  # UUID format

    @pytest.mark.asyncio
    async def test_get_session(self, memory_store):
        """Should retrieve session by ID with all fields."""
        session_id = await memory_store.create_session(
            name="test_analysis",
            binary_name="sample.bin",
            binary_hash="hash123",
        )

        session = await memory_store.get_session(session_id)

        assert session is not None
        assert session["name"] == "test_analysis"
        assert session["binary_name"] == "sample.bin"
        assert session["binary_hash"] == "hash123"
        assert session["status"] == "in_progress"

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, memory_store):
        """Getting a non-existent session should return None."""
        session = await memory_store.get_session("fake-id-that-doesnt-exist")
        assert session is None

    @pytest.mark.asyncio
    async def test_list_sessions(self, memory_store):
        """Should list all sessions in descending update order."""
        await memory_store.create_session(name="session_1")
        await memory_store.create_session(name="session_2")
        await memory_store.create_session(name="session_3")

        sessions = await memory_store.list_sessions()

        assert len(sessions) == 3
        # Most recent first
        assert sessions[0]["name"] == "session_3"

    @pytest.mark.asyncio
    async def test_list_sessions_with_status_filter(self, memory_store):
        """Should filter sessions by status."""
        await memory_store.create_session(name="active_1")
        await memory_store.create_session(name="active_2")
        s3 = await memory_store.create_session(name="done")

        await memory_store.update_session(s3, status="completed")

        in_progress = await memory_store.list_sessions(status="in_progress")
        completed = await memory_store.list_sessions(status="completed")

        assert len(in_progress) == 2
        assert len(completed) == 1
        assert completed[0]["name"] == "done"

    @pytest.mark.asyncio
    async def test_update_session_status(self, memory_store):
        """Should update session status correctly."""
        session_id = await memory_store.create_session(name="test")

        success = await memory_store.update_session(session_id, status="completed")

        assert success
        session = await memory_store.get_session(session_id)
        assert session["status"] == "completed"

    @pytest.mark.asyncio
    async def test_update_session_duration(self, memory_store):
        """Should accumulate analysis duration."""
        session_id = await memory_store.create_session(name="test")

        await memory_store.update_session(session_id, add_duration=60.5)
        await memory_store.update_session(session_id, add_duration=30.0)

        session = await memory_store.get_session(session_id)
        assert session["analysis_duration_seconds"] == 90.5

    @pytest.mark.asyncio
    async def test_find_latest_session(self, memory_store):
        """Should find the most recent session."""
        await memory_store.create_session(name="old")
        await memory_store.create_session(name="newer")
        await memory_store.create_session(name="newest")

        latest = await memory_store.find_latest_session()

        assert latest is not None
        assert latest["name"] == "newest"

    @pytest.mark.asyncio
    async def test_find_latest_session_by_binary(self, memory_store):
        """Should find latest session for a specific binary."""
        await memory_store.create_session(name="other", binary_name="other.exe")
        await memory_store.create_session(name="target_old", binary_name="target.exe")
        await memory_store.create_session(name="target_new", binary_name="target.exe")

        latest = await memory_store.find_latest_session(binary_name="target.exe")

        assert latest["name"] == "target_new"


class TestMemoryOperations:
    """Tests for memory save and recall operations."""

    @pytest.mark.asyncio
    async def test_save_memory(self, memory_store):
        """Should save a memory and return its ID."""
        session_id = await memory_store.create_session(name="test")

        memory_id = await memory_store.save_memory(
            session_id=session_id,
            memory_type="finding",
            content={"address": "0x401000", "function": "main"},
            category="function",
            user_prompt="What's at main?",
            importance=8,
        )

        assert memory_id is not None
        assert memory_id > 0

    @pytest.mark.asyncio
    async def test_save_memory_string_content(self, memory_store):
        """Should accept string content as well as dict."""
        session_id = await memory_store.create_session(name="test")

        memory_id = await memory_store.save_memory(
            session_id=session_id,
            memory_type="instruction",
            content="Remember to check for anti-debug.",
        )

        assert memory_id > 0

    @pytest.mark.asyncio
    async def test_get_session_memories(self, memory_store):
        """Should retrieve all memories for a session."""
        session_id = await memory_store.create_session(name="test")

        await memory_store.save_memory(session_id, "finding", "Finding 1")
        await memory_store.save_memory(session_id, "pattern", "Pattern 1")
        await memory_store.save_memory(session_id, "finding", "Finding 2")

        memories = await memory_store.get_session_memories(session_id)

        assert len(memories) == 3

    @pytest.mark.asyncio
    async def test_get_session_memories_filtered(self, memory_store):
        """Should filter memories by type."""
        session_id = await memory_store.create_session(name="test")

        await memory_store.save_memory(session_id, "finding", "Finding 1")
        await memory_store.save_memory(session_id, "pattern", "Pattern 1")
        await memory_store.save_memory(session_id, "finding", "Finding 2")

        findings = await memory_store.get_session_memories(session_id, memory_type="finding")

        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_recall_memories_fts(self, memory_store):
        """Should find memories using full-text search."""
        session_id = await memory_store.create_session(name="test")

        await memory_store.save_memory(session_id, "finding", "VirtualAlloc API call detected")
        await memory_store.save_memory(session_id, "finding", "CreateRemoteThread found")
        await memory_store.save_memory(session_id, "finding", "Normal string data")

        results = await memory_store.recall_memories("VirtualAlloc")

        assert len(results) >= 1
        assert any("VirtualAlloc" in r["content"] for r in results)

    @pytest.mark.asyncio
    async def test_recall_memories_fallback(self, memory_store):
        """Should fall back to LIKE search on FTS failure."""
        session_id = await memory_store.create_session(name="test")

        await memory_store.save_memory(session_id, "finding", "CreateProcess API used")

        # Use regular search that will work with LIKE fallback
        results = await memory_store.recall_memories("CreateProcess")

        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_importance_ordering(self, memory_store):
        """Higher importance memories should appear first."""
        session_id = await memory_store.create_session(name="test")

        await memory_store.save_memory(session_id, "finding", "Low importance", importance=2)
        await memory_store.save_memory(session_id, "finding", "High importance", importance=9)
        await memory_store.save_memory(session_id, "finding", "Medium importance", importance=5)

        memories = await memory_store.get_session_memories(session_id)

        assert memories[0]["importance"] == 9
        assert memories[1]["importance"] == 5
        assert memories[2]["importance"] == 2


class TestPatternOperations:
    """Tests for pattern save and similarity search."""

    @pytest.mark.asyncio
    async def test_save_pattern(self, memory_store):
        """Should save a pattern and return its ID."""
        session_id = await memory_store.create_session(name="test")

        pattern_id = await memory_store.save_pattern(
            session_id=session_id,
            pattern_type="api_sequence",
            pattern_signature="VirtualAlloc,WriteProcessMemory,CreateRemoteThread",
            description="Common process injection pattern",
        )

        assert pattern_id > 0

    @pytest.mark.asyncio
    async def test_find_similar_patterns(self, memory_store):
        """Should find similar patterns from other sessions."""
        session1 = await memory_store.create_session(name="session1", binary_name="sample1.exe")
        session2 = await memory_store.create_session(name="session2", binary_name="sample2.exe")

        await memory_store.save_pattern(
            session1,
            "api_sequence",
            "VirtualAlloc,WriteProcessMemory,CreateRemoteThread",
            "Process injection",
        )

        similar = await memory_store.find_similar_patterns(
            pattern_signature="VirtualAlloc,WriteProcessMemory",
            exclude_session=session2,
        )

        assert len(similar) == 1
        assert similar[0]["session_name"] == "session1"

    @pytest.mark.asyncio
    async def test_find_similar_excludes_current(self, memory_store):
        """Should exclude current session from similarity results."""
        session = await memory_store.create_session(name="current")

        await memory_store.save_pattern(
            session,
            "api_sequence",
            "VirtualAlloc,WriteProcessMemory",
        )

        similar = await memory_store.find_similar_patterns(
            "VirtualAlloc",
            exclude_session=session,
        )

        assert len(similar) == 0


class TestContextRetrieval:
    """Tests for full context retrieval (session + memories + patterns)."""

    @pytest.mark.asyncio
    async def test_get_session_context(self, memory_store):
        """Should return complete session context."""
        session_id = await memory_store.create_session(
            name="full_test",
            binary_name="malware.exe",
        )

        await memory_store.save_memory(session_id, "finding", "Finding 1")
        await memory_store.save_memory(session_id, "instruction", "Check for packing")
        await memory_store.save_pattern(session_id, "behavior", "self_modifying_code")

        context = await memory_store.get_session_context(session_id)

        assert context["session"]["name"] == "full_test"
        assert context["memory_count"] == 2
        assert context["pattern_count"] == 1
        assert len(context["memories"]) == 2
        assert len(context["patterns"]) == 1

    @pytest.mark.asyncio
    async def test_get_session_context_empty(self, memory_store):
        """Should return empty dict for non-existent session."""
        context = await memory_store.get_session_context("fake-id")
        assert context == {}

    @pytest.mark.asyncio
    async def test_get_relevant_context(self, memory_store):
        """Should find relevant memories from past analyses."""
        old_session = await memory_store.create_session(name="old_analysis")
        new_session = await memory_store.create_session(name="new_analysis")

        await memory_store.save_memory(
            old_session,
            "finding",
            "Anti-debug techniques using IsDebuggerPresent",
        )

        relevant = await memory_store.get_relevant_context(
            current_analysis="IsDebuggerPresent",
            current_session_id=new_session,
        )

        assert len(relevant) >= 1
