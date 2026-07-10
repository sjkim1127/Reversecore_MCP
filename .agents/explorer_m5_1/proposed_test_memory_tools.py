"""Tests for reversecore_mcp.tools.common.memory_tools."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.tools.common.memory_tools import (
    MemoryToolsPlugin,
    register_memory_tools,
)


class TestMemoryToolsPlugin:
    """Tests for MemoryToolsPlugin."""

    @pytest.fixture
    def mock_store(self):
        """Mock memory store."""
        store = MagicMock()
        store.initialize = AsyncMock()
        store.create_session = AsyncMock(return_value="session_123")
        store.save_memory = AsyncMock(return_value="memory_456")
        store.get_memories = AsyncMock(return_value=[{"content": "test"}])
        store.get_session = AsyncMock(return_value={"name": "test_session"})
        store.list_sessions = AsyncMock(return_value=[{"id": "session_123"}])
        store.recall_memories = AsyncMock(return_value=[{"content": "test"}])
        store.get_session_context = AsyncMock()
        store.update_session = AsyncMock()
        store.find_latest_session = AsyncMock()
        store.save_pattern = AsyncMock()
        store.find_similar_patterns = AsyncMock()
        store.get_relevant_context = AsyncMock()
        return store

    @pytest.fixture
    def plugin(self, mock_store):
        """Create plugin with mocked store."""
        with patch(
            "reversecore_mcp.tools.common.memory_tools.get_memory_store",
            return_value=mock_store,
        ):
            p = MemoryToolsPlugin()
            yield p

    @pytest.fixture
    def mock_mcp(self):
        """Create mock MCP server."""
        mcp = MagicMock()
        mcp.tools = {}

        def tool_decorator(*args, **kwargs):
            if args and callable(args[0]):
                mcp.tools[args[0].__name__] = args[0]
                return args[0]

            def decorator(func):
                mcp.tools[func.__name__] = func
                return func

            return decorator

        mcp.tool = tool_decorator
        return mcp

    @pytest.mark.asyncio
    async def test_create_memory_session(self, plugin, mock_mcp, mock_store):
        """Test create_memory_session tool."""
        plugin.register(mock_mcp)
        create_session = mock_mcp.tools["create_memory_session"]
        result = await create_session(name="test_session")
        assert result["status"] == "success"
        assert result["session_id"] == "session_123"

    @pytest.mark.asyncio
    async def test_save_memory_item(self, plugin, mock_mcp, mock_store):
        """Test save_memory_item tool."""
        plugin.register(mock_mcp)
        save_memory = mock_mcp.tools["save_memory_item"]
        result = await save_memory(
            session_id="session_123",
            memory_type="insight",
            content="test content",
        )
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_recall_memory_item(self, plugin, mock_mcp, mock_store):
        """Test recall_memory_item tool."""
        plugin.register(mock_mcp)
        recall = mock_mcp.tools["recall_memory_item"]
        result = await recall(query="test")
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_create_memory_session_with_binary(self, plugin, mock_mcp, tmp_path):
        """Test session creation with binary path."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ")
        plugin.register(mock_mcp)
        create_session = mock_mcp.tools["create_memory_session"]
        result = await create_session(
            name="test",
            binary_path=str(binary),
        )
        assert result["status"] == "success"
        assert result["binary_hash"] is not None

    @pytest.mark.asyncio
    async def test_list_memory_sessions(self, plugin, mock_mcp, mock_store):
        """Test list_memory_sessions tool."""
        mock_store.list_sessions.return_value = [
            {"id": "session_123", "analysis_duration_seconds": 3660}
        ]
        plugin.register(mock_mcp)
        list_sessions = mock_mcp.tools["list_memory_sessions"]

        result = await list_sessions(status="in_progress", limit=5)

        mock_store.list_sessions.assert_called_once_with(status="in_progress", limit=5)
        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["sessions"][0]["analysis_duration_formatted"] == "1h 1m"

    @pytest.mark.asyncio
    async def test_get_memory_session_detail(self, plugin, mock_mcp, mock_store):
        """Test get_memory_session_detail tool."""
        mock_store.get_session_context.return_value = {
            "session": {"id": "session_123"},
            "memories": [{"id": "m1"}],
            "patterns": [{"id": "p1"}],
            "memory_count": 1,
            "pattern_count": 1,
        }
        plugin.register(mock_mcp)
        get_detail = mock_mcp.tools["get_memory_session_detail"]

        result = await get_detail(session_id="session_123")

        mock_store.get_session_context.assert_called_once_with("session_123")
        assert result["status"] == "success"
        assert result["session"] == {"id": "session_123"}
        assert result["memories"] == [{"id": "m1"}]
        assert result["patterns"] == [{"id": "p1"}]
        assert result["summary"] == {"memory_count": 1, "pattern_count": 1}

    @pytest.mark.asyncio
    async def test_get_memory_session_detail_not_found(self, plugin, mock_mcp, mock_store):
        """Test get_memory_session_detail tool when session is not found."""
        mock_store.get_session_context.return_value = {}
        plugin.register(mock_mcp)
        get_detail = mock_mcp.tools["get_memory_session_detail"]

        result = await get_detail(session_id="nonexistent")

        mock_store.get_session_context.assert_called_once_with("nonexistent")
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_resume_memory_session_by_id(self, plugin, mock_mcp, mock_store):
        """Test resume_memory_session tool with session_id."""
        mock_store.get_session.return_value = {
            "id": "session_123",
            "name": "test_session",
        }
        mock_store.update_session.return_value = True
        mock_store.get_session_context.return_value = {
            "session": {"id": "session_123"},
            "memories": [
                {"memory_type": "instruction", "content": "inst"},
                {"memory_type": "finding", "content": "finding"},
            ],
            "patterns": [],
            "memory_count": 2,
        }
        plugin.register(mock_mcp)
        resume_session = mock_mcp.tools["resume_memory_session"]

        result = await resume_session(session_id="session_123")

        mock_store.get_session.assert_called_once_with("session_123")
        mock_store.update_session.assert_called_once_with("session_123", status="in_progress")
        mock_store.get_session_context.assert_called_once_with("session_123")
        assert result["status"] == "success"
        assert result["session"] == {"id": "session_123"}
        assert len(result["instructions"]) == 1
        assert result["instructions"][0]["memory_type"] == "instruction"

    @pytest.mark.asyncio
    async def test_resume_memory_session_by_binary(self, plugin, mock_mcp, mock_store):
        """Test resume_memory_session tool with binary_name."""
        mock_store.find_latest_session.return_value = {
            "id": "session_456",
            "name": "latest_session",
        }
        mock_store.update_session.return_value = True
        mock_store.get_session_context.return_value = {
            "session": {"id": "session_456"},
            "memories": [],
            "patterns": [],
            "memory_count": 0,
        }
        plugin.register(mock_mcp)
        resume_session = mock_mcp.tools["resume_memory_session"]

        result = await resume_session(binary_name="test.exe")

        mock_store.find_latest_session.assert_called_once_with("test.exe")
        mock_store.update_session.assert_called_once_with("session_456", status="in_progress")
        mock_store.get_session_context.assert_called_once_with("session_456")
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_resume_memory_session_not_found(self, plugin, mock_mcp, mock_store):
        """Test resume_memory_session tool when no session is found."""
        mock_store.get_session.return_value = None
        plugin.register(mock_mcp)
        resume_session = mock_mcp.tools["resume_memory_session"]

        result = await resume_session(session_id="nonexistent")

        mock_store.get_session.assert_called_once_with("nonexistent")
        assert result["status"] == "error"
        assert "No session found" in result["message"]

    @pytest.mark.asyncio
    async def test_complete_memory_session(self, plugin, mock_mcp, mock_store):
        """Test complete_memory_session tool."""
        mock_store.update_session.return_value = True
        plugin.register(mock_mcp)
        complete_session = mock_mcp.tools["complete_memory_session"]

        result = await complete_session(
            session_id="session_123", summary="analysis completed successfully"
        )

        mock_store.update_session.assert_called_once_with(
            session_id="session_123",
            status="completed",
            summary="analysis completed successfully",
        )
        assert result["status"] == "success"
        assert result["summary"] == "analysis completed successfully"

    @pytest.mark.asyncio
    async def test_complete_memory_session_not_found(self, plugin, mock_mcp, mock_store):
        """Test complete_memory_session tool when session is not found."""
        mock_store.update_session.return_value = False
        plugin.register(mock_mcp)
        complete_session = mock_mcp.tools["complete_memory_session"]

        result = await complete_session(session_id="nonexistent", summary="summary")

        assert result["status"] == "error"
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_save_pattern(self, plugin, mock_mcp, mock_store):
        """Test save_pattern tool."""
        mock_store.save_pattern.return_value = 101
        plugin.register(mock_mcp)
        save_pattern_tool = mock_mcp.tools["save_pattern"]

        result = await save_pattern_tool(
            session_id="session_123",
            pattern_type="api_sequence",
            pattern_signature="VirtualAlloc,WriteProcessMemory",
            description="inject code",
        )

        mock_store.save_pattern.assert_called_once_with(
            session_id="session_123",
            pattern_type="api_sequence",
            pattern_signature="VirtualAlloc,WriteProcessMemory",
            description="inject code",
        )
        assert result["status"] == "success"
        assert result["pattern_id"] == 101

    @pytest.mark.asyncio
    async def test_find_similar_patterns(self, plugin, mock_mcp, mock_store):
        """Test find_similar_patterns tool."""
        mock_store.find_similar_patterns.return_value = [
            {
                "id": 101,
                "pattern_signature": "VirtualAlloc,WriteProcessMemory",
                "session_name": "prev_session",
            }
        ]
        plugin.register(mock_mcp)
        find_similar = mock_mcp.tools["find_similar_patterns"]

        result = await find_similar(
            pattern_signature="VirtualAlloc,WriteProcessMemory",
            pattern_type="api_sequence",
            current_session_id="session_123",
            limit=5,
        )

        mock_store.find_similar_patterns.assert_called_once_with(
            pattern_signature="VirtualAlloc,WriteProcessMemory",
            pattern_type="api_sequence",
            exclude_session="session_123",
            limit=5,
        )
        assert result["status"] == "success"
        assert result["count"] == 1
        assert "Found 1 similar patterns" in result["message"]

    @pytest.mark.asyncio
    async def test_find_similar_patterns_none(self, plugin, mock_mcp, mock_store):
        """Test find_similar_patterns tool when no similar pattern is found."""
        mock_store.find_similar_patterns.return_value = []
        plugin.register(mock_mcp)
        find_similar = mock_mcp.tools["find_similar_patterns"]

        result = await find_similar(pattern_signature="VirtualAlloc,WriteProcessMemory")

        assert result["status"] == "success"
        assert result["count"] == 0
        assert "No similar patterns found" in result["message"]

    @pytest.mark.asyncio
    async def test_get_relevant_context(self, plugin, mock_mcp, mock_store):
        """Test get_relevant_context tool."""
        mock_store.get_relevant_context.return_value = [{"id": 1, "content": "relevant finding"}]
        plugin.register(mock_mcp)
        get_context = mock_mcp.tools["get_relevant_context"]

        result = await get_context(
            description="process hollowing analysis",
            current_session_id="session_123",
            limit=3,
        )

        mock_store.get_relevant_context.assert_called_once_with(
            current_analysis="process hollowing analysis",
            current_session_id="session_123",
            limit=3,
        )
        assert result["status"] == "success"
        assert result["count"] == 1
        assert "Found 1 relevant memories" in result["message"]

    @pytest.mark.asyncio
    async def test_get_relevant_context_none(self, plugin, mock_mcp, mock_store):
        """Test get_relevant_context tool when no context is found."""
        mock_store.get_relevant_context.return_value = []
        plugin.register(mock_mcp)
        get_context = mock_mcp.tools["get_relevant_context"]

        result = await get_context(description="process hollowing analysis")

        assert result["status"] == "success"
        assert result["count"] == 0
        assert "No relevant past context found" in result["message"]

    @pytest.mark.asyncio
    async def test_update_memory_session_time(self, plugin, mock_mcp, mock_store):
        """Test update_memory_session_time tool."""
        mock_store.update_session.return_value = True
        plugin.register(mock_mcp)
        update_time = mock_mcp.tools["update_memory_session_time"]

        result = await update_time(session_id="session_123", duration_seconds=120.5)

        mock_store.update_session.assert_called_once_with(
            session_id="session_123", add_duration=120.5
        )
        assert result["status"] == "success"
        assert "Added 120.5s to analysis time" in result["message"]

    @pytest.mark.asyncio
    async def test_update_memory_session_time_error(self, plugin, mock_mcp, mock_store):
        """Test update_memory_session_time tool error handling."""
        mock_store.update_session.return_value = False
        plugin.register(mock_mcp)
        update_time = mock_mcp.tools["update_memory_session_time"]

        result = await update_time(session_id="session_123", duration_seconds=120.5)

        assert result["status"] == "error"


class TestRegisterMemoryTools:
    """Tests for register_memory_tools."""

    def test_registration(self):
        mock_mcp = MagicMock()
        register_memory_tools(mock_mcp)
        # plugin.register calls mcp.tool() 11 times
        assert mock_mcp.tool.call_count == 11
