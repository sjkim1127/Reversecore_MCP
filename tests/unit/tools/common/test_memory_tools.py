"""Tests for reversecore_mcp.tools.common.memory_tools."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.tools.common.memory_tools import MemoryToolsPlugin, register_memory_tools


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
        return store

    @pytest.fixture
    def plugin(self, mock_store):
        """Create plugin with mocked store."""
        with patch(
            "reversecore_mcp.tools.common.memory_tools.get_memory_store", return_value=mock_store
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


class TestRegisterMemoryTools:
    """Tests for register_memory_tools."""

    def test_registration(self):
        mock_mcp = MagicMock()
        register_memory_tools(mock_mcp)
        # plugin.register calls mcp.tool() 11 times
        assert mock_mcp.tool.call_count == 11
