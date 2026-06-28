# Analysis: Extending the `mock_store` Fixture for MCP Memory Tools

This analysis evaluates how to extend the `mock_store` fixture in `tests/unit/tools/common/test_memory_tools.py` to support testing all 11 memory tools. It also examines if and how the registration tests should be updated.

---

## 1. Memory Store Method Usage across All 11 Tools

Across the 11 memory tools, the memory store singleton returned by `get_memory_store()` is initialized and queried via several async methods. Below is the comprehensive list of methods called, their signatures, parameters, and the expected mock return values.

| # | Method Name | Called By Tool(s) | Method Signature & Expected Arguments | Expected Mock Return Type & Example Value |
|---|---|---|---|---|
| 1 | `initialize` | All 11 tools | `async def initialize(self) -> None` <br> No arguments. | `None` |
| 2 | `create_session` | `create_memory_session` | `async def create_session(self, name: str, binary_name: str \| None = None, binary_hash: str \| None = None) -> str` | `str` <br> e.g. `"session_123"` |
| 3 | `save_memory` | `save_memory_item` | `async def save_memory(self, session_id: str, memory_type: str, content: dict \| str, category: str \| None = None, user_prompt: str \| None = None, importance: int = 5) -> int` | `int` <br> e.g. `456` |
| 4 | `recall_memories` | `recall_memory_item` | `async def recall_memories(self, query: str, session_id: str \| None = None, memory_type: str \| None = None, limit: int = 10) -> list[dict]` | `list[dict]` (List of memories matched by query) <br> e.g. `[{"id": 456, "session_id": "session_123", "memory_type": "finding", "category": "vulnerability", "content": "test content", "user_prompt": "query", "importance": 5}]` |
| 5 | `list_sessions` | `list_memory_sessions` | `async def list_sessions(self, status: str \| None = None, limit: int = 20, offset: int = 0) -> list[dict]` | `list[dict]` (List of session metadata) <br> e.g. `[{"id": "session_123", "name": "test_session", "analysis_duration_seconds": 3600.0, "status": "in_progress"}]` |
| 6 | `get_session_context` | `get_memory_session_detail`, `resume_memory_session` | `async def get_session_context(self, session_id: str) -> dict` | `dict` (Context structure including nested session, memories, and patterns) <br> e.g. `{"session": {"id": "session_123", "name": "test_session"}, "memories": [{"id": 1, "session_id": "session_123", "memory_type": "instruction", "content": "instruction text"}], "patterns": [{"id": 1, "session_id": "session_123", "pattern_type": "api_sequence", "pattern_signature": "VirtualAlloc"}], "memory_count": 1, "pattern_count": 1}` |
| 7 | `get_session` | `resume_memory_session` | `async def get_session(self, session_id: str) -> dict \| None` | `dict \| None` (Session details dict) <br> e.g. `{"id": "session_123", "name": "test_session"}` |
| 8 | `find_latest_session` | `resume_memory_session` | `async def find_latest_session(self, binary_name: str \| None = None) -> dict \| None` | `dict \| None` (Session details dict) <br> e.g. `{"id": "session_123", "name": "test_session"}` |
| 9 | `update_session` | `resume_memory_session`, `complete_memory_session`, `update_memory_session_time` | `async def update_session(self, session_id: str, status: str \| None = None, summary: str \| None = None, add_duration: float = 0) -> bool` | `bool` (Indicates success/failure of the update) <br> e.g. `True` |
| 10 | `save_pattern` | `save_pattern` | `async def save_pattern(self, session_id: str, pattern_type: str, pattern_signature: str, description: str \| None = None) -> int` | `int` <br> e.g. `789` |
| 11 | `find_similar_patterns` | `find_similar_patterns` | `async def find_similar_patterns(self, pattern_signature: str, pattern_type: str \| None = None, exclude_session: str \| None = None, limit: int = 10) -> list[dict]` | `list[dict]` (List of matching patterns from other sessions) <br> e.g. `[{"id": 1, "session_id": "session_456", "pattern_type": "api_sequence", "pattern_signature": "VirtualAlloc", "description": "similar", "session_name": "other_session", "binary_name": "other.exe"}]` |
| 12 | `get_relevant_context` | `get_relevant_context` | `async def get_relevant_context(self, current_analysis: str, current_session_id: str \| None = None, limit: int = 5) -> list[dict]` | `list[dict]` (List of relevant memories from other sessions) <br> e.g. `[{"id": 2, "session_id": "session_789", "content": "relevant past memory"}]` |

*Note: While the original `mock_store` fixture mocked `store.get_memories`, this method is not called by any of the 11 tools directly and is obsolete.*

---

## 2. Proposed Changes to `mock_store` Fixture

To support testing all 11 tools, the `mock_store` fixture should be expanded with all the necessary async mock methods.

### Current Implementation (`tests/unit/tools/common/test_memory_tools.py`)
```python
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
```

### Proposed Extended Implementation
The following shows the recommended implementation to mock all methods with realistic return types (especially resolving the lack of `id` in `get_session` which would cause key errors):

```python
    @pytest.fixture
    def mock_store(self):
        """Mock memory store."""
        store = MagicMock()
        store.initialize = AsyncMock()
        store.create_session = AsyncMock(return_value="session_123")

        # In the actual implementation, save_memory returns an integer memory ID
        store.save_memory = AsyncMock(return_value=456)

        # Included for backwards compatibility, though not called directly by the tools
        store.get_memories = AsyncMock(return_value=[{"content": "test"}])

        # Must return "id" to prevent KeyError: 'id' in resume_memory_session
        store.get_session = AsyncMock(
            return_value={"id": "session_123", "name": "test_session"}
        )

        # Returns list of session dicts; duration seconds can be formatted by tools
        store.list_sessions = AsyncMock(
            return_value=[
                {
                    "id": "session_123",
                    "name": "test_session",
                    "analysis_duration_seconds": 3600.0,
                    "status": "in_progress",
                }
            ]
        )

        # Returns list of matched memory dicts
        store.recall_memories = AsyncMock(
            return_value=[
                {
                    "id": 456,
                    "session_id": "session_123",
                    "memory_type": "finding",
                    "category": "vulnerability",
                    "content": "test content",
                    "user_prompt": "query",
                    "importance": 5,
                }
            ]
        )

        # --- Extended Methods to Support All 11 Tools ---

        # Mock for get_session_context (called by get_memory_session_detail and resume_memory_session)
        store.get_session_context = AsyncMock(
            return_value={
                "session": {"id": "session_123", "name": "test_session"},
                "memories": [
                    {
                        "id": 1,
                        "session_id": "session_123",
                        "memory_type": "instruction",
                        "content": "test instruction",
                    }
                ],
                "patterns": [
                    {
                        "id": 1,
                        "session_id": "session_123",
                        "pattern_type": "api_sequence",
                        "pattern_signature": "VirtualAlloc",
                        "description": "test pattern",
                    }
                ],
                "memory_count": 1,
                "pattern_count": 1,
            }
        )

        # Mock for find_latest_session (called by resume_memory_session when session_id is omitted)
        store.find_latest_session = AsyncMock(
            return_value={"id": "session_123", "name": "test_session"}
        )

        # Mock for update_session (called by resume_memory_session, complete_memory_session, and update_memory_session_time)
        store.update_session = AsyncMock(return_value=True)

        # Mock for save_pattern (called by save_pattern)
        store.save_pattern = AsyncMock(return_value=789)

        # Mock for find_similar_patterns (called by find_similar_patterns)
        store.find_similar_patterns = AsyncMock(
            return_value=[
                {
                    "id": 1,
                    "session_id": "session_456",
                    "pattern_type": "api_sequence",
                    "pattern_signature": "VirtualAlloc",
                    "description": "similar pattern",
                    "session_name": "other_session",
                    "binary_name": "other.exe",
                }
            ]
        )

        # Mock for get_relevant_context (called by get_relevant_context)
        store.get_relevant_context = AsyncMock(
            return_value=[
                {
                    "id": 2,
                    "session_id": "session_789",
                    "content": "relevant past memory",
                }
            ]
        )

        return store
```

---

## 3. Analysis of Registration Tests

### Current Registration Test
```python
class TestRegisterMemoryTools:
    """Tests for register_memory_tools."""

    def test_registration(self):
        mock_mcp = MagicMock()
        register_memory_tools(mock_mcp)
        # plugin.register calls mcp.tool() 11 times
        assert mock_mcp.tool.call_count == 11
```

### Evaluation & Recommendations for Registration Tests

1. **Call Count Assertion Validity**: The assertion `assert mock_mcp.tool.call_count == 11` currently passes because there are exactly 11 decorator calls in `MemoryToolsPlugin.register()`. However, this is a brittle assertion that only verifies the *quantity* of registered tools and not their identity. If a developer accidentally registers a different tool twice or renames one, the assertion could still pass while leaving a critical tool unregistered.
2. **Strength of Assertions**: The registration test should be updated to verify that the **exact expected tool names** are registered.
3. **Fixture Scope Sharing**: The `mock_mcp` fixture in `TestMemoryToolsPlugin` is a custom mock that populates an internal `tools` dict when decorators are executed. Currently, it is defined inside the `TestMemoryToolsPlugin` class scope, meaning `TestRegisterMemoryTools` cannot access it.
4. **Proposed Update**:
   - Move the custom `mock_mcp` fixture to module scope in `tests/unit/tools/common/test_memory_tools.py` (or into `tests/conftest.py` if shared wider).
   - Rewrite `TestRegisterMemoryTools` to use the fixture and verify the set of registered tool names:

```python
# Move mock_mcp to module level so both classes can use it
@pytest.fixture
def mock_mcp():
    """Create mock MCP server that records registered tools."""
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

class TestRegisterMemoryTools:
    """Tests for register_memory_tools."""

    def test_registration(self, mock_mcp):
        """Verify that all 11 specific memory tools are registered."""
        register_memory_tools(mock_mcp)

        expected_tools = {
            "create_memory_session",
            "save_memory_item",
            "recall_memory_item",
            "list_memory_sessions",
            "get_memory_session_detail",
            "resume_memory_session",
            "complete_memory_session",
            "save_pattern",
            "find_similar_patterns",
            "get_relevant_context",
            "update_memory_session_time"
        }

        assert set(mock_mcp.tools.keys()) == expected_tools
        assert len(mock_mcp.tools) == 11
```

By making these registration test updates, any changes or regressions to tool names or registration logic will be immediately caught.
