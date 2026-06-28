# Memory Tools Analysis and Testing Recommendations

This report contains a read-only analysis of the memory tools plugin located in `reversecore_mcp/tools/common/memory_tools.py` and recommendations for extending `tests/unit/tools/common/test_memory_tools.py` to cover negative test scenarios, edge cases, and boundary conditions for the 8 missing memory tools.

---

## 1. Core System-wide Failure Scenarios

Before analyzing individual tools, two global failure modes affect every memory tool since they all call `get_memory_store()` and `store.initialize()`:

### A. Database Initialization Failure
* **Root Cause**: The SQLite database cannot be initialized (e.g., path is not writable, disk is full, or file locks prevent opening).
* **Code Impact**: `await store.initialize()` raises a `sqlite3.Error` or `RuntimeError`.
* **Mock Configuration**:
  ```python
  mock_store.initialize = AsyncMock(side_effect=sqlite3.OperationalError("Unable to open database file"))
  ```
* **Assertion Needed**:
  ```python
  with pytest.raises(sqlite3.OperationalError) as excinfo:
      await tool_function(...)
  assert "Unable to open database" in str(excinfo.value)
  ```

### B. SQLite Connection Loss during Execution
* **Root Cause**: DB connection is lost after initialization but before the query completes.
* **Code Impact**: Methods like `list_sessions`, `get_session_context`, `update_session` raise `sqlite3.ProgrammingError` or `aiosqlite.OperationalError`.
* **Mock Configuration**:
  ```python
  mock_store.list_sessions = AsyncMock(side_effect=sqlite3.ProgrammingError("Cannot operate on a closed database"))
  ```
* **Assertion Needed**:
  ```python
  with pytest.raises(sqlite3.ProgrammingError):
      await tool_function(...)
  ```

---

## 2. Tool-by-Tool Detailed Analysis

### 1. `list_memory_sessions`

#### A. Edge Cases & Boundary Conditions
1. **Empty list (No sessions exist)**:
   * *Behavior*: `store.list_sessions` returns `[]`. The tool returns `{"status": "success", "count": 0, "sessions": []}`.
   * *Mock Configuration*:
     ```python
     mock_store.list_sessions = AsyncMock(return_value=[])
     ```
   * *Assertions*:
     ```python
     result = await list_memory_sessions()
     assert result["status"] == "success"
     assert result["count"] == 0
     assert result["sessions"] == []
     ```
2. **Invalid status parameter**:
   * *Behavior*: Passing `status="nonexistent_status"` will pass that value to the SQL query. It returns `[]` without error.
   * *Mock Configuration*:
     ```python
     mock_store.list_sessions = AsyncMock(return_value=[])
     ```
   * *Assertions*:
     ```python
     result = await list_memory_sessions(status="nonexistent")
     assert result["status"] == "success"
     assert result["sessions"] == []
     ```
3. **Invalid `limit` value**:
   * *Behavior*: Passing a negative limit or string limit could cause database exceptions or return all sessions (in SQLite, a negative limit returns all rows).
   * *Mock Configuration (to simulate SQLite type constraint failure)*:
     ```python
     mock_store.list_sessions = AsyncMock(side_effect=TypeError("limit must be an integer"))
     ```
   * *Assertions*:
     ```python
     with pytest.raises(TypeError):
         await list_memory_sessions(limit="invalid")
     ```
4. **Duration Formatting Edge Cases**:
   * *Behavior*: Sessions with `analysis_duration_seconds` set to `0` or `None` will evaluate to falsy in `if session.get("analysis_duration_seconds"):`, skipping the formatting step. Sessions with positive floating point values (e.g. `3665.5` seconds) must be correctly formatted to `"1h 1m"`.
   * *Mock Configuration*:
     ```python
     mock_store.list_sessions = AsyncMock(return_value=[
         {"id": "session_1", "analysis_duration_seconds": 3665.5},
         {"id": "session_2", "analysis_duration_seconds": 0},
         {"id": "session_3", "analysis_duration_seconds": None}
     ])
     ```
   * *Assertions*:
     ```python
     result = await list_memory_sessions()
     assert result["sessions"][0]["analysis_duration_formatted"] == "1h 1m"
     assert "analysis_duration_formatted" not in result["sessions"][1]
     assert "analysis_duration_formatted" not in result["sessions"][2]
     ```

---

### 2. `get_memory_session_detail`

#### A. Edge Cases & Boundary Conditions
1. **Missing Session**:
   * *Behavior*: If the requested `session_id` does not exist, `store.get_session_context` returns `{}`. The tool intercepts this and returns `{"status": "error", "message": "Session '<session_id>' not found"}`.
   * *Mock Configuration*:
     ```python
     mock_store.get_session_context = AsyncMock(return_value={})
     ```
   * *Assertions*:
     ```python
     result = await get_memory_session_detail(session_id="missing_session_id")
     assert result["status"] == "error"
     assert "not found" in result["message"]
     ```
2. **Session with Empty Memories and Patterns**:
   * *Behavior*: If the session exists but has no associated memories/patterns, it returns success with empty lists and counts of 0.
   * *Mock Configuration*:
     ```python
     mock_store.get_session_context = AsyncMock(return_value={
         "session": {"id": "session_123", "name": "empty_session"},
         "memories": [],
         "patterns": [],
         "memory_count": 0,
         "pattern_count": 0
     })
     ```
   * *Assertions*:
     ```python
     result = await get_memory_session_detail(session_id="session_123")
     assert result["status"] == "success"
     assert result["session"]["name"] == "empty_session"
     assert result["memories"] == []
     assert result["patterns"] == []
     assert result["summary"]["memory_count"] == 0
     assert result["summary"]["pattern_count"] == 0
     ```

---

### 3. `resume_memory_session`

#### A. Edge Cases & Boundary Conditions
1. **Missing Session (by session_id)**:
   * *Behavior*: If `session_id` is supplied but is not found, `store.get_session(session_id)` returns `None`. The tool returns `{"status": "error", "message": "No session found..."}`.
   * *Mock Configuration*:
     ```python
     mock_store.get_session = AsyncMock(return_value=None)
     ```
   * *Assertions*:
     ```python
     result = await resume_memory_session(session_id="missing_id")
     assert result["status"] == "error"
     assert "No session found to resume" in result["message"]
     ```
2. **Missing Session (by binary_name)**:
   * *Behavior*: If `session_id` is not supplied, `store.find_latest_session(binary_name)` is called. If that returns `None`, the tool returns the same error status.
   * *Mock Configuration*:
     ```python
     mock_store.find_latest_session = AsyncMock(return_value=None)
     ```
   * *Assertions*:
     ```python
     result = await resume_memory_session(binary_name="missing_binary.exe")
     assert result["status"] == "error"
     assert "No session found to resume" in result["message"]
     ```
3. **Concurrent Delete (KeyError Vulnerability)**:
   * *Behavior*: If the session was found by `store.get_session()` but deleted by a concurrent operation right before `store.get_session_context()` is executed, `get_session_context` returns `{}`. The tool does not handle this, which causes a crash due to `KeyError` when accessing `context["memory_count"]`.
   * *Mock Configuration*:
     ```python
     mock_store.get_session = AsyncMock(return_value={"id": "session_123", "name": "temp"})
     mock_store.update_session = AsyncMock(return_value=True)
     mock_store.get_session_context = AsyncMock(return_value={})
     ```
   * *Assertions*:
     ```python
     with pytest.raises(KeyError):
         await resume_memory_session(session_id="session_123")
     ```
4. **Session with No Instruction Memories**:
   * *Behavior*: The tool filters instructions from memories where `memory_type == "instruction"`. If none exist, the `instructions` list should be empty.
   * *Mock Configuration*:
     ```python
     mock_store.get_session = AsyncMock(return_value={"id": "session_123", "name": "test"})
     mock_store.update_session = AsyncMock(return_value=True)
     mock_store.get_session_context = AsyncMock(return_value={
         "session": {"id": "session_123", "name": "test"},
         "memories": [{"id": 1, "memory_type": "finding", "content": "finding_1"}],
         "patterns": [],
         "memory_count": 1,
         "pattern_count": 0
     })
     ```
   * *Assertions*:
     ```python
     result = await resume_memory_session(session_id="session_123")
     assert result["status"] == "success"
     assert len(result["memories"]) == 1
     assert result["instructions"] == []
     ```

---

### 4. `complete_memory_session`

#### A. Edge Cases & Boundary Conditions
1. **Missing Session**:
   * *Behavior*: If `session_id` does not exist, `store.update_session` returns `False`. The tool returns `{"status": "error", "message": "Session '<session_id>' not found"}`.
   * *Mock Configuration*:
     ```python
     mock_store.update_session = AsyncMock(return_value=False)
     ```
   * *Assertions*:
     ```python
     result = await complete_memory_session(session_id="missing_session_id", summary="summary")
     assert result["status"] == "error"
     assert "not found" in result["message"]
     ```
2. **Empty or Invalid Summary**:
   * *Behavior*: If `summary` is empty, it still updates the session as completed without raising validation errors (unless strict model schemas are configured).
   * *Mock Configuration*:
     ```python
     mock_store.update_session = AsyncMock(return_value=True)
     ```
   * *Assertions*:
     ```python
     result = await complete_memory_session(session_id="session_123", summary="")
     assert result["status"] == "success"
     assert result["summary"] == ""
     ```

---

### 5. `save_pattern`

#### A. Edge Cases & Boundary Conditions
1. **Bypassing Foreign Key Constraints (Data Integrity Risk)**:
   * *Behavior*: SQLite does not enforce foreign keys by default unless `PRAGMA foreign_keys = ON;` is run. Because `MemoryStore.initialize` does not enable it, a pattern can be associated with a non-existent `session_id` and the operation will succeed. Under a proper database constraint mock, it should raise an `IntegrityError`.
   * *Mock Configuration (Foreign Key Constraint Violation)*:
     ```python
     mock_store.save_pattern = AsyncMock(side_effect=sqlite3.IntegrityError("FOREIGN KEY constraint failed"))
     ```
   * *Assertions*:
     ```python
     with pytest.raises(sqlite3.IntegrityError):
         await save_pattern(session_id="nonexistent_session", pattern_type="api_sequence", pattern_signature="VirtualAlloc")
     ```
2. **Invalid `pattern_type`**:
   * *Behavior*: The tool doesn't validate `pattern_type` values (e.g. against 'api_sequence', 'code_pattern', 'behavior').
   * *Mock Configuration*:
     ```python
     mock_store.save_pattern = AsyncMock(return_value=1)
     ```
   * *Assertions*:
     ```python
     result = await save_pattern(session_id="session_123", pattern_type="invalid_type", pattern_signature="VirtualAlloc")
     assert result["status"] == "success"
     assert result["pattern_id"] == 1
     ```

---

### 6. `find_similar_patterns`

#### A. Edge Cases & Boundary Conditions
1. **Empty Search Results**:
   * *Behavior*: If no similar patterns exist, `store.find_similar_patterns` returns `[]`. The tool returns `{"status": "success", "count": 0, "similar_patterns": [], "message": "No similar patterns found in previous analyses."}`.
   * *Mock Configuration*:
     ```python
     mock_store.find_similar_patterns = AsyncMock(return_value=[])
     ```
   * *Assertions*:
     ```python
     result = await find_similar_patterns(pattern_signature="VirtualAlloc")
     assert result["status"] == "success"
     assert result["count"] == 0
     assert result["similar_patterns"] == []
     assert "No similar patterns found" in result["message"]
     ```
2. **Wildcard Injection (`%` or `_`)**:
   * *Behavior*: The signature is passed directly to the SQLite `LIKE` operator as `f"{pattern_signature}%"`. Special LIKE wildcard characters like `%` or `_` are not escaped, allowing broad-scope SQL wildcard queries.
   * *Mock Configuration (Simulating wildcard search matching all records)*:
     ```python
     mock_store.find_similar_patterns = AsyncMock(return_value=[
         {"id": 1, "pattern_signature": "VirtualAlloc"},
         {"id": 2, "pattern_signature": "CreateThread"}
     ])
     ```
   * *Assertions*:
     ```python
     result = await find_similar_patterns(pattern_signature="%")
     assert result["status"] == "success"
     assert result["count"] == 2
     ```

---

### 7. `get_relevant_context`

#### A. Edge Cases & Boundary Conditions
1. **Empty Search Results**:
   * *Behavior*: `store.get_relevant_context` returns `[]`. The tool returns `{"status": "success", "count": 0, "relevant_memories": [], "message": "No relevant past context found"}`.
   * *Mock Configuration*:
     ```python
     mock_store.get_relevant_context = AsyncMock(return_value=[])
     ```
   * *Assertions*:
     ```python
     result = await get_relevant_context(description="VirtualAlloc")
     assert result["status"] == "success"
     assert result["count"] == 0
     assert "No relevant past context found" in result["message"]
     ```
2. **Exclusion of All Matches**:
   * *Behavior*: If the search query returns matches, but all of them are filtered out because they belong to the `current_session_id`, the final list is empty.
   * *Mock Configuration (Simulating that all matches are filtered)*:
     ```python
     mock_store.get_relevant_context = AsyncMock(return_value=[])
     ```
   * *Assertions*:
     ```python
     result = await get_relevant_context(description="VirtualAlloc", current_session_id="session_123")
     assert result["status"] == "success"
     assert result["count"] == 0
     assert result["relevant_memories"] == []
     ```

---

### 8. `update_memory_session_time`

#### A. Edge Cases & Boundary Conditions
1. **Missing Session (UX Bug / Message Inconsistency)**:
   * *Behavior*: If `session_id` does not exist, `store.update_session` returns `False`. The tool returns `{"status": "error", "message": "Added <duration>s to analysis time"}`.
   * *UX Bug*: Even though status is `"error"`, the message STILL claims that the duration was added!
   * *Mock Configuration*:
     ```python
     mock_store.update_session = AsyncMock(return_value=False)
     ```
   * *Assertions*:
     ```python
     result = await update_memory_session_time(session_id="missing_session_id", duration_seconds=10.0)
     assert result["status"] == "error"
     assert "Added 10.0s to analysis time" in result["message"] # Highlights UX bug
     ```
2. **Negative Duration (Boundary condition)**:
   * *Behavior*: If `duration_seconds` is negative, `store.update_session` will skip appending the duration update in SQL because it checks `if add_duration > 0:`. However, it still updates the `updated_at` column and returns `True`. The tool will claim success and print `"Added -10.0s to analysis time"` even though nothing was added in the DB.
   * *Mock Configuration*:
     ```python
     mock_store.update_session = AsyncMock(return_value=True)
     ```
   * *Assertions*:
     ```python
     result = await update_memory_session_time(session_id="session_123", duration_seconds=-10.0)
     assert result["status"] == "success"
     assert "Added -10.0s to analysis time" in result["message"]
     ```

---

## 3. Code Recommendations for `tests/unit/tools/common/test_memory_tools.py`

Below is a proposed implementation for testing the 8 missing memory tools, addressing the negative scenarios and edge cases discussed above:

```python
    @pytest.mark.asyncio
    async def test_list_memory_sessions_success(self, plugin, mock_mcp, mock_store):
        """Test list_memory_sessions tool with sessions."""
        mock_store.list_sessions = AsyncMock(return_value=[
            {"id": "session_1", "analysis_duration_seconds": 3665.5},
            {"id": "session_2", "analysis_duration_seconds": 0}
        ])
        plugin.register(mock_mcp)
        list_sessions = mock_mcp.tools["list_memory_sessions"]

        result = await list_sessions()
        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["sessions"][0]["analysis_duration_formatted"] == "1h 1m"
        assert "analysis_duration_formatted" not in result["sessions"][1]

    @pytest.mark.asyncio
    async def test_list_memory_sessions_empty(self, plugin, mock_mcp, mock_store):
        """Test list_memory_sessions tool with no sessions."""
        mock_store.list_sessions = AsyncMock(return_value=[])
        plugin.register(mock_mcp)
        list_sessions = mock_mcp.tools["list_memory_sessions"]

        result = await list_sessions()
        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["sessions"] == []

    @pytest.mark.asyncio
    async def test_get_memory_session_detail_success(self, plugin, mock_mcp, mock_store):
        """Test get_memory_session_detail tool with valid session."""
        mock_store.get_session_context = AsyncMock(return_value={
            "session": {"id": "session_123", "name": "test_session"},
            "memories": [{"memory_type": "finding", "content": "finding_1"}],
            "patterns": [{"pattern_type": "code_pattern", "pattern_signature": "sig_1"}],
            "memory_count": 1,
            "pattern_count": 1
        })
        plugin.register(mock_mcp)
        get_detail = mock_mcp.tools["get_memory_session_detail"]

        result = await get_detail(session_id="session_123")
        assert result["status"] == "success"
        assert result["session"]["name"] == "test_session"
        assert len(result["memories"]) == 1
        assert len(result["patterns"]) == 1
        assert result["summary"]["memory_count"] == 1
        assert result["summary"]["pattern_count"] == 1

    @pytest.mark.asyncio
    async def test_get_memory_session_detail_not_found(self, plugin, mock_mcp, mock_store):
        """Test get_memory_session_detail tool with missing session."""
        mock_store.get_session_context = AsyncMock(return_value={})
        plugin.register(mock_mcp)
        get_detail = mock_mcp.tools["get_memory_session_detail"]

        result = await get_detail(session_id="nonexistent")
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_resume_memory_session_success(self, plugin, mock_mcp, mock_store):
        """Test resume_memory_session tool with valid session."""
        mock_store.get_session = AsyncMock(return_value={"id": "session_123", "name": "test_session"})
        mock_store.update_session = AsyncMock(return_value=True)
        mock_store.get_session_context = AsyncMock(return_value={
            "session": {"id": "session_123", "name": "test_session"},
            "memories": [
                {"memory_type": "instruction", "content": "instruction_1"},
                {"memory_type": "finding", "content": "finding_1"}
            ],
            "patterns": [],
            "memory_count": 2,
            "pattern_count": 0
        })
        plugin.register(mock_mcp)
        resume = mock_mcp.tools["resume_memory_session"]

        result = await resume(session_id="session_123")
        assert result["status"] == "success"
        assert len(result["instructions"]) == 1
        assert result["instructions"][0]["content"] == "instruction_1"
        assert len(result["memories"]) == 2

    @pytest.mark.asyncio
    async def test_resume_memory_session_not_found(self, plugin, mock_mcp, mock_store):
        """Test resume_memory_session tool with missing session."""
        mock_store.get_session = AsyncMock(return_value=None)
        plugin.register(mock_mcp)
        resume = mock_mcp.tools["resume_memory_session"]

        result = await resume(session_id="nonexistent")
        assert result["status"] == "error"
        assert "No session found" in result["message"]

    @pytest.mark.asyncio
    async def test_complete_memory_session_success(self, plugin, mock_mcp, mock_store):
        """Test complete_memory_session tool success."""
        mock_store.update_session = AsyncMock(return_value=True)
        plugin.register(mock_mcp)
        complete = mock_mcp.tools["complete_memory_session"]

        result = await complete(session_id="session_123", summary="Completed analysis")
        assert result["status"] == "success"
        assert result["summary"] == "Completed analysis"
        mock_store.update_session.assert_called_once_with(
            session_id="session_123",
            status="completed",
            summary="Completed analysis"
        )

    @pytest.mark.asyncio
    async def test_complete_memory_session_not_found(self, plugin, mock_mcp, mock_store):
        """Test complete_memory_session tool with missing session."""
        mock_store.update_session = AsyncMock(return_value=False)
        plugin.register(mock_mcp)
        complete = mock_mcp.tools["complete_memory_session"]

        result = await complete(session_id="nonexistent", summary="Completed analysis")
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_save_pattern_success(self, plugin, mock_mcp, mock_store):
        """Test save_pattern tool."""
        mock_store.save_pattern = AsyncMock(return_value=789)
        plugin.register(mock_mcp)
        save_pat = mock_mcp.tools["save_pattern"]

        result = await save_pat(
            session_id="session_123",
            pattern_type="api_sequence",
            pattern_signature="A,B,C",
            description="desc"
        )
        assert result["status"] == "success"
        assert result["pattern_id"] == 789

    @pytest.mark.asyncio
    async def test_find_similar_patterns_success(self, plugin, mock_mcp, mock_store):
        """Test find_similar_patterns tool with matches."""
        mock_store.find_similar_patterns = AsyncMock(return_value=[
            {"id": 1, "pattern_signature": "sig_1"}
        ])
        plugin.register(mock_mcp)
        find_similar = mock_mcp.tools["find_similar_patterns"]

        result = await find_similar(pattern_signature="sig_1")
        assert result["status"] == "success"
        assert result["count"] == 1
        assert len(result["similar_patterns"]) == 1

    @pytest.mark.asyncio
    async def test_find_similar_patterns_empty(self, plugin, mock_mcp, mock_store):
        """Test find_similar_patterns tool with no matches."""
        mock_store.find_similar_patterns = AsyncMock(return_value=[])
        plugin.register(mock_mcp)
        find_similar = mock_mcp.tools["find_similar_patterns"]

        result = await find_similar(pattern_signature="sig_1")
        assert result["status"] == "success"
        assert result["count"] == 0
        assert "No similar patterns found" in result["message"]

    @pytest.mark.asyncio
    async def test_get_relevant_context_success(self, plugin, mock_mcp, mock_store):
        """Test get_relevant_context tool with matches."""
        mock_store.get_relevant_context = AsyncMock(return_value=[
            {"content": "relevant_finding"}
        ])
        plugin.register(mock_mcp)
        get_context = mock_mcp.tools["get_relevant_context"]

        result = await get_context(description="VirtualAlloc")
        assert result["status"] == "success"
        assert result["count"] == 1
        assert len(result["relevant_memories"]) == 1

    @pytest.mark.asyncio
    async def test_update_memory_session_time_success(self, plugin, mock_mcp, mock_store):
        """Test update_memory_session_time tool success."""
        mock_store.update_session = AsyncMock(return_value=True)
        plugin.register(mock_mcp)
        update_time = mock_mcp.tools["update_memory_session_time"]

        result = await update_time(session_id="session_123", duration_seconds=15.5)
        assert result["status"] == "success"
        assert "Added 15.5s" in result["message"]

    @pytest.mark.asyncio
    async def test_update_memory_session_time_error(self, plugin, mock_mcp, mock_store):
        """Test update_memory_session_time tool error."""
        mock_store.update_session = AsyncMock(return_value=False)
        plugin.register(mock_mcp)
        update_time = mock_mcp.tools["update_memory_session_time"]

        result = await update_time(session_id="nonexistent", duration_seconds=15.5)
        assert result["status"] == "error"
        # Reflects the current message formatting logic which still states the duration was added
        assert "Added 15.5s" in result["message"]

    @pytest.mark.asyncio
    async def test_db_initialization_failure(self, plugin, mock_mcp, mock_store):
        """Test DB initialization failure propagates as error."""
        mock_store.initialize = AsyncMock(side_effect=sqlite3.OperationalError("Init failed"))
        plugin.register(mock_mcp)

        list_sessions = mock_mcp.tools["list_memory_sessions"]
        with pytest.raises(sqlite3.OperationalError) as excinfo:
            await list_sessions()
        assert "Init failed" in str(excinfo.value)
```
