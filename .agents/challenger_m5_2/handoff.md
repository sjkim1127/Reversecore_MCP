# Handoff Report — Milestone 5 Challenger 2

## 1. Observation
We observed the following files and output during our investigation:
- **Target source file**: `reversecore_mcp/tools/common/memory_tools.py`
- **Test file**: `tests/unit/tools/common/test_memory_tools.py`
- **Underlying storage file**: `reversecore_mcp/core/memory.py`
- **Test execution commands and results**:
  - Running `pytest tests/unit/tools/common/test_memory_tools.py -v` succeeded with all 22 tests passing:
    ```
    reversecore_mcp/tools/common/memory_tools.py              115      0   100%
    ============================== 22 passed in 3.34s ==============================
    ```
  - Running the complete test suite `pytest -v` succeeded with:
    ```
    TOTAL                                                   10075   1277    87%
    Coverage HTML written to dir htmlcov
    Required test coverage of 80% reached. Total coverage: 87.33%
    ================= 1693 passed, 56 skipped in 87.01s (0:01:27) ==================
    ```

- **Verbatim SQL schema (from `reversecore_mcp/core/memory.py` lines 99-111)**:
  ```python
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
  ```

- **Database Connection Initialization (from `reversecore_mcp/core/memory.py` lines 67-76)**:
  ```python
  self._db = await aiosqlite.connect(self.db_path)
  self._db.row_factory = aiosqlite.Row

  await self._create_schema()

  # Enable WAL mode for better concurrency
  await self._db.execute("PRAGMA journal_mode=WAL;")

  self._initialized = True
  ```

- **FTS5 Fallback Logic (from `reversecore_mcp/core/memory.py` lines 468-475)**:
  ```python
  try:
      cursor = await db.execute(base_query, params)
      rows = await cursor.fetchall()
      return [dict(row) for row in rows]
  except Exception as e:
      # FTS match might fail on invalid queries, fall back to LIKE
      logger.warning(f"FTS search failed, falling back to LIKE: {e}")
      return await self._recall_memories_fallback(query, session_id, memory_type, limit)
  ```

- **Binary Hashing Logic (from `reversecore_mcp/tools/common/memory_tools.py` lines 58-66)**:
  ```python
  if binary_path:
      try:
          path = Path(binary_path)
          if path.exists():
              binary_hash = hashlib.sha256(path.read_bytes()).hexdigest()
              if not binary_name:
                  binary_name = path.name
      except Exception as e:
          logger.warning(f"Could not hash binary: {e}")
  ```

---

## 2. Logic Chain
We analyzed the system's design and constructed verification test scenarios to stress-test the implicit assumptions:

1. **Foreign Key Integrity**:
   - *Observation*: The schema defines a foreign key `FOREIGN KEY (session_id) REFERENCES analysis_sessions(id)`. However, `initialize()` does not execute `PRAGMA foreign_keys = ON;`.
   - *Empirical Verification*: We created a SQLite memory store instance and saved a memory with a nonexistent `session_id` (`nonexistent-session-id-12345`). The operation completed with status `"success"`.
   - *Conclusion*: SQLite foreign key constraints are not enforced, leading to potential database corruption via orphaned memories.

2. **Large Binary File Processing (OOM risk)**:
   - *Observation*: The `create_memory_session` tool calls `path.read_bytes()`.
   - *Reasoning*: A 50MB file was hashed successfully, but a 5GB file will read the entire 5GB into memory at once, risking OOM/MemoryError. Although wrapped in `try-except Exception`, this consumes excessive heap memory before throwing or causing the process to crash.
   - *Conclusion*: Reading files entirely into memory for hashing creates an OOM vector.

3. **FTS5 Query Fallback**:
   - *Observation*: The query `*` in SQLite FTS5 causes a syntax error.
   - *Empirical Verification*: When querying `*`, a warning was logged (`FTS search failed, falling back to LIKE: unknown special query: `) and a fallback LIKE search was successfully executed.
   - *Conclusion*: The FTS5 fallback logic is correct and robust, preventing internal database query errors from breaking user searches.

4. **Importance Range Limits**:
   - *Observation*: Docstrings recommend `importance` between 1 and 10, but no validation limits the input.
   - *Empirical Verification*: Saving memories with `importance=99` and `importance=-5` successfully wrote these values to the SQLite database.
   - *Conclusion*: Range constraints are not enforced programmatically, leaving relevance ordering vulnerable to manipulation.

---

## 3. Caveats
- We did not evaluate concurrent write scenarios where database locking (`sqlite3.OperationalError: database is locked`) might cause tools to fail. SQLite defaults to a short busy timeout which could bubble up to the user under high load.
- Input validation was tested assuming the FastMCP interface type hints (Pydantic models) prevent parameter type violations (e.g., passing a list to a string parameter), but we did not verify behavior if these boundaries are bypassed.

---

## 4. Conclusion & Adversarial Challenge Report

### Challenge Summary
- **Overall risk assessment**: MEDIUM
- SQLite foreign key constraints are not enforced, allowing orphaned records.
- Hashing uses whole-file reading rather than chunked stream reading, presenting an OOM risk.

### Challenges

#### [Medium] Challenge 1: Disabled Foreign Key Constraints
- **Assumption challenged**: SQLite automatically enforces foreign key references defined in the schema.
- **Attack scenario**: A user/agent passes a corrupted or fake `session_id` when saving a memory.
- **Blast radius**: Orphaned database entries are created. This could result in data leakages or query mismatches during session resumes.
- **Mitigation**: Execute `await db.execute("PRAGMA foreign_keys = ON;")` inside `MemoryStore.initialize()`.

#### [Low] Challenge 2: Out of Memory on Hashing
- **Assumption challenged**: Hashed binary files will always fit comfortably in memory.
- **Attack scenario**: Attempting to hash a large multi-gigabyte executable.
- **Blast radius**: Memory consumption spikes, risking OOM and process crashes.
- **Mitigation**: Use chunked hashing (`f.read(chunk_size)`).

#### [Low] Challenge 3: Lack of Clamping on Importance Levels
- **Assumption challenged**: The user/agent will respect the 1-10 range contract.
- **Attack scenario**: Providing out-of-bounds `importance` parameters.
- **Blast radius**: Relevance ordering is manipulated (e.g. pinned or hidden entries).
- **Mitigation**: Clamp or validate values in `save_memory_item`.

---

## 5. Verification Method

To verify the test suite, execution, and findings independently:
1. Run unit tests to confirm 100% coverage of `memory_tools.py`:
   ```bash
   pytest tests/unit/tools/common/test_memory_tools.py -v
   ```
2. Verify that there are no regressions across the rest of the project:
   ```bash
   pytest -v
   ```
3. Run the SQLite test case for foreign key enforcement:
   - Create a sqlite memory database using the schema.
   - Try to insert into `memories` with an invalid `session_id`.
   - Observe that the insertion succeeds instead of failing.
