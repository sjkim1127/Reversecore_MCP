"""
Unit tests for r2_db — SQLite-based annotation persistence layer.

All tests use a temporary in-memory SQLite DB to avoid touching the real .r2db file.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_validate_file_path(tmp_path):
    """Patch validate_file_path to return a real temp file."""
    fake_bin = tmp_path / "test.elf"
    fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)  # minimal ELF header
    with patch(
        "reversecore_mcp.tools.radare2.r2_db.validate_file_path",
        return_value=fake_bin,
    ):
        yield fake_bin


@pytest.fixture()
def patch_db_path(tmp_path):
    """Redirect the SQLite DB to a temp directory."""
    db_path = tmp_path / ".r2db"
    with patch("reversecore_mcp.tools.radare2.r2_db._DB_PATH", db_path):
        yield db_path


# ---------------------------------------------------------------------------
# r2_list_structures
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2ListStructures:
    """Tests for r2_list_structures tool."""

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_list(self, mock_validate_file_path, patch_db_path):
        """r2_list_structures returns empty list when DB has no entries."""
        from reversecore_mcp.tools.radare2.r2_db import r2_list_structures

        result = await r2_list_structures("/workspace/test.elf")

        assert result.status == "success"
        data = result.data
        assert data["structures"] == []
        assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_returns_created_structure(self, mock_validate_file_path, patch_db_path):
        """r2_list_structures returns a struct after r2_create_structure."""
        from reversecore_mcp.tools.radare2.r2_db import (
            r2_create_structure,
            r2_list_structures,
        )

        fields = [{"name": "health", "type": "int", "offset": "0x0", "size": 4}]
        await r2_create_structure("/workspace/test.elf", "Player", fields)

        result = await r2_list_structures("/workspace/test.elf")
        assert result.status == "success"
        data = result.data
        assert data["count"] == 1
        assert data["structures"][0]["name"] == "Player"

    @pytest.mark.asyncio
    async def test_pagination_is_deterministic_and_includes_metadata(
        self, mock_validate_file_path, patch_db_path
    ):
        from reversecore_mcp.tools.radare2.r2_db import (
            r2_create_structure,
            r2_list_structures,
        )

        for name in ("Gamma", "Alpha", "Beta"):
            await r2_create_structure("/workspace/test.elf", name, [])

        first_page = await r2_list_structures("/workspace/test.elf", offset=0, limit=2)
        second_page = await r2_list_structures("/workspace/test.elf", offset=2, limit=2)
        repeated_first_page = await r2_list_structures("/workspace/test.elf", offset=0, limit=2)

        assert [item["name"] for item in first_page.data["structures"]] == ["Alpha", "Beta"]
        assert first_page.data == repeated_first_page.data
        assert first_page.pagination.total_items == 3
        assert first_page.pagination.page == 1
        assert first_page.pagination.page_size == 2
        assert first_page.pagination.has_more is True
        assert first_page.pagination.next_cursor == "2"
        assert second_page.data["structures"][0]["name"] == "Gamma"
        assert second_page.pagination.page == 2
        assert second_page.pagination.has_more is False
        assert second_page.pagination.next_cursor is None


# ---------------------------------------------------------------------------
# r2_get_structure
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2GetStructure:
    """Tests for r2_get_structure tool."""

    @pytest.mark.asyncio
    async def test_not_found_returns_error(self, mock_validate_file_path, patch_db_path):
        """r2_get_structure returns error for unknown struct."""
        from reversecore_mcp.tools.radare2.r2_db import r2_get_structure

        result = await r2_get_structure("/workspace/test.elf", "NonExistent")
        assert result.status == "error"
        assert "NOT_FOUND" in result.error_code or "not found" in result.message.lower()

    @pytest.mark.asyncio
    async def test_returns_correct_struct(self, mock_validate_file_path, patch_db_path):
        """r2_get_structure returns the correct struct definition."""
        from reversecore_mcp.tools.radare2.r2_db import (
            r2_create_structure,
            r2_get_structure,
        )

        fields = [
            {"name": "x", "type": "float", "offset": "0x0", "size": 4},
            {"name": "y", "type": "float", "offset": "0x4", "size": 4},
        ]
        await r2_create_structure("/workspace/test.elf", "Vec2", fields)

        result = await r2_get_structure("/workspace/test.elf", "Vec2")
        assert result.status == "success"
        data = result.data
        assert data["name"] == "Vec2"
        assert len(data["fields"]) == 2


# ---------------------------------------------------------------------------
# r2_create_structure
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2CreateStructure:
    """Tests for r2_create_structure tool."""

    @pytest.mark.asyncio
    async def test_creates_structure_successfully(self, mock_validate_file_path, patch_db_path):
        """r2_create_structure saves a new struct."""
        from reversecore_mcp.tools.radare2.r2_db import r2_create_structure

        result = await r2_create_structure(
            "/workspace/test.elf",
            "Entity",
            [{"name": "id", "type": "int", "offset": "0x0", "size": 4}],
        )
        assert result.status == "success"
        data = result.data
        assert data["created"] == "Entity"
        assert data["field_count"] == 1

    @pytest.mark.asyncio
    async def test_invalid_name_returns_error(self, mock_validate_file_path, patch_db_path):
        """r2_create_structure rejects non-identifier names."""
        from reversecore_mcp.tools.radare2.r2_db import r2_create_structure

        result = await r2_create_structure("/workspace/test.elf", "123Invalid!", [])
        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_upsert_replaces_existing(self, mock_validate_file_path, patch_db_path):
        """r2_create_structure updates an existing struct (upsert)."""
        from reversecore_mcp.tools.radare2.r2_db import (
            r2_create_structure,
            r2_get_structure,
        )

        await r2_create_structure(
            "/workspace/test.elf", "Config", [{"name": "flag", "type": "bool"}]
        )
        await r2_create_structure(
            "/workspace/test.elf",
            "Config",
            [{"name": "flag", "type": "bool"}, {"name": "count", "type": "int"}],
        )

        result = await r2_get_structure("/workspace/test.elf", "Config")
        assert result.status == "success"
        data = result.data
        assert len(data["fields"]) == 2


# ---------------------------------------------------------------------------
# r2_list_bookmarks / r2_add_bookmark
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2Bookmarks:
    """Tests for bookmark tools."""

    @pytest.mark.asyncio
    async def test_empty_db_returns_no_bookmarks(self, mock_validate_file_path, patch_db_path):
        """r2_list_bookmarks returns empty list initially."""
        from reversecore_mcp.tools.radare2.r2_db import r2_list_bookmarks

        result = await r2_list_bookmarks("/workspace/test.elf")
        assert result.status == "success"
        data = result.data
        assert data["bookmarks"] == []

    @pytest.mark.asyncio
    async def test_add_and_list_bookmark(self, mock_validate_file_path, patch_db_path):
        """r2_add_bookmark persists and r2_list_bookmarks retrieves it."""
        from reversecore_mcp.tools.radare2.r2_db import (
            r2_add_bookmark,
            r2_list_bookmarks,
        )

        await r2_add_bookmark("/workspace/test.elf", "0x401020", "Suspicious XOR", "bug")

        result = await r2_list_bookmarks("/workspace/test.elf")
        assert result.status == "success"
        data = result.data
        assert data["count"] == 1
        bm = data["bookmarks"][0]
        assert bm["address"] == "0x401020"
        assert bm["comment"] == "Suspicious XOR"
        assert bm["category"] == "bug"

    @pytest.mark.asyncio
    async def test_filter_by_category(self, mock_validate_file_path, patch_db_path):
        """r2_list_bookmarks filters by category."""
        from reversecore_mcp.tools.radare2.r2_db import (
            r2_add_bookmark,
            r2_list_bookmarks,
        )

        await r2_add_bookmark("/workspace/test.elf", "0x401020", "Note 1", "note")
        await r2_add_bookmark("/workspace/test.elf", "0x401030", "Bug 1", "bug")

        result = await r2_list_bookmarks("/workspace/test.elf", category="note")
        data = result.data
        assert data["count"] == 1
        assert data["bookmarks"][0]["category"] == "note"

    @pytest.mark.asyncio
    async def test_pagination_is_deterministic_and_includes_metadata(
        self, mock_validate_file_path, patch_db_path
    ):
        from reversecore_mcp.tools.radare2.r2_db import r2_add_bookmark, r2_list_bookmarks

        for address in ("0x401030", "0x401010", "0x401020"):
            await r2_add_bookmark("/workspace/test.elf", address, f"note at {address}")

        first_page = await r2_list_bookmarks("/workspace/test.elf", offset=0, limit=2)
        second_page = await r2_list_bookmarks("/workspace/test.elf", offset=2, limit=2)

        assert [item["address"] for item in first_page.data["bookmarks"]] == [
            "0x401010",
            "0x401020",
        ]
        assert first_page.pagination.total_items == 3
        assert first_page.pagination.has_more is True
        assert first_page.pagination.next_cursor == "2"
        assert [item["address"] for item in second_page.data["bookmarks"]] == ["0x401030"]
        assert second_page.pagination.has_more is False

    @pytest.mark.asyncio
    async def test_empty_comment_returns_error(self, mock_validate_file_path, patch_db_path):
        """r2_add_bookmark rejects empty comment."""
        from reversecore_mcp.tools.radare2.r2_db import r2_add_bookmark

        result = await r2_add_bookmark("/workspace/test.elf", "0x401020", "")
        assert result.status == "error"


# ---------------------------------------------------------------------------
# r2_list pagination validation and combined type pagination
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["r2_list_structures", "r2_list_types", "r2_list_bookmarks"])
@pytest.mark.parametrize(
    ("pagination_args", "field"),
    [
        ({"limit": -1}, "limit"),
        ({"limit": 0}, "limit"),
        ({"limit": 501}, "limit"),
        ({"limit": True}, "limit"),
        ({"offset": -1}, "offset"),
        ({"offset": 1 << 63}, "offset"),
        ({"offset": False}, "offset"),
    ],
)
async def test_annotation_lists_reject_invalid_pagination_before_io(
    tool_name, pagination_args, field
):
    import reversecore_mcp.tools.radare2.r2_db as r2_db

    tool = getattr(r2_db, tool_name)
    with (
        patch.object(r2_db, "validate_file_path") as validate_path,
        patch.object(r2_db, "_get_db_sync") as open_db,
        patch.object(r2_db, "_execute_r2_command", new=AsyncMock()) as execute_r2,
    ):
        result = await tool("/workspace/not-opened.elf", **pagination_args)

    assert result.status == "error"
    assert result.error_code == "VALIDATION_ERROR"
    assert field in result.message
    validate_path.assert_not_called()
    open_db.assert_not_called()
    execute_r2.assert_not_awaited()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_r2_list_types_paginates_combined_user_and_native_types(
    mock_validate_file_path, patch_db_path
):
    from reversecore_mcp.tools.radare2.r2_db import _get_db_sync, _sha256, r2_list_types

    file_hash = _sha256(mock_validate_file_path)
    db = _get_db_sync()
    try:
        db.executemany(
            "INSERT INTO types(binary_hash, name, definition) VALUES (?, ?, ?)",
            [
                (file_hash, "UserB", "struct UserB"),
                (file_hash, "UserA", "struct UserA"),
            ],
        )
        db.commit()
    finally:
        db.close()

    native_types = [
        {"type": "Zulu", "typestr": "struct Zulu"},
        {"type": "Alpha", "typestr": "struct Alpha"},
        {"type": "Bravo", "typestr": "struct Bravo"},
    ]
    execute_r2 = AsyncMock(return_value=(json.dumps(native_types), {}))

    with patch("reversecore_mcp.tools.radare2.r2_db._execute_r2_command", new=execute_r2):
        pages = [
            await r2_list_types("/workspace/test.elf", offset=offset, limit=2)
            for offset in (0, 2, 4)
        ]

    assert all(len(page.data["types"]) <= 2 for page in pages)
    assert [(item["name"], item["source"]) for page in pages for item in page.data["types"]] == [
        ("UserA", "user"),
        ("UserB", "user"),
        ("Alpha", "r2"),
        ("Bravo", "r2"),
        ("Zulu", "r2"),
    ]
    assert [page.pagination.total_items for page in pages] == [5, 5, 5]
    assert [page.pagination.has_more for page in pages] == [True, True, False]
    assert [page.pagination.next_cursor for page in pages] == ["2", "4", None]


# r2_read_memory
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2ReadMemory:
    """Tests for r2_read_memory tool."""

    @pytest.mark.asyncio
    async def test_success_returns_bytes(self, mock_validate_file_path):
        """r2_read_memory returns hex bytes from pxj output."""
        from reversecore_mcp.tools.radare2.r2_db import r2_read_memory

        with patch(
            "reversecore_mcp.tools.radare2.r2_db._execute_r2_command",
            new_callable=AsyncMock,
            return_value=("[144,144,144,144]", 50),
        ):
            result = await r2_read_memory("/workspace/test.elf", "0x401000", 4)

        assert result.status == "success"
        data = result.data
        assert data["size"] == 4
        assert "90" in data["bytes"]

    @pytest.mark.asyncio
    async def test_size_too_large_returns_error(self, mock_validate_file_path):
        """r2_read_memory rejects size > 4096."""
        from reversecore_mcp.tools.radare2.r2_db import r2_read_memory

        result = await r2_read_memory("/workspace/test.elf", "0x401000", 99999)
        assert result.status == "error"
        assert "4096" in result.message

    @pytest.mark.asyncio
    async def test_size_zero_returns_error(self, mock_validate_file_path):
        """r2_read_memory rejects size <= 0."""
        from reversecore_mcp.tools.radare2.r2_db import r2_read_memory

        result = await r2_read_memory("/workspace/test.elf", "0x401000", 0)
        assert result.status == "error"


# ---------------------------------------------------------------------------
# get_cached_result / set_cached_result
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestR2DbCaching:
    """Tests for result caching layer in r2_db."""

    @pytest.mark.asyncio
    async def test_cache_success_roundtrip(self, mock_validate_file_path, patch_db_path):
        """ToolSuccess can be saved to and retrieved from cache."""
        from reversecore_mcp.core.result import ToolSuccess, success
        from reversecore_mcp.tools.radare2.r2_db import (
            get_cached_result,
            set_cached_result,
        )

        test_result = success({"disasm": "mov eax, 1", "count": 1})
        await set_cached_result(
            str(mock_validate_file_path),
            "test_tool",
            "cache_key_1",
            test_result,
            ttl=3600,
        )

        cached = await get_cached_result(str(mock_validate_file_path), "cache_key_1")
        assert cached is not None
        assert isinstance(cached, ToolSuccess)
        assert cached.status == "success"
        assert cached.data == {"disasm": "mov eax, 1", "count": 1}

    @pytest.mark.asyncio
    async def test_cache_error_roundtrip(self, mock_validate_file_path, patch_db_path):
        """ToolError can be saved to and retrieved from cache."""
        from reversecore_mcp.core.result import ToolError, failure
        from reversecore_mcp.tools.radare2.r2_db import (
            get_cached_result,
            set_cached_result,
        )

        test_error = failure("DISASM_ERROR", "Failed to disassemble address", hint="Check offset")
        await set_cached_result(
            str(mock_validate_file_path),
            "test_tool",
            "cache_key_err",
            test_error,
            ttl=3600,
        )

        cached = await get_cached_result(str(mock_validate_file_path), "cache_key_err")
        assert cached is not None
        assert isinstance(cached, ToolError)
        assert cached.status == "error"
        assert cached.error_code == "DISASM_ERROR"
        assert cached.message == "Failed to disassemble address"
        assert cached.hint == "Check offset"

    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self, mock_validate_file_path, patch_db_path):
        """Non-existent cache key returns None."""
        from reversecore_mcp.tools.radare2.r2_db import get_cached_result

        cached = await get_cached_result(str(mock_validate_file_path), "non_existent_key")
        assert cached is None

    @pytest.mark.asyncio
    async def test_concurrent_r2_db_access(self, mock_validate_file_path, patch_db_path):
        """Concurrent read/write operations succeed without database locked errors."""
        import asyncio

        from reversecore_mcp.tools.radare2.r2_db import (
            r2_add_bookmark,
            r2_create_structure,
            r2_list_bookmarks,
            r2_list_structures,
        )

        async def worker(index: int):
            # Create a structure
            await r2_create_structure(
                str(mock_validate_file_path),
                f"struct_{index}",
                [{"name": "f1", "type": "int", "offset": 0, "size": 4}],
            )
            # Add a bookmark
            await r2_add_bookmark(
                str(mock_validate_file_path),
                f"0x{1000 + index:x}",
                f"comment_{index}",
            )
            # Read structures and bookmarks
            structs = await r2_list_structures(str(mock_validate_file_path))
            bookmarks = await r2_list_bookmarks(str(mock_validate_file_path))
            assert structs.status == "success"
            assert bookmarks.status == "success"

        # Run 20 concurrent operations simultaneously
        tasks = [worker(i) for i in range(20)]
        await asyncio.gather(*tasks)

        final_structs = await r2_list_structures(str(mock_validate_file_path), limit=100)
        assert final_structs.status == "success"
        assert final_structs.data["count"] == 20
