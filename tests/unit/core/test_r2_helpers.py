"""Unit tests for reversecore_mcp.core.r2_helpers."""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from reversecore_mcp.core.r2_helpers import (
    _get_file_stat_key,
    _get_r2_pool,
    calculate_dynamic_timeout,
    get_adaptive_analysis_level,
)


class TestR2HelpersStatKey:
    """Tests for _get_file_stat_key."""

    def test_existing_file_stat_key(self, tmp_path: Path):
        test_file = tmp_path / "sample.bin"
        test_file.write_bytes(b"\x90" * 100)

        key = _get_file_stat_key(str(test_file))
        assert key[0] == str(test_file.resolve())
        assert key[1] == 100
        assert isinstance(key[2], int)

    def test_nonexistent_file_stat_key(self, tmp_path: Path):
        nonexistent = tmp_path / "does_not_exist.bin"
        key = _get_file_stat_key(str(nonexistent))
        assert key[0] == str(nonexistent.resolve())
        assert key[1] == -1
        assert key[2] == -1


class TestCalculateDynamicTimeout:
    """Tests for calculate_dynamic_timeout with stat-based caching."""

    def test_timeout_calculation(self, tmp_path: Path):
        test_file = tmp_path / "small.bin"
        test_file.write_bytes(b"\x00" * 1024)

        timeout = calculate_dynamic_timeout(str(test_file), base_timeout=300)
        assert timeout >= 300

    def test_cache_invalidation_on_file_modification(self, tmp_path: Path):
        test_file = tmp_path / "grow.bin"
        # 1 MB initially
        test_file.write_bytes(b"\x90" * (1024 * 1024))
        timeout_1 = calculate_dynamic_timeout(str(test_file), base_timeout=300)

        # Ensure mtime updates
        time.sleep(0.01)
        # Grow to 50 MB
        test_file.write_bytes(b"\x90" * (50 * 1024 * 1024))
        timeout_2 = calculate_dynamic_timeout(str(test_file), base_timeout=300)

        assert timeout_2 > timeout_1
        assert timeout_2 == 300 + int(50 * 2)

    def test_cache_clear_and_info(self, tmp_path: Path):
        calculate_dynamic_timeout.cache_clear()
        info_before = calculate_dynamic_timeout.cache_info()
        assert info_before.hits == 0

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 500)

        calculate_dynamic_timeout(str(test_file))
        calculate_dynamic_timeout(str(test_file))

        info_after = calculate_dynamic_timeout.cache_info()
        assert info_after.hits >= 1


class TestGetAdaptiveAnalysisLevel:
    """Tests for get_adaptive_analysis_level with stat-based caching."""

    def test_small_file_level(self, tmp_path: Path):
        test_file = tmp_path / "tiny.bin"
        test_file.write_bytes(b"\x90" * 1024)
        level = get_adaptive_analysis_level(str(test_file))
        assert level == "aaa"

    def test_medium_file_level(self, tmp_path: Path):
        test_file = tmp_path / "medium.bin"
        # 15 MB -> Medium file (10MB - 50MB) -> "aa"
        test_file.write_bytes(b"\x90" * (15 * 1024 * 1024))
        level = get_adaptive_analysis_level(str(test_file))
        assert level == "aa"

    def test_large_file_level(self, tmp_path: Path):
        test_file = tmp_path / "large.bin"
        # 60 MB -> Large file (50MB - 100MB) -> "aab"
        with patch("os.stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_size=60 * 1024 * 1024, st_mtime_ns=12345)
            level = get_adaptive_analysis_level(str(test_file))
            assert level == "aab"

    def test_very_large_file_level(self, tmp_path: Path):
        test_file = tmp_path / "huge.bin"
        # 250 MB -> Very large file (>200MB) -> "-n"
        with patch("os.stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_size=250 * 1024 * 1024, st_mtime_ns=54321)
            level = get_adaptive_analysis_level(str(test_file))
            assert level == "-n"

    def test_requested_no_analysis(self, tmp_path: Path):
        test_file = tmp_path / "file.bin"
        test_file.write_bytes(b"\x90" * 100)
        level = get_adaptive_analysis_level(str(test_file), requested_level="-n")
        assert level == "-n"

    def test_file_modification_invalidates_cached_level(self, tmp_path: Path):
        test_file = tmp_path / "dynamic_level.bin"
        # 1 KB -> "aaa"
        test_file.write_bytes(b"\x90" * 1024)
        assert get_adaptive_analysis_level(str(test_file)) == "aaa"

        # Grow to 20 MB -> "aa"
        time.sleep(0.01)
        test_file.write_bytes(b"\x90" * (20 * 1024 * 1024))
        assert get_adaptive_analysis_level(str(test_file)) == "aa"


class TestGetR2PoolHelper:
    """Tests for _get_r2_pool DI unification (Issue #272)."""

    def test_get_r2_pool_unification(self):
        from reversecore_mcp.core.container import get_r2_pool
        from reversecore_mcp.core.r2_pool import r2_pool

        pool_from_helper = _get_r2_pool()
        pool_from_container = get_r2_pool()

        assert pool_from_helper is r2_pool
        assert pool_from_container is r2_pool
