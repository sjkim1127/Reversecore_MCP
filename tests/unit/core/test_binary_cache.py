"""Unit tests for BinaryMetadataCache."""

import time

from reversecore_mcp.core.binary_cache import BinaryMetadataCache, binary_cache


class TestBinaryMetadataCache:
    """Tests for BinaryMetadataCache class."""

    def test_cache_key_generation(self, tmp_path):
        """Test that cache keys are generated correctly."""
        cache = BinaryMetadataCache()
        test_file = tmp_path / "test.bin"
        test_file.write_text("test")

        key1 = cache._get_cache_key(str(test_file))
        key2 = cache._get_cache_key(str(test_file.absolute()))

        assert key1 == key2
        assert str(test_file.absolute()) in key1

    def test_set_and_get_metadata(self, tmp_path):
        """Test setting and getting metadata."""
        cache = BinaryMetadataCache()
        test_file = tmp_path / "test.bin"
        test_file.write_text("test")

        # Set metadata
        cache.set(str(test_file), "format", "PE")
        cache.set(str(test_file), "arch", "x86-64")

        # Get metadata
        assert cache.get(str(test_file), "format") == "PE"
        assert cache.get(str(test_file), "arch") == "x86-64"

    def test_get_nonexistent_key(self, tmp_path):
        """Test getting a key that doesn't exist."""
        cache = BinaryMetadataCache()
        test_file = tmp_path / "test.bin"
        test_file.write_text("test")

        result = cache.get(str(test_file), "nonexistent")
        assert result is None

    def test_cache_invalidation_on_file_modification(self, tmp_path):
        """Test that cache is invalidated when file is modified."""
        # Use 0-second TTL to always check mtime
        cache = BinaryMetadataCache(ttl_seconds=0)
        test_file = tmp_path / "test.bin"
        test_file.write_text("original")

        # Set initial metadata
        cache.set(str(test_file), "format", "PE")
        assert cache.get(str(test_file), "format") == "PE"

        # Modify file
        time.sleep(0.01)  # Ensure mtime changes
        test_file.write_text("modified")

        # Cache should be invalid now
        result = cache.get(str(test_file), "format")
        assert result is None

    def test_cache_with_nonexistent_file(self, tmp_path):
        """Test that cache handles nonexistent files gracefully."""
        cache = BinaryMetadataCache()
        nonexistent = tmp_path / "nonexistent.bin"

        # Should return None for nonexistent file
        result = cache.get(str(nonexistent), "format")
        assert result is None

        # Setting on nonexistent file should not crash
        cache.set(str(nonexistent), "format", "PE")

    def test_clear_specific_file(self, tmp_path):
        """Test clearing cache for a specific file."""
        cache = BinaryMetadataCache()
        test_file1 = tmp_path / "test1.bin"
        test_file2 = tmp_path / "test2.bin"
        test_file1.write_text("test1")
        test_file2.write_text("test2")

        # Set metadata for both files
        cache.set(str(test_file1), "format", "PE")
        cache.set(str(test_file2), "format", "ELF")

        # Clear first file
        cache.clear(str(test_file1))

        # First file should be cleared
        assert cache.get(str(test_file1), "format") is None
        # Second file should still be cached
        assert cache.get(str(test_file2), "format") == "ELF"

    def test_clear_all(self, tmp_path):
        """Test clearing entire cache."""
        cache = BinaryMetadataCache()
        test_file1 = tmp_path / "test1.bin"
        test_file2 = tmp_path / "test2.bin"
        test_file1.write_text("test1")
        test_file2.write_text("test2")

        # Set metadata for both files
        cache.set(str(test_file1), "format", "PE")
        cache.set(str(test_file2), "format", "ELF")

        # Clear all
        cache.clear()

        # Both should be cleared
        assert cache.get(str(test_file1), "format") is None
        assert cache.get(str(test_file2), "format") is None

    def test_multiple_keys_per_file(self, tmp_path):
        """Test storing multiple metadata keys for the same file."""
        cache = BinaryMetadataCache()
        test_file = tmp_path / "test.bin"
        test_file.write_text("test")

        # Set multiple keys
        cache.set(str(test_file), "format", "PE")
        cache.set(str(test_file), "arch", "x86-64")
        cache.set(str(test_file), "size", 1024)

        # All keys should be retrievable
        assert cache.get(str(test_file), "format") == "PE"
        assert cache.get(str(test_file), "arch") == "x86-64"
        assert cache.get(str(test_file), "size") == 1024

    def test_overwrite_existing_key(self, tmp_path):
        """Test overwriting an existing key."""
        cache = BinaryMetadataCache()
        test_file = tmp_path / "test.bin"
        test_file.write_text("test")

        # Set initial value
        cache.set(str(test_file), "format", "PE")
        assert cache.get(str(test_file), "format") == "PE"

        # Overwrite
        cache.set(str(test_file), "format", "ELF")
        assert cache.get(str(test_file), "format") == "ELF"

    def test_is_valid_method(self, tmp_path):
        """Test the _is_valid method."""
        # Use 0-second TTL to always check mtime
        cache = BinaryMetadataCache(ttl_seconds=0)
        test_file = tmp_path / "test.bin"
        test_file.write_text("test")

        # Not valid initially (not in cache)
        assert cache._is_valid(str(test_file)) is False

        # Set metadata
        cache.set(str(test_file), "format", "PE")

        # Now valid
        assert cache._is_valid(str(test_file)) is True

        # Modify file
        time.sleep(0.01)
        test_file.write_text("modified")

        # No longer valid
        assert cache._is_valid(str(test_file)) is False

    def test_global_instance(self):
        """Test that the global instance is accessible."""
        assert binary_cache is not None
        assert isinstance(binary_cache, BinaryMetadataCache)

    def test_is_valid_false_when_key_not_in_timestamps(self, tmp_path):
        """_is_valid returns False when key is in cache but not in _file_timestamps."""
        cache = BinaryMetadataCache(ttl_seconds=0)
        test_file = tmp_path / "test.bin"
        test_file.write_text("x")
        key = cache._get_cache_key(str(test_file))
        cache._cache[key] = {"format": "PE"}
        # Do not set _file_timestamps[key]
        assert cache._is_valid(str(test_file)) is False

    def test_is_valid_file_not_found_invalidates_cache(self, tmp_path):
        """When file is deleted after caching, _is_valid invalidates and returns False."""
        cache = BinaryMetadataCache(ttl_seconds=0)
        test_file = tmp_path / "gone.bin"
        test_file.write_text("x")
        cache.set(str(test_file), "format", "PE")
        test_file.unlink()
        assert cache._is_valid(str(test_file)) is False
        assert cache.get(str(test_file), "format") is None
