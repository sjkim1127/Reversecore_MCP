"""Unit tests for malware API hashing algorithms and database."""

import pytest

from reversecore_mcp.tools.deobfuscation.data.hash_algorithms import (
    SUPPORTED_ALGORITHMS,
    ApiHashDatabase,
    compute_all_hashes,
    crc32_hash,
    djb2_32,
    fnv1_32,
    fnv1a_32,
    get_api_hash_db,
    murmurhash3_32,
    rol32,
    ror7,
    ror13,
    ror32,
    sdbm_32,
)


@pytest.mark.unit
class TestHashAlgorithms:
    """Test standard hashing algorithms."""

    def test_ror32_and_rol32(self):
        val = 0x12345678
        rotated_right = ror32(val, 8)
        assert rotated_right == 0x78123456
        assert rol32(rotated_right, 8) == val

    def test_ror13(self):
        # VirtualAlloc standard ROR13 hash is widely documented in Metasploit/Cobalt Strike
        h_str = ror13("VirtualAlloc")
        h_bytes = ror13(b"VirtualAlloc\x00extra")
        assert isinstance(h_str, int)
        assert h_str == h_bytes
        assert 0 <= h_str <= 0xFFFFFFFF

    def test_ror7(self):
        h1 = ror7("LoadLibraryA")
        h2 = ror7(b"LoadLibraryA")
        assert h1 == h2
        assert 0 <= h1 <= 0xFFFFFFFF

    def test_crc32_hash(self):
        h = crc32_hash("CreateProcessA")
        assert h == (crc32_hash(b"CreateProcessA") & 0xFFFFFFFF)

    def test_djb2_32(self):
        h = djb2_32("NtAllocateVirtualMemory")
        assert isinstance(h, int)
        assert djb2_32(b"NtAllocateVirtualMemory\x00") == h

    def test_sdbm_32(self):
        h = sdbm_32("VirtualProtect")
        assert isinstance(h, int)
        assert sdbm_32(b"VirtualProtect\x00") == h

    def test_fnv1a_and_fnv1_32(self):
        h_fnv1a = fnv1a_32("WriteProcessMemory")
        h_fnv1 = fnv1_32("WriteProcessMemory")
        assert h_fnv1a != h_fnv1
        assert 0 <= h_fnv1a <= 0xFFFFFFFF
        assert 0 <= h_fnv1 <= 0xFFFFFFFF

    def test_murmurhash3_32(self):
        h1 = murmurhash3_32("MessageBoxA", seed=0)
        h2 = murmurhash3_32("MessageBoxA", seed=42)
        assert h1 != h2
        # Test various lengths (tails)
        assert murmurhash3_32("A") > 0
        assert murmurhash3_32("AB") > 0
        assert murmurhash3_32("ABC") > 0
        assert murmurhash3_32("ABCD") > 0

    def test_compute_all_hashes(self):
        hashes = compute_all_hashes("VirtualAlloc")
        assert "ror13" in hashes
        assert "crc32" in hashes
        assert "djb2" in hashes
        assert "fnv1a" in hashes
        assert "murmurhash3" in hashes
        assert len(hashes) == len(SUPPORTED_ALGORITHMS)


@pytest.mark.unit
class TestApiHashDatabase:
    """Test ApiHashDatabase lookup and custom symbol registration."""

    def test_database_lookup(self):
        db = ApiHashDatabase()
        h_ror13 = ror13("VirtualAlloc")
        matches = db.lookup(h_ror13, algorithm="ror13")
        assert len(matches) >= 1
        assert any(m["api_name"] == "VirtualAlloc" for m in matches)
        assert any(m["dll"] == "kernel32.dll" for m in matches)

        # Lookup without specifying algorithm
        all_matches = db.lookup(h_ror13)
        assert len(all_matches) >= 1

    def test_custom_symbol_registration(self):
        db = ApiHashDatabase()
        db.register_custom_symbol(
            "custom_driver.sys", "CustomDispatcher", "NTSTATUS CustomDispatcher()"
        )

        h_djb2 = djb2_32("CustomDispatcher")
        matches = db.lookup(h_djb2, algorithm="djb2")
        assert len(matches) >= 1
        assert matches[0]["api_name"] == "CustomDispatcher"
        assert matches[0]["dll"] == "custom_driver.sys"
        assert "NTSTATUS" in matches[0]["signature"]

    def test_global_singleton(self):
        db1 = get_api_hash_db()
        db2 = get_api_hash_db()
        assert db1 is db2
