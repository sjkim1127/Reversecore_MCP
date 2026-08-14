"""Data package for deobfuscation algorithms and databases."""

from __future__ import annotations

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
    ror7,
    ror13,
    ror32,
    sdbm_32,
)

__all__ = [
    "SUPPORTED_ALGORITHMS",
    "ApiHashDatabase",
    "compute_all_hashes",
    "crc32_hash",
    "djb2_32",
    "fnv1_32",
    "fnv1a_32",
    "get_api_hash_db",
    "murmurhash3_32",
    "ror7",
    "ror13",
    "ror32",
    "sdbm_32",
]
