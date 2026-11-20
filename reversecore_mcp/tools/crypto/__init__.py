"""Cryptographic analysis and key extraction tools package.

Provides static cryptographic constant scanning and dynamic API-hooking key extraction:
- scan_crypto_constants: FindCrypt-style scanner for AES, ChaCha20, RC4, TEA/XTEA, hashes, and Base64
- extract_crypto_keys_dynamic: LD_PRELOAD/DYLD_INSERT_LIBRARIES hooker for runtime key/IV capture
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class CryptoToolsPlugin(Plugin):
    """Plugin for static cryptographic constant scanning and dynamic key extraction."""

    @property
    def name(self) -> str:
        return "crypto_tools"

    @property
    def description(self) -> str:
        return (
            "Cryptographic analysis tools including FindCrypt-style static constant "
            "detection and dynamic API-hooking key/IV extraction."
        )

    def register(self, mcp_server: Any) -> None:
        """Register cryptographic analysis tools."""
        from reversecore_mcp.tools.crypto.dynamic_extractor import (
            extract_crypto_keys_dynamic,
        )
        from reversecore_mcp.tools.crypto.scanner import scan_crypto_constants

        mcp_server.tool(scan_crypto_constants)
        mcp_server.tool(extract_crypto_keys_dynamic)

        logger.info(f"Registered {self.name} plugin with 2 cryptographic analysis tools")


__all__ = ["CryptoToolsPlugin"]
