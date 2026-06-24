"""Unit tests for Ghidra SAST Extension."""

import pytest

from reversecore_mcp.core.extension import GhidraAnalysisContext
from reversecore_mcp.tools.ghidra.ghidra_sast_extension import GhidraSASTExtension


@pytest.mark.asyncio
async def test_ghidra_sast_extension_unsafe():
    """Test that GhidraSASTExtension detects unsafe calls and injects comments."""
    ext = GhidraSASTExtension()
    ctx = GhidraAnalysisContext(
        file_path="/app/workspace/test.elf",
        function_address="0x401000",
    )

    decompiled = """
void main() {
    char dest[10];
    strcpy(dest, "unbounded input");
}
"""
    result = await ext.on_after_decompile(ctx, decompiled)
    assert "[🚨 SAST WARNING]" in result
    assert ctx.metadata.get("sast_warnings") == 1


@pytest.mark.asyncio
async def test_ghidra_sast_extension_safe():
    """Test that GhidraSASTExtension does not annotate safe code."""
    ext = GhidraSASTExtension()
    ctx = GhidraAnalysisContext(
        file_path="/app/workspace/test.elf",
        function_address="0x401000",
    )

    decompiled = """
void main() {
    char dest[10];
    strncpy(dest, "bounded input", 9);
}
"""
    result = await ext.on_after_decompile(ctx, decompiled)
    assert "[🚨 SAST WARNING]" not in result
    assert "sast_warnings" not in ctx.metadata
