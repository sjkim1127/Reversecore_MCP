"""Tests for reversecore_mcp.tools.common.assembler."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.common.assembler import (
    assemble_instructions,
    get_capstone_params,
    get_keystone_params,
)

# Define mock constants to use in testing parameter mapping
MOCK_KS_ARCH_X86 = 4
MOCK_KS_MODE_64 = 8
MOCK_KS_ARCH_ARM = 1
MOCK_KS_MODE_THUMB = 16
MOCK_KS_ARCH_ARM64 = 2
MOCK_KS_MODE_LITTLE_ENDIAN = 0


def test_get_keystone_params_valid():
    """Test mapping of valid architecture and mode to Keystone constants."""
    with (
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_X86", MOCK_KS_ARCH_X86),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_64", MOCK_KS_MODE_64),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_ARM", MOCK_KS_ARCH_ARM),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_THUMB", MOCK_KS_MODE_THUMB),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_ARM64", MOCK_KS_ARCH_ARM64),
        patch(
            "reversecore_mcp.tools.common.assembler.KS_MODE_LITTLE_ENDIAN",
            MOCK_KS_MODE_LITTLE_ENDIAN,
        ),
    ):
        arch, mode = get_keystone_params("x86", "64")
        assert arch == MOCK_KS_ARCH_X86
        assert mode == MOCK_KS_MODE_64

        arch, mode = get_keystone_params("arm", "thumb")
        assert arch == MOCK_KS_ARCH_ARM
        assert mode == MOCK_KS_MODE_THUMB

        arch, mode = get_keystone_params("arm64", "64")
        assert arch == MOCK_KS_ARCH_ARM64
        assert mode == MOCK_KS_MODE_LITTLE_ENDIAN


def test_get_keystone_params_invalid():
    """Test get_keystone_params raises ValidationError for invalid inputs."""
    with pytest.raises(ValidationError):
        get_keystone_params("x86", "99")

    with pytest.raises(ValidationError):
        get_keystone_params("unknown_arch", "64")

    with pytest.raises(ValidationError):
        get_keystone_params("arm", "invalid_mode")


def test_get_capstone_params_valid():
    """Test mapping of valid architecture and mode to Capstone constants."""
    from capstone import CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM

    arch, mode = get_capstone_params("x86", "64")
    assert arch == CS_ARCH_X86
    assert mode == CS_MODE_64

    arch, mode = get_capstone_params("arm", "arm")
    assert arch == CS_ARCH_ARM
    assert mode == CS_MODE_ARM


def test_get_capstone_params_unsupported():
    """Test get_capstone_params returns None for unsupported mapping."""
    arch, mode = get_capstone_params("unknown", "64")
    assert arch is None
    assert mode == 0


class MockKsInstance:
    """Mock Keystone class instance for simulating assemblies."""

    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode

    def asm(self, code, addr=0):
        if "invalid" in code:
            from reversecore_mcp.tools.common.assembler import KsError

            if KsError is Exception:
                raise KsError("Keystone compile error")
            else:
                raise KsError(1)

        # Return mock encoding
        if "push" in code:
            return [0x50, 0x5B], 2
        return [0x90], 1


@pytest.mark.asyncio
async def test_assemble_instructions_success_x86_64():
    """Test successful x86-64 assembly using mocked Keystone."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert result.data["hex"] == "90"
        assert result.data["bytes"] == [0x90]
        assert result.data["instruction_count"] == 1
        assert "0x0: nop" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_success_x86_32():
    """Test successful x86-32 assembly with semicolons using mocked Keystone."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions(
            "push eax; pop ebx", arch="x86", mode="32", base_address="0x1000"
        )
        assert result.status == "success"
        assert result.data["hex"] == "505b"
        assert result.data["bytes"] == [0x50, 0x5B]
        assert result.data["instruction_count"] == 2
        # Since Capstone is installed, it will disassemble [0x50, 0x5b] as push eax; pop ebx
        assert "0x1000: push eax" in result.data["verification"]
        assert "0x1001: pop ebx" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_invalid_assembly():
    """Test assembly compilation fails for syntax error."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        # "invalid" in code triggers simulated KsError
        result = await assemble_instructions("invalid_instruction", arch="x86", mode="64")
        assert result.status == "error"
        assert result.error_code == "INTERNAL_ERROR"
        assert result.details["exception_type"] == "ToolExecutionError"


@pytest.mark.asyncio
async def test_assemble_instructions_invalid_params():
    """Test ValidationError is returned as error result for bad base address or architecture."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions(
            "nop", arch="x86", mode="64", base_address="invalid_hex"
        )
        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code

        result = await assemble_instructions("nop", arch="invalid_arch", mode="64")
        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code


@pytest.mark.asyncio
async def test_assemble_instructions_keystone_unavailable():
    """Test failure response when Keystone is not available."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", None):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert "KEYSTONE_NOT_AVAILABLE" in result.error_code
