"""Unit tests for the architecture registry."""

from __future__ import annotations

from reversecore_mcp.core.arch_registry import (
    get_arch_init_cmds,
    get_pc_register,
    get_sp_register,
)


def test_x86_64_pc_register():
    assert get_pc_register("x86_64") == "rip"
    assert get_pc_register("amd64") == "rip"
    assert get_pc_register("x86", bits=64) == "rip"


def test_x86_32_pc_register():
    assert get_pc_register("x86", bits=32) == "eip"
    assert get_pc_register("x86") == "eip"


def test_arm64_pc_register():
    assert get_pc_register("arm64") == "pc"
    assert get_pc_register("aarch64") == "pc"
    assert get_pc_register("arm", bits=64) == "pc"


def test_arm32_pc_register():
    assert get_pc_register("arm32") == "r15"
    assert get_pc_register("arm", bits=32) == "r15"


def test_mips_init_cmds():
    cmds = get_arch_init_cmds("mips", bits=32)
    assert "e asm.arch=mips" in cmds
    assert "e asm.bits=32" in cmds

    cmds_64 = get_arch_init_cmds("mips", bits=64)
    assert "e asm.arch=mips" in cmds_64
    assert "e asm.bits=64" in cmds_64


def test_riscv_init_cmds():
    cmds = get_arch_init_cmds("riscv", bits=64)
    assert "e asm.arch=riscv" in cmds
    assert "e asm.bits=64" in cmds


def test_invalid_arch_returns_none_or_empty():
    assert get_pc_register("unknown_arch") is None
    assert get_sp_register("unknown_arch") is None
    assert get_arch_init_cmds("unknown_arch", bits=32) == []


def test_sp_register():
    assert get_sp_register("x86_64") == "rsp"
    assert get_sp_register("x86", bits=32) == "esp"
    assert get_sp_register("arm64") == "sp"
    assert get_sp_register("arm32") == "r13"
    assert get_sp_register("ppc", bits=32) == "r1"
