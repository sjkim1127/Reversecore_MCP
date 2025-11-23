"""Unit tests for ESIL emulation tools."""

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools import cli_tools
from reversecore_mcp.tools import decompilation
from reversecore_mcp.tools import r2_analysis


def test_parse_register_state_basic():
    """Test basic register state parsing."""
    ar_output = """rax = 0x00000000
rbx = 0x00401000
rcx = 0xdeadbeef
rip = 0x00401234"""
    
    result = decompilation._parse_register_state(ar_output)
    
    assert result["rax"] == "0x00000000"
    assert result["rbx"] == "0x00401000"
    assert result["rcx"] == "0xdeadbeef"
    assert result["rip"] == "0x00401234"
    assert len(result) == 4


def test_parse_register_state_empty():
    """Test register parsing with empty output."""
    result = decompilation._parse_register_state("")
    assert result == {}


def test_parse_register_state_malformed():
    """Test register parsing with malformed output."""
    ar_output = """some random text
no equals sign here
rax = 0x123"""
    
    result = decompilation._parse_register_state(ar_output)
    
    # Should only parse the valid line
    assert result["rax"] == "0x123"
    assert len(result) == 1


def test_parse_register_state_with_spaces():
    """Test register parsing handles whitespace correctly."""
    ar_output = """  rax  =  0x00000000  
rbx=0x00401000
  rcx   =   0xdeadbeef  """
    
    result = decompilation._parse_register_state(ar_output)
    
    assert result["rax"] == "0x00000000"
    assert result["rbx"] == "0x00401000"
    assert result["rcx"] == "0xdeadbeef"


@pytest.mark.asyncio
async def test_emulate_machine_code_validation_error(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test emulate_machine_code with invalid parameters."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    # Test instructions count too high
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="main",
        instructions=2000  # Exceeds 1000 limit
    )
    
    assert result.status == "error"
    assert "VALIDATION_ERROR" in result.error_code or "1000" in result.message


@pytest.mark.asyncio
async def test_emulate_machine_code_invalid_address(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test emulate_machine_code with invalid address format."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    # Test with shell injection attempt
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="main; rm -rf /",
        instructions=10
    )
    
    assert result.status == "error"
    assert "VALIDATION_ERROR" in result.error_code


@pytest.mark.asyncio
async def test_emulate_machine_code_success(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test successful emulation with mocked radare2 output."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        # Mock radare2 'ar' output
        mock_output = """rax = 0x00000000
rbx = 0x00401000
rcx = 0xdeadbeef
rsp = 0x7fff0000
rip = 0x00401234"""
        return (mock_output, len(mock_output))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="main",
        instructions=50
    )
    
    assert result.status == "success"
    assert isinstance(result.data, dict)
    assert "rax" in result.data
    assert result.data["rax"] == "0x00000000"
    assert result.metadata.get("instructions_executed") == 50
    assert result.metadata.get("start_address") == "main"


@pytest.mark.asyncio
async def test_emulate_machine_code_empty_registers(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test emulation with empty register output (emulation failure)."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        # Empty output indicates emulation failure
        return ("", 0)
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="main",
        instructions=10
    )
    
    assert result.status == "error"
    assert "EMULATION_ERROR" in result.error_code


@pytest.mark.asyncio
async def test_emulate_machine_code_default_instructions(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test emulation uses default instruction count of 50."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    executed_commands = []
    
    async def mock_exec(cmd, **kw):
        executed_commands.append(cmd)
        mock_output = "rax = 0x00000000"
        return (mock_output, len(mock_output))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="0x401000"
    )
    
    assert result.status == "success"
    # Check that 'aes 50' was in the command
    assert any("aes 50" in str(cmd) for cmd in executed_commands)


@pytest.mark.asyncio
async def test_emulate_machine_code_hex_address(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test emulation with hex address format."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        mock_output = "rip = 0x00401000"
        return (mock_output, len(mock_output))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="0x401000",
        instructions=10
    )
    
    assert result.status == "success"
    assert result.metadata.get("start_address") == "0x401000"


@pytest.mark.asyncio
async def test_emulate_machine_code_symbol_address(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test emulation with symbol address format."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        mock_output = "rax = 0x12345678"
        return (mock_output, len(mock_output))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.emulate_machine_code(
        file_path=str(test_file),
        start_address="sym.decrypt",
        instructions=100
    )
    
    assert result.status == "success"
    assert result.metadata.get("start_address") == "sym.decrypt"
    assert result.metadata.get("instructions_executed") == 100
