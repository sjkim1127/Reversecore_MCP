import json
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.advanced_yara import (
    _mask_instruction,
    generate_advanced_yara_rule,
)


@pytest.mark.unit
def test_mask_instruction():
    # Regular instruction
    inst_mov = {"mnemonic": "mov rax, rbx", "opcode": "mov rax, rbx", "bytes": "4889d8"}
    assert _mask_instruction(inst_mov, True) == "48 89 d8"
    assert _mask_instruction(inst_mov, False) == "48 89 d8"

    # CALL instruction (5 bytes typically)
    inst_call = {
        "mnemonic": "call 0x123456",
        "opcode": "call 0x123456",
        "bytes": "e811223344",
    }
    assert _mask_instruction(inst_call, True) == "e8 ?? ?? ?? ??"
    assert _mask_instruction(inst_call, False) == "e8 11 22 33 44"

    # Conditional JMP (2 bytes)
    inst_je = {"mnemonic": "je 0x1234", "opcode": "je 0x1234", "bytes": "740a"}
    assert _mask_instruction(inst_je, True) == "74 ??"
    assert _mask_instruction(inst_je, False) == "74 0a"

    # Conditional JMP (6 bytes)
    inst_je_long = {
        "mnemonic": "je 0x123456",
        "opcode": "je 0x123456",
        "bytes": "0f8411223344",
    }
    assert _mask_instruction(inst_je_long, True) == "0f 84 ?? ?? ?? ??"


@pytest.mark.unit
@pytest.mark.asyncio
@patch("reversecore_mcp.tools.analysis.advanced_yara.validate_file_path")
@patch("reversecore_mcp.tools.analysis.advanced_yara._execute_r2_command")
async def test_generate_advanced_yara_rule_success(mock_execute, mock_validate):
    mock_validate.return_value = Path("test.bin")

    mock_instructions = [
        {"mnemonic": "mov rax, rbx", "bytes": "4889d8"},
        {"mnemonic": "call 0x1000", "bytes": "e811223344"},
        {"mnemonic": "xor rcx, rcx", "bytes": "4831c9"},
    ]
    mock_execute.return_value = (json.dumps(mock_instructions), 0)

    result = await generate_advanced_yara_rule(
        file_path="test.bin",
        address="0x1000",
        rule_name="test_rule",
        num_instructions=3,
        mask_operands=True,
    )

    assert result.status == "success"
    content_json = result.data
    assert "rule_name" in content_json
    assert content_json["rule_name"] == "test_rule"
    assert "48 89 d8 e8 ?? ?? ?? ?? 48 31 c9" in content_json["yara_rule"]


@pytest.mark.unit
@pytest.mark.asyncio
@patch("reversecore_mcp.tools.analysis.advanced_yara.validate_file_path")
@patch("reversecore_mcp.tools.analysis.advanced_yara._execute_r2_command")
async def test_generate_advanced_yara_rule_no_mask(mock_execute, mock_validate):
    mock_validate.return_value = Path("test.bin")

    mock_instructions = [
        {"mnemonic": "call 0x1000", "bytes": "e811223344"},
    ]
    mock_execute.return_value = (json.dumps(mock_instructions), 0)

    result = await generate_advanced_yara_rule(
        file_path="test.bin",
        address="0x1000",
        rule_name="test_rule",
        num_instructions=1,
        mask_operands=False,
    )

    assert result.status == "success"
    content_json = result.data
    assert "e8 11 22 33 44" in content_json["yara_rule"]
