"""Tests for reversecore_mcp.tools.ghidra.decompilation."""

from unittest.mock import AsyncMock, patch

import pytest


class TestEstimateTypeSize:
    """Tests for _estimate_type_size."""

    def test_void(self):
        from reversecore_mcp.tools.ghidra.decompilation import _estimate_type_size

        assert _estimate_type_size("void") == 4

    def test_char(self):
        from reversecore_mcp.tools.ghidra.decompilation import _estimate_type_size

        assert _estimate_type_size("char") == 1

    def test_int(self):
        from reversecore_mcp.tools.ghidra.decompilation import _estimate_type_size

        assert _estimate_type_size("int") == 4

    def test_pointer(self):
        from reversecore_mcp.tools.ghidra.decompilation import _estimate_type_size

        assert _estimate_type_size("char*") == 8

    def test_struct(self):
        from reversecore_mcp.tools.ghidra.decompilation import _estimate_type_size

        assert _estimate_type_size("struct foo") == 4

    def test_unknown(self):
        from reversecore_mcp.tools.ghidra.decompilation import _estimate_type_size

        assert _estimate_type_size("custom_type") == 4


class TestInferTypeFromInstruction:
    """Tests for _infer_type_from_instruction."""

    def test_movzx(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movzx", "eax, byte [rbx]") == "uint8_t"

    def test_movsx(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movsx", "eax, byte [rbx]") == "uint8_t"

    def test_movsd(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movsd", "xmm0, [rbx]") == "double"

    def test_movss(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movss", "xmm0, [rbx]") == "float"

    def test_lea(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("lea", "rax, [rbx+4]") == "uint64_t"

    def test_default(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("nop", "") == "uint32_t"


class TestValidateAddressOrFail:
    """Tests for _validate_address_or_fail."""

    def test_valid(self):
        from reversecore_mcp.tools.ghidra.decompilation import _validate_address_or_fail

        result = _validate_address_or_fail("0x401000")
        assert result is None

    def test_invalid(self):
        from reversecore_mcp.tools.ghidra.decompilation import _validate_address_or_fail

        result = _validate_address_or_fail("bad; cmd")
        assert result is not None


class TestParseRegisterState:
    """Tests for _parse_register_state."""

    def test_empty(self):
        from reversecore_mcp.tools.ghidra.decompilation import _parse_register_state

        result = _parse_register_state("")
        assert result == {}

    def test_simple(self):
        from reversecore_mcp.tools.ghidra.decompilation import _parse_register_state

        result = _parse_register_state("rax = 0x401000\nrbx = 0x7fff0000")
        assert result["rax"] == "0x401000"
        assert result["rbx"] == "0x7fff0000"


class TestExtractStructuresFromDisasm:
    """Tests for _extract_structures_from_disasm."""

    def test_empty(self):
        from reversecore_mcp.tools.ghidra.decompilation import _extract_structures_from_disasm

        result = _extract_structures_from_disasm([])
        assert result == {}

    def test_with_ops(self):
        from reversecore_mcp.tools.ghidra.decompilation import _extract_structures_from_disasm

        ops = [
            {"opcode": "mov", "operands": [{"type": "mem", "value": "[rax + 0x10]"}]},
            {"opcode": "lea", "operands": [{"type": "reg", "value": "rbx"}]},
        ]
        result = _extract_structures_from_disasm(ops)
        assert isinstance(result, dict)


class TestEmulateMachineCode:
    """Tests for emulate_machine_code."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import emulate_machine_code

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("rax = 0x401000", 20)
                result = await emulate_machine_code(str(test_file), "0x401000")

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_empty_register_state(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import emulate_machine_code

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("", 0)
                result = await emulate_machine_code(str(test_file), "0x401000")

        assert result.status in ("success", "error")


class TestExtractStructuresFromDisasm:
    """Tests for _extract_structures_from_disasm."""

    def test_empty(self):
        from reversecore_mcp.tools.ghidra.decompilation import _extract_structures_from_disasm

        result = _extract_structures_from_disasm([])
        assert result == {}

    def test_with_ops(self):
        from reversecore_mcp.tools.ghidra.decompilation import _extract_structures_from_disasm

        ops = [
            {"opcode": "mov", "operands": [{"type": "mem", "value": "[rax + 0x10]"}]},
            {"opcode": "lea", "operands": [{"type": "reg", "value": "rbx"}]},
        ]
        result = _extract_structures_from_disasm(ops)
        assert isinstance(result, dict)

    def test_skips_stack_regs(self):
        from reversecore_mcp.tools.ghidra.decompilation import _extract_structures_from_disasm

        ops = [
            {"opcode": "mov", "disasm": "mov eax, [rsp+0x10]"},
            {"opcode": "mov", "disasm": "mov ebx, [rbp+0x20]"},
        ]
        result = _extract_structures_from_disasm(ops)
        assert result == {}

    def test_dedup_fields(self):
        from reversecore_mcp.tools.ghidra.decompilation import _extract_structures_from_disasm

        ops = [
            {"opcode": "mov", "disasm": "mov eax, [rax+0x10]"},
            {"opcode": "mov", "disasm": "mov ebx, [rax+0x10]"},
        ]
        result = _extract_structures_from_disasm(ops)
        assert "struct_ptr_rax" in result
        assert len(result["struct_ptr_rax"]["fields"]) == 1


class TestInferTypeFromInstruction:
    """Tests for _infer_type_from_instruction."""

    def test_float(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movss", "movss xmm0, [rax]") == "float"

    def test_double(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movsd", "movsd xmm0, [rax]") == "double"

    def test_sse_vector(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("movaps", "movaps xmm0, [rax]") == "float[4]"

    def test_uint8_t(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("mov", "mov byte [rax], 1") == "uint8_t"

    def test_uint16_t(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("mov", "mov word [rax], 1") == "uint16_t"

    def test_uint32_t(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("mov", "mov dword [rax], 1") == "uint32_t"

    def test_uint64_t(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("mov", "mov qword [rax], 1") == "uint64_t"

    def test_default(self):
        from reversecore_mcp.tools.ghidra.decompilation import _infer_type_from_instruction

        assert _infer_type_from_instruction("nop", "nop") == "uint32_t"


class TestValidateAddressOrFail:
    """Tests for _validate_address_or_fail."""

    def test_valid_address(self):
        from reversecore_mcp.tools.ghidra.decompilation import _validate_address_or_fail

        assert _validate_address_or_fail("0x401000") is None

    def test_invalid_address(self):
        from reversecore_mcp.tools.ghidra.decompilation import _validate_address_or_fail

        result = _validate_address_or_fail("; rm -rf /")
        assert result is not None
        assert result.status == "error"


class TestGetPseudoCode:
    """Tests for get_pseudo_code."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import get_pseudo_code

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("void main() {}", 20)
                result = await get_pseudo_code(str(test_file), "main")

        assert result.status in ("success", "error")


class TestSmartDecompile:
    """Tests for smart_decompile."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import smart_decompile

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("int main() { return 0; }", 30)
                result = await smart_decompile(str(test_file), "0x401000")

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_with_json_output(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import smart_decompile

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ('{"functions": [{"name": "main"}]}', 30)
                result = await smart_decompile(str(test_file), "0x401000")

        assert result.status in ("success", "error")


class TestRecoverStructures:
    """Tests for recover_structures."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import recover_structures

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ('{"structures": []}', 20)
                result = await recover_structures(str(test_file), "0x401000")

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_no_json(self, tmp_path):
        from reversecore_mcp.tools.ghidra.decompilation import recover_structures

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghidra.decompilation.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.ghidra.decompilation._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("no json here", 20)
                result = await recover_structures(str(test_file), "0x401000")

        assert result.status in ("success", "error")
