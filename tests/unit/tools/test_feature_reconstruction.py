"""Unit tests for Feature Reconstruction and Equivalence Verification."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import success
from reversecore_mcp.tools.analysis.feature_reconstruction import (
    _clean_decompiler_artifacts,
    _extract_called_apis,
    _synthesize_c_code,
    _synthesize_python_code,
    reconstruct_feature_code,
)


@pytest.mark.unit
def test_clean_decompiler_artifacts():
    dirty_pseudo_c = """
    undefined8 main(void) {
        long in_FS_OFFSET;
        long local_10;

        local_10 = *(long *)(in_FS_OFFSET + 0x28);
        puts("Hello World");
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
            __stack_chk_fail();
        }
        return 0;
    }
    """
    cleaned = _clean_decompiler_artifacts(dirty_pseudo_c)
    cleaned_str = "\n".join(cleaned)
    assert "in_FS_OFFSET" not in cleaned_str
    assert "__stack_chk_fail" not in cleaned_str
    assert 'puts("Hello World");' in cleaned_str


@pytest.mark.unit
def test_extract_called_apis():
    disasm = """
    0x401000  call sym.imp.printf
    0x401010  call sym.imp.malloc
    0x401020  call 0x401050
    """
    pseudo_c = 'printf("Hello %s", name); malloc(100);'
    apis = _extract_called_apis(disasm, pseudo_c)
    assert "printf" in apis
    assert "malloc" in apis


@pytest.mark.unit
def test_synthesize_python_code():
    c_lines = [
        'puts("Starting analysis");',
        "int x = 42;",
        "return x;",
    ]
    code = _synthesize_python_code("test_func", c_lines, ["puts"])
    assert "def test_func(" in code
    assert "return x" in code
    assert "puts" in code


@pytest.mark.unit
def test_synthesize_c_code():
    c_lines = [
        'printf("Result: %d\\n", val);',
        "return 0;",
    ]
    code = _synthesize_c_code("my_calc", c_lines, ["printf"])
    assert "#include <stdint.h>" in code
    assert "my_calc" in code
    assert "return 0;" in code


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_feature_code_workflow(tmp_path):
    bin_file = tmp_path / "sample.exe"
    bin_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

    pseudo_c = """int calculate_hash(char *input) {
        int hash = 5381;
        while (*input != 0) {
            hash = hash * 33 + *input;
            input++;
        }
        return hash;
    }"""

    disasm_output = """
    0x401000  mov eax, 0x1505
    0x401005  cmp byte [rdi], 0
    0x401008  je 0x401020
    0x40100a  jmp 0x401005
    0x401020  ret
    """

    with patch(
        "reversecore_mcp.tools.analysis.feature_reconstruction.validate_file_path",
        return_value=bin_file,
    ):
        with patch("reversecore_mcp.tools.analysis.feature_reconstruction.validate_address_format"):
            with patch(
                "reversecore_mcp.tools.analysis.feature_reconstruction.r2_decompile",
                new_callable=AsyncMock,
            ) as m_decomp:
                m_decomp.return_value = success({"pseudo_c": pseudo_c, "full_pseudo_c": pseudo_c})
                with patch(
                    "reversecore_mcp.tools.analysis.feature_reconstruction.execute_r2_command",
                    new_callable=AsyncMock,
                ) as m_r2:
                    m_r2.return_value = (disasm_output, 100)

                    # 1. Reconstruct to C
                    res_c = await reconstruct_feature_code(
                        str(bin_file), "calculate_hash", target_language="c"
                    )
                    assert res_c.status == "success"
                    assert res_c.data["target_language"] == "c"
                    assert "verification_ledger" in res_c.data
                    assert res_c.data["equivalence_status"] in (
                        "STRUCTURALLY_EQUIVALENT",
                        "VERIFIED",
                    )
                    assert "calculate_hash" in res_c.data["reconstructed_code"]

                    # 2. Reconstruct to Python with test inputs
                    m_r2.side_effect = [
                        (disasm_output, 100),  # pdf
                        ("rax=0x1505 rbx=0x0", 50),  # esil emulation
                    ]
                    res_py = await reconstruct_feature_code(
                        str(bin_file),
                        "calculate_hash",
                        target_language="python",
                        test_inputs=["0x42"],
                    )
                    assert res_py.status == "success"
                    assert res_py.data["target_language"] == "python"
                    assert res_py.data["equivalence_status"] == "VERIFIED"
                    emul_ver = res_py.data["verification_ledger"]["emulation_verification"]
                    assert emul_ver["emulation_successful"] is True
                    assert len(emul_ver["obligation_ledger"]) == 1
                    assert emul_ver["obligation_ledger"][0]["esil_return"] == "0x1505"
                    assert emul_ver["obligation_ledger"][0]["status"] == "PASSED"
