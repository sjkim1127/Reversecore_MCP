"""Unit tests for verify_string_references tool (Issue #324)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.analysis.string_verifier import (
    _is_code_xref,
    _parse_address_safely,
    verify_string_references,
)

FIXTURE_BINARY = (
    Path(__file__).resolve().parents[3] / "fixtures" / "workspace" / "binaries" / "hello_x64"
)


@pytest.mark.unit
class TestStringVerifierHelpers:
    """Test helper functions for string verification."""

    def test_parse_address_safely(self):
        assert _parse_address_safely("0x401000") == 0x401000
        assert _parse_address_safely("0X1000") == 0x1000
        assert _parse_address_safely("4198400") == 4198400
        assert _parse_address_safely(0x401000) == 0x401000
        assert _parse_address_safely("not_an_address") is None
        assert _parse_address_safely("") is None

    def test_is_code_xref_with_function(self):
        item = {
            "from": 0x401020,
            "type": "DATA",
            "fcn_name": "main",
            "opcode": "lea rdi, [0x402000]",
        }
        assert _is_code_xref(item) is True

    def test_is_code_xref_with_code_type(self):
        item = {
            "from": 0x401020,
            "type": "CODE",
            "opcode": "call 0x402000",
        }
        assert _is_code_xref(item) is True

    def test_is_code_xref_non_code_synthetic_section(self):
        item = {
            "from": 0x403000,
            "type": "NULL",
            "fcn_name": "aav.0x403000+16",
            "opcode": "invalid",
        }
        assert _is_code_xref(item) is False


@pytest.mark.unit
@pytest.mark.asyncio
class TestVerifyStringReferences:
    """Integration and unit tests for verify_string_references."""

    @pytest.fixture
    def test_binary(self):
        import shutil

        from reversecore_mcp.core.security import get_workspace_config

        ws = get_workspace_config().workspace
        ws.mkdir(parents=True, exist_ok=True)
        dest = ws / "hello_x64"
        if FIXTURE_BINARY.exists():
            shutil.copy2(FIXTURE_BINARY, dest)
            dest.chmod(0o755)
        else:
            dest.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return str(dest)

    async def test_validation_error_nonexistent_file(self):
        res = await verify_string_references("/nonexistent/path/to/binary")
        assert res.ok is False
        assert res.status == "error"
        assert res.error is not None
        assert res.error.code == "VALIDATION_ERROR"

    async def test_verify_real_fixture_binary(self, test_binary):
        if not FIXTURE_BINARY.exists():
            pytest.skip(f"Fixture binary not found: {FIXTURE_BINARY}")

        res = await verify_string_references(
            file_path=test_binary,
            strings=["Hello from real test binary"],
            include_context=True,
        )
        assert res.ok is True
        assert res.status == "success"
        data = res.data
        assert data["summary"]["total_evaluated"] >= 1
        assert data["summary"]["referenced"] >= 1

        matched = [
            s
            for s in data["verified_strings"]
            if "Hello from real test binary" in (s.get("string") or "")
        ]
        assert len(matched) >= 1
        record = matched[0]
        assert record["usage"] == "referenced"
        assert record["is_code_reference"] is True
        assert record["evidence_origin"] == "structural"
        assert record["classification"] == "behavior_capable"
        assert "main" in record["referencing_functions"]
        assert record["xref_count"] > 0
        assert "context" in record

    async def test_verify_unresolved_string(self, test_binary):
        if not FIXTURE_BINARY.exists():
            pytest.skip(f"Fixture binary not found: {FIXTURE_BINARY}")

        res = await verify_string_references(
            file_path=test_binary,
            strings=["NONEXISTENT_STRING_IMPOSSIBLE_VALUE_12345"],
        )
        assert res.ok is True
        data = res.data
        assert data["summary"]["unresolved"] >= 1
        record = data["verified_strings"][0]
        assert record["usage"] == "unresolved"
        assert record["address"] is None

    @patch("reversecore_mcp.tools.analysis.string_verifier.R2Session")
    async def test_mocked_unreferenced_string(self, mock_r2_cls, test_binary):
        mock_session = MagicMock()
        mock_r2_cls.return_value = mock_session
        mock_session.open.return_value = True
        mock_session.cmdj.side_effect = lambda cmd: {
            "izj": [{"vaddr": 0x402000, "string": "dead_string_here"}],
            "izzj": [],
            "axtj @ 0x402000": [],  # 0 xrefs
        }.get(cmd, [])

        res = await verify_string_references(
            file_path=test_binary,
            strings=["dead_string_here"],
        )
        assert res.ok is True
        data = res.data
        assert data["summary"]["unreferenced"] == 1
        record = data["verified_strings"][0]
        assert record["usage"] == "unreferenced"
        assert record["evidence_origin"] == "artifact"
        assert record["classification"] == "artifact_only"
        assert record["xref_count"] == 0

        # Check that artifact finding was emitted
        assert len(data["findings"]) == 1
        assert data["findings"][0]["origin"] == "artifact"

    @patch("reversecore_mcp.tools.analysis.string_verifier.R2Session")
    async def test_mocked_ambiguous_data_xref(self, mock_r2_cls, test_binary):
        mock_session = MagicMock()
        mock_r2_cls.return_value = mock_session
        mock_session.open.return_value = True
        mock_session.cmdj.side_effect = lambda cmd: {
            "izj": [{"vaddr": 0x402000, "string": "table_pointer_string"}],
            "izzj": [],
            "axtj @ 0x402000": [
                {"from": 0x403000, "type": "NULL", "fcn_name": "aav.0x403000", "opcode": "invalid"}
            ],
        }.get(cmd, [])

        res = await verify_string_references(
            file_path=test_binary,
            strings=["table_pointer_string"],
        )
        assert res.ok is True
        data = res.data
        assert data["summary"]["ambiguous"] == 1
        record = data["verified_strings"][0]
        assert record["usage"] == "ambiguous"
        assert record["is_code_reference"] is False
        assert record["evidence_origin"] == "structural"
        assert record["classification"] == "behavior_capable"
