"""Unit tests for preserving truncated tool outputs and retrieval (Issue #326)."""

from __future__ import annotations

import sys

import pytest

from reversecore_mcp.core.execution import (
    SubprocessExecutionResult,
    execute_subprocess_async,
    persist_output_artifact,
)
from reversecore_mcp.core.result import (
    ContinuationInfo,
    ToolSuccess,
    TruncationMeta,
    success,
)
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.common.file_operations import retrieve_truncated_output


@pytest.mark.unit
class TestTruncationModels:
    """Test TruncationMeta and continuation response envelopes."""

    def test_truncation_meta_creation(self):
        meta = TruncationMeta(
            truncated=True,
            returned_bytes=1000,
            total_captured_bytes=5000,
            saved_artifact="outputs/cmd_test.log",
            continuation=ContinuationInfo(offset=1000, length=1000),
        )
        assert meta.truncated is True
        assert meta.returned_bytes == 1000
        assert meta.total_captured_bytes == 5000
        assert meta.saved_artifact == "outputs/cmd_test.log"
        assert meta.continuation is not None
        assert meta.continuation.offset == 1000

    def test_success_helper_with_truncation_dict(self):
        res = success(
            "preview_data",
            truncation={
                "truncated": True,
                "returned_bytes": 100,
                "total_captured_bytes": 1000,
                "saved_artifact": "outputs/sample.log",
                "continuation": {"offset": 100},
            },
        )
        assert isinstance(res, ToolSuccess)
        assert res.truncation is not None
        assert res.truncation.truncated is True
        assert res.truncation.returned_bytes == 100
        assert res.truncation.saved_artifact == "outputs/sample.log"

    def test_subprocess_execution_result_tuple_compatibility(self):
        trunc_meta = {"truncated": True, "saved_artifact": "outputs/cmd_123.log"}
        res = SubprocessExecutionResult("hello", 5, trunc_meta)

        # Unpack as normal 2-tuple
        text, count = res
        assert text == "hello"
        assert count == 5

        # Attribute access
        assert res.output_text == "hello"
        assert res.bytes_read == 5
        assert res.truncation_meta == trunc_meta


@pytest.mark.unit
class TestArtifactPersistence:
    """Test output artifact persistence in workspace/outputs."""

    def test_persist_output_artifact(self):
        ws = get_workspace_config().workspace
        ws.mkdir(parents=True, exist_ok=True)

        payload = b"Line 1: important reverse engineering output\nLine 2: more data\n"
        cmd = ["dummy_tool", "--verbose", "sample.bin"]

        abs_path, rel_path = persist_output_artifact(cmd, payload, prefix="test")

        assert abs_path.exists()
        assert abs_path.read_bytes() == payload
        assert rel_path.startswith("outputs/test_")
        assert rel_path.endswith(".log")

        # Determinism: same cmd produces identical rel_path
        abs_path2, rel_path2 = persist_output_artifact(cmd, payload, prefix="test")
        assert abs_path == abs_path2
        assert rel_path == rel_path2


@pytest.mark.unit
@pytest.mark.asyncio
class TestSubprocessTruncationPreservation:
    """Test execute_subprocess_async truncation preservation and warning."""

    async def test_small_output_not_truncated(self):
        cmd = [sys.executable, "-c", "print('short deterministic output')"]
        res = await execute_subprocess_async(cmd, max_output_size=1000)

        assert "short deterministic output" in res.output_text
        assert res.truncation_meta is None

    async def test_large_output_truncated_and_preserved(self):
        # Generate 500 lines of output (approx 15KB) with max_output_size=500 bytes
        script = "import sys; [print(f'LINE_{i:04d}_CONTENT_DATA') for i in range(500)]"
        cmd = [sys.executable, "-c", script]

        res = await execute_subprocess_async(cmd, max_output_size=500, preserve_artifact=True)
        text, total_bytes = res

        assert total_bytes > 500
        assert "[WARNING: Output truncated at 500 bytes" in text
        assert "Full output preserved in outputs/cmd_" in text
        assert res.truncation_meta is not None
        assert res.truncation_meta["truncated"] is True
        assert res.truncation_meta["total_captured_bytes"] == total_bytes

        # Verify saved artifact file has complete content
        ws = get_workspace_config().workspace
        saved_file = ws / res.truncation_meta["saved_artifact"]
        assert saved_file.exists()
        artifact_content = saved_file.read_text(encoding="utf-8")
        assert "LINE_0000_CONTENT_DATA" in artifact_content
        assert "LINE_0499_CONTENT_DATA" in artifact_content


@pytest.mark.unit
@pytest.mark.asyncio
class TestRetrieveTruncatedOutputTool:
    """Test retrieve_truncated_output tool for retrieving output continuations."""

    async def test_retrieve_validation_error_outside_workspace(self):
        res = await retrieve_truncated_output("/etc/passwd")
        assert res.ok is False
        assert res.status == "error"
        assert res.error.code == "VALIDATION_ERROR"

    async def test_retrieve_file_not_found(self):
        res = await retrieve_truncated_output("outputs/nonexistent_12345.log")
        assert res.ok is False
        assert res.status == "error"
        assert res.error.code == "FILE_NOT_FOUND"

    async def test_retrieve_sequential_continuation(self):
        ws = get_workspace_config().workspace
        out_dir = ws / "outputs"
        out_dir.mkdir(parents=True, exist_ok=True)

        test_file = out_dir / "test_chunked_artifact.log"
        full_text = "CHUNK_A_" * 100 + "CHUNK_B_" * 100  # 1600 bytes
        test_file.write_text(full_text, encoding="utf-8")
        rel_path = "outputs/test_chunked_artifact.log"

        # 1. Retrieve first slice: 800 bytes
        res1 = await retrieve_truncated_output(rel_path, offset=0, length=800)
        assert res1.ok is True
        data1 = res1.data
        assert data1["offset"] == 0
        assert data1["returned_bytes"] == 800
        assert data1["has_more"] is True
        assert data1["next_offset"] == 800
        assert data1["content"] == full_text[:800]
        assert data1["continuation"] == {"offset": 800, "length": 800}

        # 2. Retrieve second slice (tail)
        res2 = await retrieve_truncated_output(rel_path, offset=800, length=800)
        assert res2.ok is True
        data2 = res2.data
        assert data2["offset"] == 800
        assert data2["returned_bytes"] == 800
        assert data2["has_more"] is False
        assert data2["next_offset"] is None
        assert data2["content"] == full_text[800:1600]

        # 3. Read at EOF
        res3 = await retrieve_truncated_output(rel_path, offset=1600, length=800)
        assert res3.ok is True
        data3 = res3.data
        assert data3["returned_bytes"] == 0
        assert data3["has_more"] is False
