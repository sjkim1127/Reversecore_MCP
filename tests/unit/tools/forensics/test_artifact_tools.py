"""Unit tests for artifact correlation and reporting pipeline (artifact.py).

Tests cover happy path workflows for artifact collection, IoC correlation,
YARA rule generation, timeline construction, and report export.
Also covers edge cases: empty input, insufficient patterns, no flagged IoCs.
"""

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.forensics.artifact import (
    ARTIFACT_TYPES,
    artifact_collect,
    artifact_correlate_ioc,
    artifact_generate_yara,
    artifact_report,
    artifact_timeline,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def sample_string_artifacts():
    """Sample string artifacts from memory analysis."""
    return [
        {"value": "cmd.exe /c whoami", "source": "memory_malfind", "type": "string"},
        {"value": "powershell -exec bypass", "source": "memory_malfind", "type": "string"},
        {"value": "C:\\Windows\\Temp\\evil.exe", "source": "memory_malfind", "type": "string"},
    ]


@pytest.fixture()
def sample_network_artifacts():
    """Sample network artifacts from PCAP analysis."""
    return [
        {"value": "192.168.1.100", "source": "pcap_extract_c2", "type": "ip"},
        {"value": "185.199.1.1", "source": "pcap_extract_c2", "type": "ip"},
        {"value": "evil-c2.example.com", "source": "pcap_extract_dns", "type": "dns_query"},
    ]


@pytest.fixture()
def normalized_artifacts():
    """Pre-normalized artifacts with ioc_tags and collected_at."""
    return [
        {
            "type": "string",
            "value": "cmd.exe /c whoami",
            "source": "memory_malfind",
            "metadata": {},
            "collected_at": "2024-01-01T00:00:00Z",
            "flagged": True,
            "ioc_tags": ["IP_IOC"],
        },
        {
            "type": "ip",
            "value": "192.168.1.100",
            "source": "pcap_extract_c2",
            "metadata": {},
            "collected_at": "2024-01-01T00:01:00Z",
            "flagged": False,
            "ioc_tags": [],
        },
        {
            "type": "beacon",
            "value": "185.199.1.1:4444",
            "source": "pcap_extract_c2",
            "metadata": {},
            "collected_at": "2024-01-01T00:02:00Z",
            "flagged": True,
            "ioc_tags": ["IP_IOC"],
        },
    ]


# ── artifact_collect ───────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_collect_success(sample_string_artifacts):
    """Happy path: artifacts normalized and returned."""
    result = await artifact_collect(
        artifacts=sample_string_artifacts,
        artifact_type="string",
        source="memory_malfind",
    )

    assert result.status == "success"
    assert result.data["artifact_count"] == 3
    assert result.data["artifact_type"] == "string"
    assert all("collected_at" in a for a in result.data["artifacts"])


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_collect_empty_input():
    """Edge case: no artifacts provided."""
    result = await artifact_collect(artifacts=[], artifact_type="string")
    assert result.status == "error"
    assert result.error_code == "EMPTY_INPUT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_collect_invalid_type(sample_string_artifacts):
    """Edge case: invalid artifact type."""
    result = await artifact_collect(
        artifacts=sample_string_artifacts,
        artifact_type="invalid_type_xyz",
    )
    assert result.status == "error"
    assert result.error_code == "INVALID_TYPE"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_collect_all_types():
    """Happy path: all valid artifact types are accepted."""
    for atype in ARTIFACT_TYPES:
        result = await artifact_collect(
            artifacts=[{"value": "test"}],
            artifact_type=atype,
            source="test",
        )
        assert result.status == "success", f"Failed for type: {atype}"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_collect_non_dict_skipped():
    """Edge case: non-dict items in artifact list are silently skipped."""
    result = await artifact_collect(
        artifacts=[{"value": "valid"}, "not_a_dict", 42, None],  # type: ignore
        artifact_type="string",
        source="test",
    )
    assert result.status == "success"
    assert result.data["artifact_count"] == 1  # only the valid dict


# ── artifact_correlate_ioc ─────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_correlate_ioc_success(normalized_artifacts):
    """Happy path: IoC extraction runs and enriches artifacts."""
    mock_ioc_result = MagicMock()
    mock_ioc_result.status = "success"
    mock_ioc_result.data = {
        "ips": ["192.168.1.100", "185.199.1.1"],
        "urls": [],
        "md5_hashes": [],
        "sha1_hashes": [],
        "sha256_hashes": [],
    }

    with patch(
        "reversecore_mcp.tools.forensics.artifact.extract_iocs",
        return_value=mock_ioc_result,
    ):
        result = await artifact_correlate_ioc(normalized_artifacts)

    assert result.status == "success"
    assert result.data["total_artifacts"] == 3
    assert "enriched_artifacts" in result.data
    assert "extracted_iocs" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_correlate_ioc_empty():
    """Edge case: no artifacts to correlate."""
    result = await artifact_correlate_ioc([])
    assert result.status == "error"
    assert result.error_code == "EMPTY_INPUT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_correlate_ioc_no_flags(normalized_artifacts):
    """Happy path: IoC extraction finds nothing — risk is LOW."""
    mock_ioc_result = MagicMock()
    mock_ioc_result.status = "success"
    mock_ioc_result.data = {
        "ips": [],
        "urls": [],
        "md5_hashes": [],
        "sha1_hashes": [],
        "sha256_hashes": [],
    }

    with patch(
        "reversecore_mcp.tools.forensics.artifact.extract_iocs",
        return_value=mock_ioc_result,
    ):
        result = await artifact_correlate_ioc(normalized_artifacts)

    assert result.status == "success"
    assert result.data["risk_level"] == "LOW"
    assert result.data["flagged_count"] == 0


# ── artifact_generate_yara ─────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_generate_yara_success(normalized_artifacts):
    """Happy path: YARA rule generated from string artifacts."""
    artifacts_with_strings = normalized_artifacts + [
        {
            "type": "string",
            "value": "CreateRemoteThread",
            "source": "test",
            "metadata": {},
            "collected_at": "2024-01-01T00:00:00Z",
            "flagged": False,
            "ioc_tags": [],
        }
    ]

    result = await artifact_generate_yara(artifacts_with_strings, rule_name="test_rule")

    assert result.status == "success"
    assert "yara_rule" in result.data
    assert "rule test_rule" in result.data["yara_rule"]
    assert result.data["pattern_count"] >= 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_generate_yara_saves_file(
    normalized_artifacts, workspace_dir, patched_workspace_config
):
    """Happy path: YARA rule saved to output file."""
    artifacts_with_strings = normalized_artifacts + [
        {
            "type": "string",
            "value": "LoadLibraryA",
            "source": "test",
            "metadata": {},
            "collected_at": "2024-01-01T00:00:00Z",
            "flagged": False,
            "ioc_tags": [],
        }
    ]
    output = str(workspace_dir / "rules" / "test.yar")

    result = await artifact_generate_yara(artifacts_with_strings, output_path=output)

    assert result.status == "success"
    assert result.data["saved_path"] == output
    from pathlib import Path

    assert Path(output).exists()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_generate_yara_empty():
    """Edge case: empty artifacts list."""
    result = await artifact_generate_yara([])
    assert result.status == "error"
    assert result.error_code == "EMPTY_INPUT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_generate_yara_insufficient_patterns():
    """Edge case: only hash/process artifacts — no string patterns for YARA."""
    artifacts = [
        {
            "type": "hash",
            "value": "a" * 32,
            "source": "test",
            "metadata": {},
            "collected_at": "2024-01-01T00:00:00Z",
            "flagged": False,
            "ioc_tags": [],
        }
    ]
    result = await artifact_generate_yara(artifacts)
    assert result.status == "error"
    assert result.error_code == "INSUFFICIENT_ARTIFACTS"


# ── artifact_timeline ──────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_timeline_asc(normalized_artifacts):
    """Happy path: timeline sorted ascending."""
    result = await artifact_timeline(normalized_artifacts, sort_order="asc")

    assert result.status == "success"
    assert result.data["total_events"] == 3
    assert result.data["sort_order"] == "asc"
    # Verify ascending order by timestamp
    times = [e["timestamp"] for e in result.data["timeline"]]
    assert times == sorted(times)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_timeline_desc(normalized_artifacts):
    """Happy path: timeline sorted descending."""
    result = await artifact_timeline(normalized_artifacts, sort_order="desc")

    assert result.status == "success"
    assert result.data["sort_order"] == "desc"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_timeline_empty():
    """Edge case: empty artifacts list."""
    result = await artifact_timeline([])
    assert result.status == "error"
    assert result.error_code == "EMPTY_INPUT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_timeline_invalid_order(normalized_artifacts):
    """Edge case: invalid sort_order value."""
    result = await artifact_timeline(normalized_artifacts, sort_order="random")
    assert result.status == "error"
    assert result.error_code == "INVALID_PARAM"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_timeline_pivot_points(normalized_artifacts):
    """Happy path: pivot points identified for flagged events."""
    result = await artifact_timeline(normalized_artifacts)

    assert result.status == "success"
    # normalized_artifacts has 2 flagged events
    assert "pivot_points" in result.data
    assert "first_ioc" in result.data["pivot_points"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_timeline_no_timestamps():
    """Edge case: artifacts without timestamp fields placed at end."""
    artifacts = [
        {
            "type": "string",
            "value": "test",
            "source": "manual",
            "metadata": {},
            "flagged": False,
            "ioc_tags": [],
        },
        {
            "type": "ip",
            "value": "1.2.3.4",
            "source": "manual",
            "metadata": {},
            "flagged": False,
            "ioc_tags": [],
        },
    ]
    result = await artifact_timeline(artifacts)
    assert result.status == "success"
    # No timestamps — all should be "unknown"
    for event in result.data["timeline"]:
        assert event["timestamp"] == "unknown"


# ── artifact_report ────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_report_success(normalized_artifacts):
    """Happy path: report generated with summary and Markdown content."""
    result = await artifact_report(
        artifacts=normalized_artifacts,
        case_name="test_case",
        analyst="Test Analyst",
        include_yara=False,
    )

    assert result.status == "success"
    assert "report_markdown" in result.data
    assert "# Forensics Investigation Report" in result.data["report_markdown"]
    assert "test_case" in result.data["report_markdown"]
    assert result.data["summary"]["total_artifacts"] == 3


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_report_saves_file(
    normalized_artifacts, workspace_dir, patched_workspace_config
):
    """Happy path: report saved to output file."""
    output = str(workspace_dir / "reports" / "case.md")

    result = await artifact_report(
        artifacts=normalized_artifacts,
        case_name="saved_case",
        output_path=output,
        include_yara=False,
    )

    assert result.status == "success"
    from pathlib import Path

    assert Path(output).exists()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_report_empty():
    """Edge case: empty artifacts list."""
    result = await artifact_report(artifacts=[])
    assert result.status == "error"
    assert result.error_code == "EMPTY_INPUT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_artifact_report_severity_levels():
    """Happy path: severity computed correctly based on flagged count."""

    def _make_flagged(n):
        return [
            {
                "type": "string",
                "value": f"evil_{i}",
                "source": "test",
                "metadata": {},
                "collected_at": "2024-01-01T00:00:00Z",
                "flagged": True,
                "ioc_tags": ["IP_IOC"],
            }
            for i in range(n)
        ]

    for count, expected_severity in [(0, "LOW"), (2, "MEDIUM"), (5, "HIGH"), (15, "CRITICAL")]:
        all_artifacts = _make_flagged(count)
        if count == 0:
            # Add one unflagged to avoid empty list error
            all_artifacts.append(
                {
                    "type": "string",
                    "value": "clean",
                    "source": "test",
                    "metadata": {},
                    "collected_at": "2024-01-01T00:00:00Z",
                    "flagged": False,
                    "ioc_tags": [],
                }
            )

        result = await artifact_report(all_artifacts, include_yara=False)
        assert result.status == "success", f"Failed for count={count}"
        assert result.data["summary"]["severity"] == expected_severity, (
            f"Wrong severity for count={count}"
        )
