import pytest

from reversecore_mcp.tools.report.sigma_generator import _generate_sigma_yaml, generate_sigma_rule


@pytest.mark.unit
def test_generate_sigma_yaml():
    yaml_out = _generate_sigma_yaml(
        title="Test Sigma",
        description="A test rule",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image|endswith": ["\\test.exe", "\\malware.exe"]}},
        condition="selection",
        level="high",
    )

    assert 'title: "Test Sigma"' in yaml_out
    assert "status: experimental" in yaml_out
    assert "category: process_creation" in yaml_out
    assert "Image|endswith:" in yaml_out
    assert '- "\\test.exe"' in yaml_out
    assert "condition: selection" in yaml_out
    assert "level: high" in yaml_out


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_sigma_rule_validation():
    # Neither iocs nor api_calls provided
    result = await generate_sigma_rule(title="Invalid")
    assert result.status == "error"
    assert result.error_code == "VALIDATION_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_sigma_rule_iocs_only():
    iocs = [
        "192.168.1.1",
        "bad.com",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]
    result = await generate_sigma_rule(title="IOC Rule", iocs=iocs)

    assert result.status == "success"
    content = result.data
    assert content["rule_title"] == "IOC Rule"
    assert "format" in content

    yaml_str = content["sigma_yaml"]
    assert "DestinationIp:" in yaml_str
    assert "192.168.1.1" in yaml_str
    assert "Hashes:" in yaml_str
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in yaml_str
    assert "CommandLine|contains:" in yaml_str
    assert "bad.com" in yaml_str


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_sigma_rule_apis_only():
    apis = ["VirtualAllocEx", "CreateRemoteThread"]
    result = await generate_sigma_rule(title="API Rule", api_calls=apis)

    assert result.status == "success"
    content = result.data
    yaml_str = content["sigma_yaml"]
    assert "CallTrace|contains:" in yaml_str
    assert "VirtualAllocEx" in yaml_str
    assert "CreateRemoteThread" in yaml_str
    assert "condition: selection_apis" in yaml_str
