import pytest
import yaml

from reversecore_mcp.tools.report.sigma_generator import (
    _generate_sigma_yaml,
    generate_sigma_rule,
)


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

    parsed = yaml.safe_load(yaml_out)
    assert parsed["title"] == "Test Sigma"
    assert parsed["status"] == "experimental"
    assert parsed["logsource"] == {"category": "process_creation", "product": "windows"}
    assert parsed["detection"]["selection"]["Image|endswith"] == [
        "\\test.exe",
        "\\malware.exe",
    ]
    assert parsed["detection"]["condition"] == "selection"
    assert parsed["level"] == "high"


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
        "2001:db8::1",
        "bad.com",
        "namespace::symbol",
        "g" * 64,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]
    result = await generate_sigma_rule(title="IOC Rule", iocs=iocs)

    assert result.status == "success"
    content = result.data
    assert content["rule_title"] == "IOC Rule"
    assert "format" in content

    parsed = yaml.safe_load(content["sigma_yaml"])
    selection = parsed["detection"]["selection_iocs"]
    assert selection["DestinationIp"] == ["192.168.1.1", "2001:db8::1"]
    assert selection["Hashes"] == [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
    assert selection["CommandLine|contains"] == ["bad.com", "namespace::symbol", "g" * 64]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_sigma_rule_apis_only():
    apis = ["VirtualAllocEx", "CreateRemoteThread"]
    result = await generate_sigma_rule(title="API Rule", api_calls=apis)

    assert result.status == "success"
    content = result.data
    parsed = yaml.safe_load(content["sigma_yaml"])
    assert parsed["detection"]["selection_apis"]["CallTrace|contains"] == [
        "VirtualAllocEx",
        "CreateRemoteThread",
    ]
    assert parsed["detection"]["condition"] == "selection_apis"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_user_values_round_trip_as_yaml_scalars_without_structure_injection():
    title = 'rule"\nlevel: critical\nattacker_key: injected\n#'
    description = 'quote " slash \\ colon: 한국어 🚀\nattacker: yes\u0085\u2028'
    description += "".join(
        chr(codepoint) for codepoint in (0x0080, 0x0084, 0x0086, 0x009F, 0xFFFE, 0xFFFF)
    )
    ioc = 'example.test"\n  - injected\ncondition: selection_apis\n#'
    api_call = 'CreateRemoteThread"\nselection_attack:\n  Image: injected\n#'
    category = 'process_creation"\n  attacker: injected'
    product = 'windows: # "\\\n  definition: injected'

    result = await generate_sigma_rule(
        title=title,
        description=description,
        iocs=[ioc],
        api_calls=[api_call],
        category=category,
        product=product,
    )

    assert result.status == "success"
    parsed = yaml.safe_load(result.data["sigma_yaml"])
    assert set(parsed) == {
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "logsource",
        "detection",
        "level",
    }
    assert parsed["title"] == title
    assert parsed["description"] == description
    assert parsed["logsource"] == {"category": category, "product": product}
    assert parsed["detection"] == {
        "selection_iocs": {"CommandLine|contains": [ioc]},
        "selection_apis": {"CallTrace|contains": [api_call]},
        "condition": "selection_iocs or selection_apis",
    }
    assert parsed["level"] == "medium"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_sigma_rule_rejects_malformed_ip_and_non_string_indicators():
    malformed_ip = await generate_sigma_rule(title="Invalid IP", iocs=["999.1.1.1"])
    non_string_ioc = await generate_sigma_rule(title="Invalid IOC", iocs=[123])  # type: ignore[list-item]
    non_list_api_calls = await generate_sigma_rule(
        title="Invalid API list",
        api_calls="CreateRemoteThread",  # type: ignore[arg-type]
    )

    assert malformed_ip.status == "error"
    assert malformed_ip.error_code == "VALIDATION_ERROR"
    assert non_string_ioc.status == "error"
    assert non_string_ioc.error_code == "VALIDATION_ERROR"
    assert non_list_api_calls.status == "error"
    assert non_list_api_calls.error_code == "VALIDATION_ERROR"


@pytest.mark.unit
def test_sigma_formatter_rejects_unsafe_logsource_keys_and_conditions():
    base = {
        "title": "Test Sigma",
        "description": "A test rule",
        "detection": {"selection": {"Image|endswith": ["\\test.exe"]}},
        "level": "high",
    }

    with pytest.raises(ValueError, match="unsupported key"):
        _generate_sigma_yaml(
            **base,
            logsource={
                "category": "process_creation",
                "product": "windows",
                "attacker\nkey": "injected",
            },
            condition="selection",
        )

    with pytest.raises(ValueError, match="Condition"):
        _generate_sigma_yaml(
            **base,
            logsource={"category": "process_creation", "product": "windows"},
            condition="selection\nlevel: critical",
        )

    with pytest.raises(ValueError, match="Logsource keys and values"):
        _generate_sigma_yaml(
            **base,
            logsource={"category": None, "product": "windows"},  # type: ignore[dict-item]
            condition="selection",
        )

    with pytest.raises(ValueError, match="Level"):
        _generate_sigma_yaml(
            **{**base, "level": []},  # type: ignore[dict-item]
            logsource={"category": "process_creation", "product": "windows"},
            condition="selection",
        )

    with pytest.raises(ValueError, match="selection names"):
        _generate_sigma_yaml(
            **{
                **base,
                "detection": {"selection\nlevel: critical": {"Image": ["test.exe"]}},
            },
            logsource={"category": "process_creation", "product": "windows"},
            condition="selection",
        )
