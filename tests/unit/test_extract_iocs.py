import pytest
import json
from reversecore_mcp.tools.lib_tools import extract_iocs

def test_extract_iocs_basic():
    text = "Here is an IP 192.168.1.1 and an email test@example.com and a url https://example.com"
    result = extract_iocs(text)
    assert result.status == "success"
    data_dict = result.data
    
    assert "192.168.1.1" in data_dict["ipv4"]
    assert "test@example.com" in data_dict["emails"]
    assert "https://example.com" in data_dict["urls"]

def test_extract_iocs_empty():
    result = extract_iocs("nothing here")
    assert result.status == "success"
    data_dict = result.data
    assert not data_dict.get("ipv4")
    assert not data_dict.get("emails")
    assert not data_dict.get("urls")

def test_extract_iocs_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("10.0.0.1", encoding="utf-8")
    result = extract_iocs(str(f))
    assert result.status == "success"
    data_dict = result.data
    assert "10.0.0.1" in data_dict["ipv4"]

def test_extract_iocs_options():
    text = "192.168.1.1 test@example.com"
    result = extract_iocs(text, extract_ips=False)
    assert result.status == "success"
    data_dict = result.data
    assert "ipv4" not in data_dict or not data_dict["ipv4"]
    assert "test@example.com" in data_dict["emails"]
