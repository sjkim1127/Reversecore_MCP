"""Unit tests for the R2EsilSimulator class."""

from unittest.mock import MagicMock

import pytest

from reversecore_mcp.tools.radare2.r2_esil_simulator import R2EsilSimulator


@pytest.fixture
def mock_r2_session():
    """Mock R2Session for testing."""
    session = MagicMock()
    # By default, cmd returns empty string or predictable strings
    session.cmd.return_value = ""
    session.cmdj.return_value = {"rip": 0x41414141}
    return session


@pytest.mark.unit
def test_setup_esil_env(mock_r2_session):
    """Test ESIL environment initialization."""
    simulator = R2EsilSimulator(mock_r2_session)
    result = simulator.setup_esil_env()

    assert result is True
    # Verify critical commands were called
    mock_r2_session.cmd.assert_any_call("aei")
    mock_r2_session.cmd.assert_any_call("aeim")


@pytest.mark.unit
def test_hook_allocators(mock_r2_session):
    """Test setting breakpoints for allocators."""
    simulator = R2EsilSimulator(mock_r2_session)
    simulator.hook_allocators("sym.malloc", "sym.free")

    mock_r2_session.cmd.assert_any_call("db sym.malloc")
    mock_r2_session.cmd.assert_any_call("db sym.free")


@pytest.mark.unit
def test_simulate_heap_layout(mock_r2_session):
    """Test returning the layout."""
    simulator = R2EsilSimulator(mock_r2_session)
    simulator.chunks = {0x60000000: 32}
    layout = simulator.simulate_heap_layout()

    assert layout["virtual_heap_base"] == "0x60000000"
    assert "0x60000000" in layout["chunks"]
    assert layout["chunks"]["0x60000000"] == 32


@pytest.mark.unit
def test_verify_payload_crash_success(mock_r2_session):
    """Test payload injection where PC gets corrupted to 0x41414141."""
    simulator = R2EsilSimulator(mock_r2_session)

    # Configure mock to return 0x41414141 when reading registers
    mock_r2_session.cmdj.return_value = {"rip": 0x41414141}

    payload = b"AAAA"
    result = simulator.verify_payload_crash(0x60000000, payload, max_steps=5)

    assert result["crashed"] is True
    assert result["corrupted_pc"] == "0x41414141"
    # Ensure wx was called with hex of payload
    mock_r2_session.cmd.assert_any_call("wx 41414141 @ 1610612736")  # 1610612736 is 0x60000000
    mock_r2_session.cmd.assert_any_call("aes")


@pytest.mark.unit
def test_verify_payload_crash_no_crash(mock_r2_session):
    """Test payload injection where PC does NOT get corrupted."""
    simulator = R2EsilSimulator(mock_r2_session)

    # Configure mock to return valid addresses
    mock_r2_session.cmdj.return_value = {"rip": 0x400000}

    payload = b"BBBB"
    result = simulator.verify_payload_crash(0x60000000, payload, max_steps=5)

    assert result["crashed"] is False
    assert result["corrupted_pc"] == ""
    assert "0x400000" in result["pc_history"]
