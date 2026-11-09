"""Unit tests for reversecore_mcp.setup (One-line installer and client configuration engine)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from reversecore_mcp import setup
from reversecore_mcp.setup import (
    ClientDefinition,
    configure_client,
    get_supported_clients,
    resolve_server_command,
    run_setup,
)
from reversecore_mcp.setup import (
    main as setup_main,
)


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    """Create a temporary fake user home directory."""
    home = tmp_path / "fake_home"
    home.mkdir(parents=True, exist_ok=True)
    return home


def test_client_definition_is_detected(fake_home: Path):
    """Test detection logic for client definition."""
    cfg = fake_home / ".cursor" / "mcp.json"
    marker = fake_home / ".cursor"

    client = ClientDefinition(
        name="cursor",
        display_name="Cursor",
        default_config_path=cfg,
        marker_paths=[marker],
    )

    assert not client.is_detected()

    # Detected via marker directory
    marker.mkdir(parents=True, exist_ok=True)
    assert client.is_detected()

    # Detected via config file
    marker.rmdir()
    assert not client.is_detected()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("{}", encoding="utf-8")
    assert client.is_detected()


def test_get_supported_clients(fake_home: Path):
    """Test supported client retrieval with home path override."""
    clients = get_supported_clients(home=fake_home)
    names = [c.name for c in clients]

    assert "cursor" in names
    assert "claude_code" in names
    assert "windsurf" in names
    assert "claude_desktop" in names
    assert "antigravity" in names
    assert "cline" in names
    assert "roo_code" in names
    assert "codex" in names

    # All config paths should be rooted inside fake_home
    for c in clients:
        assert str(fake_home) in str(c.default_config_path)


def test_resolve_server_command(fake_home: Path):
    """Test command resolution modes."""
    # 1. Custom command & args
    cmd, args, env = resolve_server_command(
        custom_command="my-custom-server",
        custom_args=["--foo", "bar"],
    )
    assert cmd == "my-custom-server"
    assert args == ["--foo", "bar"]
    assert env == {}

    # 2. Docker mode
    cmd, args, env = resolve_server_command(
        mode="docker",
        workspace_dir=fake_home / "ws",
    )
    assert cmd == "docker"
    assert "run" in args
    assert "ghcr.io/sjkim1127/reversecore-mcp:latest" in args
    assert f"{fake_home / 'ws'}:/app/workspace" in args

    # 3. uvx mode
    cmd, args, _ = resolve_server_command(mode="uvx")
    assert cmd == "uvx"
    assert args == ["reversecore-mcp"]

    # 4. pipx mode
    cmd, args, _ = resolve_server_command(mode="pipx")
    assert cmd == "pipx"
    assert args == ["run", "reversecore-mcp"]

    # 5. python mode
    cmd, args, _ = resolve_server_command(mode="python")
    assert cmd == sys.executable
    assert args == ["-m", "reversecore_mcp.server"]

    # 6. auto mode fallback
    cmd, args, _ = resolve_server_command(mode="auto")
    assert isinstance(cmd, str)
    assert isinstance(args, list)

    # 7. Tiered mode env resolution
    _, _, env_tiered = resolve_server_command(tiered=True)
    assert env_tiered.get("REVERSECORE_PROFILE") == "tiered"

    # 8. Tiered mode in Docker
    _, docker_tiered_args, _ = resolve_server_command(mode="docker", tiered=True)
    assert "REVERSECORE_PROFILE=tiered" in docker_tiered_args


def test_configure_client_new_json_file(fake_home: Path):
    """Test writing a new JSON configuration file atomically."""
    cfg = fake_home / ".cursor" / "mcp.json"
    client = ClientDefinition(
        name="cursor",
        display_name="Cursor",
        default_config_path=cfg,
    )

    res = configure_client(
        client=client,
        command="reversecore-mcp",
        args=["--flag"],
        dry_run=False,
    )

    assert res.status == "configured"
    assert res.backup_path is None
    assert cfg.exists()

    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert "mcpServers" in data
    assert "reversecore" in data["mcpServers"]
    assert data["mcpServers"]["reversecore"]["command"] == "reversecore-mcp"
    assert data["mcpServers"]["reversecore"]["args"] == ["--flag"]


def test_configure_client_preserves_existing_servers_and_creates_backup(
    fake_home: Path,
):
    """Test that existing MCP servers are preserved and backup is made."""
    cfg = fake_home / ".claude.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    initial_content = {
        "otherKey": 123,
        "mcpServers": {
            "sqlite_server": {
                "command": "uvx",
                "args": ["mcp-server-sqlite"],
            }
        },
    }
    cfg.write_text(json.dumps(initial_content), encoding="utf-8")

    client = ClientDefinition(
        name="claude_code",
        display_name="Claude Code",
        default_config_path=cfg,
    )

    res = configure_client(
        client=client,
        command="/usr/local/bin/reversecore-mcp",
        args=[],
        env={"CUSTOM_ENV": "1"},
        dry_run=False,
    )

    assert res.status == "configured"
    assert res.backup_path is not None
    assert res.backup_path.exists()
    assert ".bak." in res.backup_path.name

    updated_data = json.loads(cfg.read_text(encoding="utf-8"))
    assert updated_data["otherKey"] == 123
    assert "sqlite_server" in updated_data["mcpServers"]
    assert "reversecore" in updated_data["mcpServers"]
    assert updated_data["mcpServers"]["reversecore"]["env"] == {"CUSTOM_ENV": "1"}


def test_configure_client_idempotent(fake_home: Path):
    """Test that re-running with identical config returns unchanged."""
    cfg = fake_home / "mcp.json"
    client = ClientDefinition(name="test", display_name="Test", default_config_path=cfg)

    # First run: configured
    res1 = configure_client(client, "test-cmd", ["arg1"])
    assert res1.status == "configured"

    # Second run: unchanged
    res2 = configure_client(client, "test-cmd", ["arg1"])
    assert res2.status == "unchanged"
    assert res2.backup_path is None


def test_configure_client_dry_run(fake_home: Path):
    """Test that dry-run performs no filesystem modifications."""
    cfg = fake_home / "mcp.json"
    client = ClientDefinition(name="test", display_name="Test", default_config_path=cfg)

    res = configure_client(client, "test-cmd", ["arg1"], dry_run=True)
    assert res.status == "configured"
    assert not cfg.exists()


def test_configure_client_remove(fake_home: Path):
    """Test unregistering reversecore server from client config."""
    cfg = fake_home / "mcp.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "reversecore": {"command": "rev"},
                    "other": {"command": "other"},
                }
            }
        ),
        encoding="utf-8",
    )
    client = ClientDefinition(name="test", display_name="Test", default_config_path=cfg)

    # Dry-run remove
    res_dry = configure_client(client, "rev", [], dry_run=True, remove=True)
    assert res_dry.status == "removed"
    # Ensure not actually deleted yet
    assert "reversecore" in json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]

    # Actual remove
    res = configure_client(client, "rev", [], dry_run=False, remove=True)
    assert res.status == "removed"
    assert res.backup_path is not None
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert "reversecore" not in data["mcpServers"]
    assert "other" in data["mcpServers"]

    # Second remove: unchanged
    res_again = configure_client(client, "rev", [], dry_run=False, remove=True)
    assert res_again.status == "unchanged"


def test_configure_toml_client(fake_home: Path):
    """Test TOML configuration for Codex."""
    cfg = fake_home / ".codex" / "config.toml"
    client = ClientDefinition(
        name="codex",
        display_name="Codex",
        default_config_path=cfg,
        format_type="toml",
    )

    # Dry-run
    res_dry = configure_client(client, "reversecore-mcp", ["--run"], dry_run=True)
    assert res_dry.status == "configured"
    assert not cfg.exists()

    # Actual add
    res = configure_client(client, "reversecore-mcp", ["--run"])
    assert res.status == "configured"
    assert cfg.exists()
    content = cfg.read_text(encoding="utf-8")
    assert "[mcp_servers.reversecore]" in content
    assert 'command = "reversecore-mcp"' in content

    # Idempotent
    res_same = configure_client(client, "reversecore-mcp", ["--run"])
    assert res_same.status == "unchanged"

    # Remove
    res_del = configure_client(client, "reversecore-mcp", ["--run"], remove=True)
    assert res_del.status == "removed"
    assert "[mcp_servers.reversecore]" not in cfg.read_text(encoding="utf-8")


def test_configure_client_corrupt_json(fake_home: Path):
    """Test handling of invalid existing JSON."""
    cfg = fake_home / "mcp.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("{ corrupt json: [", encoding="utf-8")
    client = ClientDefinition(name="test", display_name="Test", default_config_path=cfg)

    res = configure_client(client, "cmd", [])
    assert res.status == "failed"
    assert "Failed to parse existing JSON" in res.message


def test_run_setup_workflow(fake_home: Path):
    """Test the end-to-end run_setup workflow with detected and specified clients."""
    # Create marker for cursor
    cursor_dir = fake_home / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)

    results = run_setup(
        home_dir=fake_home,
        auto_approve=True,
        mode="uvx",
    )

    assert len(results) >= 1
    cursor_res = next(r for r in results if r.client_name == "cursor")
    assert cursor_res.status == "configured"

    # Run again -> should be unchanged
    results2 = run_setup(
        home_dir=fake_home,
        auto_approve=True,
        mode="uvx",
    )
    cursor_res2 = next(r for r in results2 if r.client_name == "cursor")
    assert cursor_res2.status == "unchanged"


def test_run_setup_list_only(fake_home: Path, capsys):
    """Test list_only mode of run_setup."""
    results = run_setup(home_dir=fake_home, list_only=True)
    assert results == []
    captured = capsys.readouterr()
    assert "Detected AI Agents and Clients:" in captured.out
    assert "Cursor" in captured.out
    assert "Claude Code" in captured.out


def test_setup_main_cli(fake_home: Path, monkeypatch):
    """Test setup CLI entrypoint parsing."""
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    # 1. --list
    exit_code = setup_main(["--list"])
    assert exit_code == 0

    # 2. --dry-run --clients cursor --docker
    exit_code = setup_main(["--dry-run", "--clients", "cursor", "--docker"])
    assert exit_code == 0

    # 3. --dry-run --uvx --all
    exit_code = setup_main(["--dry-run", "--uvx", "--all"])
    assert exit_code == 0

    # 4. --dry-run --pipx
    exit_code = setup_main(["--dry-run", "--pipx"])
    assert exit_code == 0

    # 5. --dry-run --tiered
    exit_code = setup_main(["--dry-run", "--tiered"])
    assert exit_code == 0


def test_server_main_delegates_to_setup(monkeypatch):
    """Test that reversecore_mcp.server.main routes to setup when 'setup' is passed in sys.argv."""
    called = {"setup_main": False, "args": []}

    def fake_setup_main(argv):
        called["setup_main"] = True
        called["args"] = argv
        return 0

    monkeypatch.setattr(setup, "main", fake_setup_main)
    monkeypatch.setattr(sys, "argv", ["reversecore-mcp", "setup", "--dry-run", "--all"])

    from reversecore_mcp import server

    with pytest.raises(SystemExit) as exc_info:
        server.main()

    assert exc_info.value.code == 0
    assert called["setup_main"] is True
    assert called["args"] == ["--dry-run", "--all"]
