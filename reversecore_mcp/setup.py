"""One-line and CLI Setup Installer for Reversecore_MCP.

Automatically detects installed AI agents & IDEs (Cursor, Claude Code, Windsurf,
Claude Desktop, Antigravity, VS Code Cline/Roo Code, etc.) and registers the
Reversecore_MCP server configuration safely with automatic backups.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

BANNER = r"""
========================================================================
   ____                                                     __  __  ____ ____
  / __ \___ _   _____  _____________  _________  ________  /  |/  // ___// __ \
 / /_/ / _ \ | / / _ \/ ___/ ___/ _ \/ ___/ __ \/ ___/ _ \/ /|_/ / / /   / /_/ /
/ _, _/  __/ |/ /  __/ /  (__  )  __/ /__/ /_/ / /  /  __/ /  / / / /___/ ____/
/_/ |_|\___/|___/\___/_/  /____/\___/\___/\____/_/   \___/_/  /_/  \____/_/
           Reversecore_MCP Client Setup & Integration Wizard
========================================================================
"""


@dataclass
class ClientDefinition:
    """Specification of an AI agent/client and how to locate its MCP config."""

    name: str
    display_name: str
    default_config_path: Path
    marker_paths: list[Path] = field(default_factory=list)
    format_type: str = "json"  # "json" or "toml"

    def is_detected(self) -> bool:
        """Check whether this client appears to be installed on the current system."""
        # 1. If config file already exists, it is detected
        if self.default_config_path.exists():
            return True
        # 2. If any of the marker paths exist, it is detected
        for marker in self.marker_paths:
            if marker.exists():
                return True
        return False


@dataclass
class ClientSetupResult:
    """Result of configuring a client."""

    client_name: str
    display_name: str
    status: str  # "configured", "unchanged", "skipped", "failed", "removed"
    config_path: Path
    backup_path: Path | None = None
    message: str = ""


def get_supported_clients(home: Path | None = None) -> list[ClientDefinition]:
    """Return the list of all supported AI agents and their default config locations.

    Args:
        home: Optional home directory override (defaults to Path.home()).
    """
    user_home = home or Path.home()
    system = platform.system()

    # Determine OS-specific config directories
    if system == "Darwin":
        claude_desktop_cfg = (
            user_home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
        claude_desktop_marker = user_home / "Library" / "Application Support" / "Claude"
        cursor_app_support = user_home / "Library" / "Application Support" / "Cursor"
        code_storage = (
            user_home / "Library" / "Application Support" / "Code" / "User" / "globalStorage"
        )
    elif system == "Windows":
        app_data = (
            user_home / "AppData" / "Roaming"
            if home is not None
            else Path(os.environ.get("APPDATA", str(user_home / "AppData" / "Roaming")))
        )
        claude_desktop_cfg = app_data / "Claude" / "claude_desktop_config.json"
        claude_desktop_marker = app_data / "Claude"
        cursor_app_support = app_data / "Cursor"
        code_storage = app_data / "Code" / "User" / "globalStorage"
    else:  # Linux / Unix
        config_home = (
            user_home / ".config"
            if home is not None
            else Path(os.environ.get("XDG_CONFIG_HOME", str(user_home / ".config")))
        )
        claude_desktop_cfg = config_home / "Claude" / "claude_desktop_config.json"
        claude_desktop_marker = config_home / "Claude"
        cursor_app_support = config_home / "Cursor"
        code_storage = config_home / "Code" / "User" / "globalStorage"

    claude_config_dir = os.environ.get("CLAUDE_CONFIG_DIR") if home is None else None
    claude_code_cfg = (
        Path(claude_config_dir) / ".claude.json"
        if claude_config_dir
        else user_home / ".claude.json"
    )
    claude_code_marker = Path(claude_config_dir) if claude_config_dir else user_home / ".claude"

    cline_dir = code_storage / "saoudrizwan.claude-dev"
    roo_dir = code_storage / "rooveterinaryinc.roo-cline"

    clients: list[ClientDefinition] = [
        ClientDefinition(
            name="cursor",
            display_name="Cursor",
            default_config_path=user_home / ".cursor" / "mcp.json",
            marker_paths=[
                user_home / ".cursor",
                cursor_app_support,
            ],
        ),
        ClientDefinition(
            name="claude_code",
            display_name="Claude Code",
            default_config_path=claude_code_cfg,
            marker_paths=[
                claude_code_marker,
                claude_code_cfg,
            ],
        ),
        ClientDefinition(
            name="windsurf",
            display_name="Windsurf",
            default_config_path=user_home / ".codeium" / "windsurf" / "mcp_config.json",
            marker_paths=[
                user_home / ".codeium" / "windsurf",
            ],
        ),
        ClientDefinition(
            name="claude_desktop",
            display_name="Claude Desktop",
            default_config_path=claude_desktop_cfg,
            marker_paths=[
                claude_desktop_marker,
                claude_desktop_cfg,
            ],
        ),
        ClientDefinition(
            name="antigravity",
            display_name="Antigravity",
            default_config_path=user_home / ".gemini" / "config" / "mcp_config.json",
            marker_paths=[
                user_home / ".gemini",
            ],
        ),
        ClientDefinition(
            name="cline",
            display_name="VS Code (Cline)",
            default_config_path=cline_dir / "settings" / "cline_mcp_settings.json",
            marker_paths=[
                cline_dir,
            ],
        ),
        ClientDefinition(
            name="roo_code",
            display_name="VS Code (Roo Code)",
            default_config_path=roo_dir / "settings" / "cline_mcp_settings.json",
            marker_paths=[
                roo_dir,
            ],
        ),
        ClientDefinition(
            name="codex",
            display_name="Codex",
            default_config_path=user_home / ".codex" / "config.toml",
            marker_paths=[
                user_home / ".codex",
            ],
            format_type="toml",
        ),
    ]

    return clients


def resolve_server_command(
    mode: str = "auto",
    custom_command: str | None = None,
    custom_args: list[str] | None = None,
    workspace_dir: Path | None = None,
    tiered: bool = False,
) -> tuple[str, list[str], dict[str, str]]:
    """Determine the command, arguments, and environment variables for reversecore.

    Args:
        mode: Resolution mode: 'auto', 'docker', 'uvx', 'pipx', or 'python'.
        custom_command: User-provided explicit command string.
        custom_args: User-provided explicit argument list.
        workspace_dir: Custom workspace directory to bind or configure.
        tiered: Whether to enable Tiered Tools / Agents Mode (REVERSECORE_PROFILE=tiered).

    Returns:
        Tuple of (command, args, env).
    """
    env_vars: dict[str, str] = {}
    if tiered:
        env_vars["REVERSECORE_PROFILE"] = "tiered"

    if custom_command is not None:
        return custom_command, custom_args or [], env_vars

    ws = str(workspace_dir or (Path.home() / "workspace"))

    if mode == "docker":
        docker_args = [
            "run",
            "-i",
            "--rm",
            "-v",
            f"{ws}:/app/workspace",
            "-e",
            "REVERSECORE_WORKSPACE=/app/workspace",
            "-e",
            "MCP_TRANSPORT=stdio",
        ]
        if tiered:
            docker_args.extend(["-e", "REVERSECORE_PROFILE=tiered"])
        docker_args.append("ghcr.io/sjkim1127/reversecore-mcp:latest")
        return (
            "docker",
            docker_args,
            {},
        )

    if mode == "uvx":
        return "uvx", ["reversecore-mcp"], env_vars

    if mode == "pipx":
        return "pipx", ["run", "reversecore-mcp"], env_vars

    if mode == "python":
        return sys.executable, ["-m", "reversecore_mcp.server"], env_vars

    # Default 'auto' mode
    # 1. Prefer 'reversecore-mcp' if already on PATH
    which_bin = shutil.which("reversecore-mcp")
    if which_bin:
        return which_bin, [], env_vars

    # 2. If running from within an environment that can import reversecore_mcp, use current python
    try:
        import reversecore_mcp  # noqa: F401

        return sys.executable, ["-m", "reversecore_mcp.server"], env_vars
    except ImportError:
        pass

    # 3. Check for uvx
    if shutil.which("uvx"):
        return "uvx", ["reversecore-mcp"], env_vars

    # 4. Check for pipx
    if shutil.which("pipx"):
        return "pipx", ["run", "reversecore-mcp"], env_vars

    # 5. Fallback to python3
    return "python3", ["-m", "reversecore_mcp.server"], env_vars


def _create_backup(target_path: Path) -> Path | None:
    """Create a timestamped backup of the configuration file if it exists."""
    if not target_path.exists():
        return None
    timestamp = int(time.time())
    backup_path = target_path.with_name(f"{target_path.name}.bak.{timestamp}")
    try:
        shutil.copy2(target_path, backup_path)
        return backup_path
    except OSError as exc:
        logger.warning(f"Failed to create backup for {target_path}: {exc}")
        return None


def _write_json_atomically(target_path: Path, data: dict[str, Any]) -> None:
    """Write dictionary to target JSON file atomically using a temporary file."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(
        dir=target_path.parent, prefix=f".{target_path.name}.", suffix=".tmp"
    )
    with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(temp_path, target_path)


def configure_client(
    client: ClientDefinition,
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    dry_run: bool = False,
    remove: bool = False,
) -> ClientSetupResult:
    """Apply or remove Reversecore_MCP registration in the given client's configuration.

    Args:
        client: Client definition specifying paths and format.
        command: MCP server executable command.
        args: MCP server command-line arguments.
        env: Optional environment variables dictionary.
        dry_run: When True, calculate actions without making filesystem modifications.
        remove: When True, delete the reversecore server entry if present.

    Returns:
        ClientSetupResult describing outcome, backup path, and status.
    """
    config_path = client.default_config_path

    if client.format_type == "toml":
        # Basic TOML handling for Codex
        return _configure_toml_client(
            client, command, args, env=env, dry_run=dry_run, remove=remove
        )

    # JSON configuration handling
    existing_data: dict[str, Any] = {}
    if config_path.exists():
        try:
            content = config_path.read_text(encoding="utf-8").strip()
            if content:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    existing_data = loaded
        except Exception as exc:
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="failed",
                config_path=config_path,
                message=f"Failed to parse existing JSON: {exc}",
            )

    mcp_servers = existing_data.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        mcp_servers = {}
        existing_data["mcpServers"] = mcp_servers

    if remove:
        if "reversecore" not in mcp_servers:
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="unchanged",
                config_path=config_path,
                message="Reversecore was not registered in this client.",
            )
        if dry_run:
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="removed",
                config_path=config_path,
                message="[Dry run] Would remove reversecore registration.",
            )
        backup_path = _create_backup(config_path)
        del mcp_servers["reversecore"]
        _write_json_atomically(config_path, existing_data)
        return ClientSetupResult(
            client_name=client.name,
            display_name=client.display_name,
            status="removed",
            config_path=config_path,
            backup_path=backup_path,
            message="Reversecore registration removed successfully.",
        )

    # Check if existing entry is already identical
    target_entry: dict[str, Any] = {
        "command": command,
        "args": args,
    }
    if env:
        target_entry["env"] = env

    current_entry = mcp_servers.get("reversecore")
    if current_entry == target_entry:
        return ClientSetupResult(
            client_name=client.name,
            display_name=client.display_name,
            status="unchanged",
            config_path=config_path,
            message="Already configured with identical settings.",
        )

    if dry_run:
        return ClientSetupResult(
            client_name=client.name,
            display_name=client.display_name,
            status="configured",
            config_path=config_path,
            message=f"[Dry run] Would write reversecore server entry ({command} {' '.join(args)}).",
        )

    backup_path = _create_backup(config_path)
    mcp_servers["reversecore"] = target_entry
    _write_json_atomically(config_path, existing_data)

    return ClientSetupResult(
        client_name=client.name,
        display_name=client.display_name,
        status="configured",
        config_path=config_path,
        backup_path=backup_path,
        message=f"Configured reversecore server ({command}).",
    )


def _configure_toml_client(
    client: ClientDefinition,
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    dry_run: bool = False,
    remove: bool = False,
) -> ClientSetupResult:
    """Configure or remove Reversecore in TOML configuration (Codex)."""
    config_path = client.default_config_path
    content = ""
    if config_path.exists():
        try:
            content = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="failed",
                config_path=config_path,
                message=f"Failed to read file: {exc}",
            )

    header = "[mcp_servers.reversecore]"
    has_entry = header in content

    if remove:
        if not has_entry:
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="unchanged",
                config_path=config_path,
                message="Reversecore was not registered.",
            )
        if dry_run:
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="removed",
                config_path=config_path,
                message="[Dry run] Would remove reversecore block from TOML.",
            )
        backup_path = _create_backup(config_path)
        # Remove block from header until next bracketed section or EOF
        lines = content.splitlines(keepends=True)
        new_lines: list[str] = []
        skipping = False
        for line in lines:
            if line.strip() == header or line.strip() == "[mcp_servers.reversecore.env]":
                skipping = True
                continue
            if skipping and line.strip().startswith("[") and line.strip().endswith("]"):
                if not line.strip().startswith("[mcp_servers.reversecore"):
                    skipping = False
            if not skipping:
                new_lines.append(line)
        config_path.write_text("".join(new_lines), encoding="utf-8")
        return ClientSetupResult(
            client_name=client.name,
            display_name=client.display_name,
            status="removed",
            config_path=config_path,
            backup_path=backup_path,
            message="Reversecore block removed from TOML.",
        )

    # Format new TOML block
    args_toml = json.dumps(args)
    env_lines = ""
    if env:
        env_lines = (
            "\n[mcp_servers.reversecore.env]\n"
            + "\n".join(f'{k} = "{v}"' for k, v in env.items())
            + "\n"
        )

    new_block = f"""
{header}
command = "{command}"
args = {args_toml}
{env_lines}"""
    if has_entry and f'command = "{command}"' in content and f"args = {args_toml}" in content:
        if not env or all(f'{k} = "{v}"' in content for k, v in env.items()):
            return ClientSetupResult(
                client_name=client.name,
                display_name=client.display_name,
                status="unchanged",
                config_path=config_path,
                message="Already configured in TOML.",
            )

    if dry_run:
        return ClientSetupResult(
            client_name=client.name,
            display_name=client.display_name,
            status="configured",
            config_path=config_path,
            message="[Dry run] Would append reversecore block to TOML.",
        )

    backup_path = _create_backup(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if has_entry:
        # Replace existing block
        lines = content.splitlines(keepends=True)
        new_lines = []
        skipping = False
        for line in lines:
            if line.strip() == header:
                skipping = True
                new_lines.append(new_block.lstrip())
                continue
            if skipping and line.strip().startswith("[") and line.strip().endswith("]"):
                skipping = False
            if not skipping:
                new_lines.append(line)
        config_path.write_text("".join(new_lines), encoding="utf-8")
    else:
        # Append block
        with config_path.open("a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write(new_block)

    return ClientSetupResult(
        client_name=client.name,
        display_name=client.display_name,
        status="configured",
        config_path=config_path,
        backup_path=backup_path,
        message="Configured reversecore in TOML.",
    )


def run_setup(
    target_clients: list[str] | None = None,
    mode: str = "auto",
    custom_command: str | None = None,
    custom_args: list[str] | None = None,
    workspace_dir: Path | None = None,
    tiered: bool = False,
    auto_approve: bool = False,
    dry_run: bool = False,
    remove: bool = False,
    list_only: bool = False,
    home_dir: Path | None = None,
) -> list[ClientSetupResult]:
    """Execute the Reversecore_MCP setup workflow.

    Args:
        target_clients: Explicit list of client names to configure (None = all detected).
        mode: Command resolution mode ('auto', 'docker', 'uvx', 'pipx', 'python').
        custom_command: Optional explicit command override.
        custom_args: Optional explicit args override.
        workspace_dir: Custom workspace directory.
        tiered: When True, configure clients with Tiered Tools / Agents Mode (REVERSECORE_PROFILE=tiered).
        auto_approve: When True, configure without interactive confirmation.
        dry_run: When True, preview actions without modifying files.
        remove: When True, unregister Reversecore from clients.
        list_only: When True, list detected clients and exit.
        home_dir: Optional home directory override for testing.

    Returns:
        List of ClientSetupResult objects.
    """
    all_clients = get_supported_clients(home=home_dir)
    detected_clients = [c for c in all_clients if c.is_detected()]

    if list_only:
        print(BANNER)
        print("Detected AI Agents and Clients:")
        for c in all_clients:
            status_str = "Detected" if c.is_detected() else "Not found"
            print(f"  • {c.display_name:24} [{status_str:9}] -> {c.default_config_path}")
        return []

    # Determine command & arguments
    command, args, env = resolve_server_command(
        mode=mode,
        custom_command=custom_command,
        custom_args=custom_args,
        workspace_dir=workspace_dir,
        tiered=tiered,
    )

    # Filter clients to configure
    selected_clients: list[ClientDefinition]
    if target_clients:
        target_set = {t.lower().replace("-", "_") for t in target_clients}
        selected_clients = [c for c in all_clients if c.name in target_set]
    else:
        # Default to detected clients (if none detected, include top 3 common ones: cursor, claude_code, windsurf)
        if detected_clients:
            selected_clients = detected_clients
        else:
            selected_clients = [
                c for c in all_clients if c.name in ("cursor", "claude_code", "windsurf")
            ]

    print(BANNER)
    print("Reversecore_MCP Client Setup Plan")
    print(f"  Target Command: {command} {' '.join(args)}".strip())
    print(f"  Action:         {'Remove registration' if remove else 'Register MCP server'}")
    print(f"  Dry Run:        {'Yes' if dry_run else 'No'}\n")

    print("Detected Clients:")
    for c in all_clients:
        marker = "✓" if c.is_detected() else " "
        selected_mark = "▶" if c in selected_clients else " "
        print(f"  [{marker}] {selected_mark} {c.display_name:24} -> {c.default_config_path}")
    print()

    # Interactive confirmation if TTY and not auto_approve and not dry_run
    if not auto_approve and not dry_run and sys.stdin.isatty():
        prompt = (
            f"Apply changes to {len(selected_clients)} client(s)? [Y/n]: "
            if not remove
            else f"Remove Reversecore from {len(selected_clients)} client(s)? [y/N]: "
        )
        try:
            choice = input(prompt).strip().lower()
            if remove and choice != "y":
                print("Aborted.")
                return []
            if not remove and choice in ("n", "no"):
                print("Aborted.")
                return []
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return []

    results: list[ClientSetupResult] = []
    print("Applying configuration:")
    for client in selected_clients:
        res = configure_client(
            client=client,
            command=command,
            args=args,
            env=env,
            dry_run=dry_run,
            remove=remove,
        )
        results.append(res)
        status_icon = {
            "configured": "✓",
            "unchanged": "•",
            "removed": "✗",
            "failed": "!",
            "skipped": "-",
        }.get(res.status, "?")
        print(f"  [{status_icon}] {res.display_name:22} : {res.status.upper()} ({res.message})")

    print("\nSummary:")
    configured_count = sum(1 for r in results if r.status in ("configured", "removed"))
    unchanged_count = sum(1 for r in results if r.status == "unchanged")
    failed_count = sum(1 for r in results if r.status == "failed")
    print(f"  Updated: {configured_count}, Unchanged: {unchanged_count}, Failed: {failed_count}")
    if configured_count > 0 and not remove and not dry_run:
        print(
            "\n✨ Setup complete! Restart Cursor, Claude Code, or Windsurf to activate Reversecore_MCP."
        )

    return results


def build_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser for reversecore-mcp setup."""
    parser = argparse.ArgumentParser(
        prog="reversecore-mcp setup",
        description="One-line setup installer to register Reversecore_MCP with Cursor, Claude Code, Windsurf, etc.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Configure all detected clients automatically without prompting.",
    )
    parser.add_argument(
        "--clients",
        type=str,
        help="Comma-separated client names to configure (e.g. 'cursor,claude_code,windsurf').",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "docker", "uvx", "pipx", "python"],
        default="auto",
        help="Execution mode for Reversecore_MCP (default: auto).",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Shorthand for --mode docker (runs server in Docker container).",
    )
    parser.add_argument(
        "--uvx",
        action="store_true",
        help="Shorthand for --mode uvx (runs server via uvx tool).",
    )
    parser.add_argument(
        "--pipx",
        action="store_true",
        help="Shorthand for --mode pipx (runs server via pipx tool).",
    )
    parser.add_argument(
        "--tiered",
        action="store_true",
        help="Enable Tiered Tools / Agents Mode (15 essential tools, >90% lower LLM context tokens).",
    )
    parser.add_argument(
        "--command",
        type=str,
        help="Explicit custom executable command for the MCP server.",
    )
    parser.add_argument(
        "--args",
        nargs="*",
        help="Explicit custom arguments for the MCP server command.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show proposed configuration changes without writing to disk.",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Unregister Reversecore_MCP from target clients.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List detected AI clients and their configuration paths.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for reversecore-mcp setup."""
    args_list = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    parsed = parser.parse_args(args_list)

    mode = parsed.mode
    if parsed.docker:
        mode = "docker"
    elif parsed.uvx:
        mode = "uvx"
    elif parsed.pipx:
        mode = "pipx"

    target_clients = None
    if parsed.clients:
        target_clients = [c.strip() for c in parsed.clients.split(",") if c.strip()]

    results = run_setup(
        target_clients=target_clients,
        mode=mode,
        custom_command=parsed.command,
        custom_args=parsed.args,
        tiered=parsed.tiered,
        auto_approve=parsed.all,
        dry_run=parsed.dry_run,
        remove=parsed.remove,
        list_only=parsed.list,
    )

    # Return non-zero if any client failed
    if any(r.status == "failed" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
