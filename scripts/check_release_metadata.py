#!/usr/bin/env python3
"""Validate release metadata shared by PyPI, OCI, and the MCP Registry."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
MCP_NAME = "io.github.sjkim1127/reversecore-mcp"
PYPI_NAME = "reversecore-mcp"
OCI_PREFIX = "ghcr.io/sjkim1127/reversecore_mcp:"


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as file:
        return tomllib.load(file)


def _package_version() -> str:
    module = ast.parse((ROOT / "reversecore_mcp" / "__init__.py").read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    return node.value.value
    raise ValueError("reversecore_mcp.__version__ is missing or is not a string literal")


def _project_readme(project: dict[str, Any]) -> Path:
    readme = project.get("readme")
    if isinstance(readme, str):
        return ROOT / readme
    if isinstance(readme, dict) and isinstance(readme.get("file"), str):
        return ROOT / readme["file"]
    raise ValueError("project.readme must reference a file")


def validate_release_metadata(tag: str | None = None) -> list[str]:
    errors: list[str] = []
    pyproject = _load_toml(ROOT / "pyproject.toml")
    project = pyproject["project"]
    version = str(project.get("version", ""))

    if project.get("name") != PYPI_NAME:
        errors.append(f"project.name must be {PYPI_NAME!r}")

    package_version = _package_version()
    if package_version != version:
        errors.append(
            f"reversecore_mcp.__version__ ({package_version}) does not match pyproject version ({version})"
        )

    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    if server.get("name") != MCP_NAME:
        errors.append(f"server.json name must be {MCP_NAME!r}")
    if server.get("version") != version:
        errors.append(
            f"server.json version ({server.get('version')}) does not match pyproject version ({version})"
        )

    packages = {
        package.get("registryType"): package
        for package in server.get("packages", [])
        if isinstance(package, dict)
    }

    pypi = packages.get("pypi")
    if not pypi:
        errors.append("server.json must declare a PyPI package")
    else:
        if pypi.get("identifier") != PYPI_NAME:
            errors.append(f"PyPI identifier must be {PYPI_NAME!r}")
        if pypi.get("version") != version:
            errors.append("PyPI package version must match project.version")
        if pypi.get("transport", {}).get("type") != "stdio":
            errors.append("PyPI package transport must be stdio")

    oci = packages.get("oci")
    expected_oci = f"{OCI_PREFIX}{version}"
    if not oci:
        errors.append("server.json must declare an OCI package")
    else:
        if oci.get("identifier") != expected_oci:
            errors.append(f"OCI identifier must be {expected_oci!r}")
        if oci.get("transport", {}).get("type") != "stdio":
            errors.append("OCI package transport must be stdio")

    readme_path = _project_readme(project)
    marker = f"<!-- mcp-name: {MCP_NAME} -->"
    if not readme_path.exists():
        errors.append(f"project README does not exist: {readme_path.relative_to(ROOT)}")
    elif marker not in readme_path.read_text(encoding="utf-8"):
        errors.append(f"{readme_path.name} must contain the MCP ownership marker {marker!r}")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    label_pattern = re.compile(
        r'io\.modelcontextprotocol\.server\.name\s*=\s*"?'
        + re.escape(MCP_NAME)
        + r'"?'
    )
    if not label_pattern.search(dockerfile):
        errors.append("Dockerfile is missing the MCP Registry ownership label")

    if tag:
        normalized_tag = tag.removeprefix("refs/tags/")
        expected_tag = f"v{version}"
        if normalized_tag != expected_tag:
            errors.append(f"release tag {normalized_tag!r} must equal {expected_tag!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        help="Optional release tag to verify, such as v2.1.0 or refs/tags/v2.1.0",
    )
    args = parser.parse_args()

    errors = validate_release_metadata(args.tag)
    if errors:
        print("Release metadata validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    version = _load_toml(ROOT / "pyproject.toml")["project"]["version"]
    print(f"Release metadata is consistent for {MCP_NAME} v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
