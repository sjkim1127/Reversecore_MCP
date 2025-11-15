# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- _No changes yet_

## [1.3.0] - 2025-11-15

### Added
- **ToolResult Contract**: All public MCP tools now emit `ToolSuccess`/`ToolError` Pydantic models with structured metadata, enabling AI agents to branch on `status`, `error_code`, and `hint` without parsing strings.
- **Documentation Refresh**: `README.md` showcases ToolResult-aware API examples and guidance for implementing new tools with the shared decorators.

### Changed
- **Local-First Hardening**:
  - CLI + library integration tests consume the `patched_workspace_config` fixture instead of mutating global environment variables.
  - CLI/lib/unit suites assert directly on ToolResult fields, ensuring the contract can’t regress.
  - Metrics, logging, and execution decorators now wrap every tool consistently via `handle_tool_errors`.
- **Config Compatibility**: Reintroduced `reload_settings()` as a thin wrapper over `reset_config()` so legacy tests keep working while the new singleton flow stays intact.

### Fixed
- **Test Stability**:
  - CLI integration tests skip gracefully when required binaries (file/strings/r2) are unavailable on the host.
  - HTTP server tests skip when FastAPI isn’t installed, preventing false negatives in minimal dev environments.
  - Metrics decorator tests now validate error counting by returning `ToolResult` objects instead of magic strings.
- **Security Fixtures**: Read-only directory fixture no longer races on already-created paths during Windows tests.

## [1.2.0] - 2025-11-15

### Added
- Initial release of Reversecore_MCP
- Support for CLI tools: file, strings, radare2, binwalk
- Support for library tools: YARA, Capstone, LIEF
- Security-first design with comprehensive input validation
- Docker containerization support
- MCP protocol integration for AI agents
