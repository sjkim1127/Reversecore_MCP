# Changelog

All notable changes to Reversecore MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Report Tools module for professional analysis documentation
  - `start_analysis_session` / `end_analysis_session` for session tracking
  - `add_session_ioc` / `get_session_iocs` for IOC management
  - `add_session_mitre` for MITRE ATT&CK mapping
  - `create_analysis_report` with multiple templates
  - `send_report` for email delivery
  - `get_system_time` for accurate timestamps
- Internationalized date formats (global support)
- `report_generation_mode` prompt for guided reporting

### Changed
- Replaced Korean-specific date formats with global formats
- Updated documentation for global users

## [3.0.0] - 2025-12-01

### Added
- Game Security Analysis tools
  - `find_cheat_points` - Automated cheat detection
  - `analyze_game_protocol` - Network protocol analysis
- Enhanced AI reasoning prompts
  - Expert persona priming
  - Chain-of-Thought checkpoints
  - Structured reasoning frameworks
- `game_analysis_mode` prompt for game client analysis

### Changed
- Dynamic timeout scaling (base + 2s/MB, max +600s)
- Ghidra JVM heap increased to 16GB
- Sink-aware pruning with 39 dangerous APIs
- Trace depth reduced from 3 to 2 for performance

### Fixed
- Timeout issues with large binaries
- Memory leaks in Radare2 pool

## [2.5.0] - 2025-11-15

### Added
- Trinity Defense System
  - Three-phase automated threat pipeline
  - Ghost Trace for hidden behavior detection
  - Neural Decompiler for AI-enhanced analysis
  - Adaptive Vaccine for defense generation
- Binary comparison tools
  - `diff_binaries` for patch analysis
  - Function-level comparison

### Changed
- Improved error messages with hints
- Better timeout handling

## [2.0.0] - 2025-11-01

### Added
- Ghidra integration for decompilation
- LIEF-based binary parsing
- YARA signature generation and scanning
- Structure recovery from binaries
- Cross-reference analysis

### Changed
- Migrated to FastMCP framework
- Restructured tool organization
- Unified response format (ToolResult)

### Removed
- Legacy r2pipe direct usage (replaced with pool)

## [1.0.0] - 2025-10-15

### Added
- Initial release
- Basic Radare2 integration
  - `run_radare2` command execution
  - Function listing and disassembly
- CLI tool wrappers
  - `run_file` for file identification
  - `run_strings` for string extraction
  - `run_binwalk` for embedded file detection
- Capstone disassembly
- ESIL emulation
- Docker support (x86_64 and ARM64)
- MCP protocol support (stdio and HTTP)

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 3.0.0 | 2025-12-01 | Game analysis, performance optimizations |
| 2.5.0 | 2025-11-15 | Trinity Defense, binary diffing |
| 2.0.0 | 2025-11-01 | Ghidra integration, LIEF, YARA |
| 1.0.0 | 2025-10-15 | Initial release |

## Migration Guides

### Upgrading to 3.0.0

No breaking changes. New features are additive.

### Upgrading to 2.0.0

Tool response format changed:

**Before (1.x):**
```python
{"result": "...", "error": null}
```

**After (2.0+):**
```python
{"status": "success", "data": "...", "metadata": {...}}
```

Update your response parsing accordingly.
