# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Result Type System**: Introduced internal Result type for structured error handling
  - All tool functions now use Result type internally for better type safety
  - Structured error responses with error codes, messages, and hints
  - Support for both string and dict data in Success results
  - Public APIs maintain backward compatibility (still return strings)

### Changed
- **Improved Error Handling**: Simplified error handling across all tools
  - Removed deeply nested try-except blocks in favor of flat error handling
  - Clear separation of concerns with helper functions
  - Better error messages with actionable hints
  - Improved exception type detection using isinstance() checks
  
- **Code Quality Improvements**:
  - Reduced lib_tools.py complexity by ~58 lines (613 → 555)
  - Extracted reusable helper functions (e.g., _format_yara_match)
  - Simplified logic flow: validation → execution → formatting
  
- **YARA Response Format**: Changed from array to structured object
  - Old: `[{rule: "...", ...}]`
  - New: `{matches: [{rule: "...", ...}], match_count: 1}`
  - Provides better context and metadata

### Deprecated
- **sanitize_command_string()**: Deprecated in favor of validate_r2_command()
  - Use `validate_r2_command()` from `reversecore_mcp.core.command_spec` for radare2 commands
  - Provides stronger security guarantees through regex-based validation
  - Will be removed in a future version

### Fixed
- Improved YARA timeout error detection to properly handle TimeoutError exceptions
- Better error messages for CalledProcessError exceptions

## [1.0.0] - 2024-XX-XX

### Added
- Initial release of Reversecore_MCP
- Support for CLI tools: file, strings, radare2, binwalk
- Support for library tools: YARA, Capstone, LIEF
- Security-first design with comprehensive input validation
- Docker containerization support
- MCP protocol integration for AI agents
