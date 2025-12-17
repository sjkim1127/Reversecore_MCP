"""Common constants and rules for prompts."""

# Common path rule instruction for Docker environment
# This constant is included in prompts to guide AI clients on proper file path usage
DOCKER_PATH_RULE = """
[CRITICAL: File Path Rule]
- This server runs in a Docker container with workspace at /app/workspace/
- When the user provides a full path like "/Users/.../file.exe", extract ONLY the filename
- Example: "/Users/john/Reversecore_Workspace/sample.exe" → use "sample.exe"
- First, ALWAYS run `list_workspace()` to verify the file exists in the workspace
- If the file is not in the workspace, inform the user to copy it there first

[CRITICAL: Tool Usage Rule]
- ALWAYS use `list_workspace()` first to verify files.
- For disassembly, ALWAYS use `Radare2_disassemble` or `run_radare2`.
- DO NOT use Capstone tools as they lack file format context (VA/offset).
- Use `extract_iocs` for automated artifact extraction (IP, URL, BTC, Hashes).
"""

LANGUAGE_RULE = """
[Language Rule]
- Answer in the same language as the user's request.
- Keep technical terms (API names, addresses, opcodes) in English.
"""
