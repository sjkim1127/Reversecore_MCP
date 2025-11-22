# Universal File Copy Tool Usage Guide

This guide demonstrates how to use the new `copy_to_workspace` and `list_workspace` tools for seamless file analysis across different AI agents.

## Tools Overview

### 1. copy_to_workspace

Copy any accessible file to the workspace directory where reverse engineering tools can access it.

**Parameters:**
- `source_path` (required): Absolute or relative path to the source file
- `destination_name` (optional): Custom filename in workspace (defaults to original name)

**Returns:**
- Success: File path in workspace, along with metadata (source path, destination path, file size)
- Error: Validation error with details

**Example Usage:**

```python
# Claude Desktop
copy_to_workspace("/mnt/user-data/uploads/malware.exe")
# → /app/workspace/malware.exe

# Cursor AI
copy_to_workspace("/home/user/Downloads/sample.bin")
# → /app/workspace/sample.bin

# With custom name
copy_to_workspace("/tmp/upload/file.bin", destination_name="suspicious.bin")
# → /app/workspace/suspicious.bin
```

### 2. list_workspace

List all files currently in the workspace directory.

**Parameters:** None

**Returns:**
- Dictionary containing:
  - `files`: List of file objects with `name`, `size`, and `path`
  - Metadata: `file_count` and `workspace_path`

**Example Usage:**

```python
list_workspace()
# Returns:
# {
#   "files": [
#     {"name": "malware.exe", "size": 102400, "path": "/app/workspace/malware.exe"},
#     {"name": "sample.bin", "size": 51200, "path": "/app/workspace/sample.bin"}
#   ]
# }
# Metadata: {"file_count": 2, "workspace_path": "/app/workspace"}
```

## Workflow Examples

### Example 1: Analyzing an Uploaded File

```
User: (uploads malware.exe via Claude Desktop)
"Analyze this executable file"

Agent Steps:
1. copy_to_workspace("/mnt/user-data/uploads/malware.exe")
   → File copied to /app/workspace/malware.exe
   
2. run_file("/app/workspace/malware.exe")
   → Get file type information
   
3. run_strings("/app/workspace/malware.exe")
   → Extract printable strings
   
4. run_yara("/app/workspace/malware.exe", "/app/rules/malware.yar")
   → Check for malware signatures
```

### Example 2: Batch Analysis

```
User: (has files in /home/user/samples/)
"Analyze all files in my samples directory"

Agent Steps:
1. For each file in directory:
   - copy_to_workspace(file_path, destination_name=f"sample_{i}.bin")
   
2. list_workspace()
   → See all copied files
   
3. For each file in workspace:
   - run_file(file_path)
   - run_strings(file_path)
   - Parse and summarize results
```

### Example 3: Cross-Platform Analysis

```
Windows (Windsurf):
copy_to_workspace("C:\\Users\\Kim\\Desktop\\suspicious.exe")

Mac (Cursor):
copy_to_workspace("/Users/kim/Downloads/sample.bin")

Linux (Claude Desktop):
copy_to_workspace("/home/kim/malware/test.elf")

All files end up in the same workspace for analysis!
```

## Security Features

1. **File Size Limit**: Maximum 5GB per file
2. **Path Sanitization**: Prevents directory traversal attacks
3. **Overwrite Protection**: Won't overwrite existing files
4. **Read-Only Source**: Source files are never modified
5. **Workspace Isolation**: All analysis confined to workspace

## Error Handling

Common errors and solutions:

```python
# Error: File doesn't exist
copy_to_workspace("/nonexistent/file.bin")
# → ValidationError: "Source file does not exist"

# Error: File already exists
copy_to_workspace("/tmp/file.bin")  # first time: OK
copy_to_workspace("/tmp/file.bin")  # second time: error
# → ValidationError: "File already exists in workspace: file.bin"
# Solution: Use different destination_name or remove existing file

# Error: File too large
copy_to_workspace("/huge/6GB_file.bin")
# → ValidationError: "File too large to copy"

# Error: Invalid destination name
copy_to_workspace("/tmp/file.bin", destination_name="../../../etc/passwd")
# → ValidationError: "Invalid destination name"
```

## Integration with Docker

To support multiple upload directories, mount them in Docker:

```bash
docker run -d \
  -p 8000:8000 \
  -v E:/Reversecore_Workspace:/app/workspace \
  -v /tmp:/tmp:ro \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  --name reversecore-mcp \
  reversecore-mcp
```

## Best Practices

1. **Always copy before analyzing**: Use `copy_to_workspace` to ensure files are accessible
2. **Use descriptive names**: When analyzing multiple files, use `destination_name` for clarity
3. **Check workspace regularly**: Use `list_workspace` to see what files are available
4. **Handle errors gracefully**: Check result status and provide user-friendly messages
5. **Clean up when done**: Consider removing files after analysis to save space

## Supported AI Agents

This tool works with any AI agent that can:
- Access local file system
- Call MCP tools
- Provide file paths

Confirmed working with:
- Claude Desktop
- Cursor
- Windsurf
- Cline
- Any MCP-compatible AI agent
