# Quick Start

This guide will help you run the Reversecore MCP server and begin analyzing binaries with your AI assistant in just a few minutes.

---

## Step 1: Start the Server

### Option A: Using Docker (Fastest)

Start the pre-built container. Make sure to replace `/path/to/your/samples` with the folder where your target binaries are located:

```bash
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

### Option B: Native Setup

Start the Python server script directly:

```bash
export REVERSECORE_WORKSPACE=./samples
python server.py
```

---

## Step 2: Connect Your AI Assistant

### Claude Desktop

To connect Reversecore MCP to the official Claude Desktop app, edit your configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the server definition inside the `mcpServers` object:

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/your/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

Restart Claude Desktop, and you will see the plug icon indicating that the server is connected.

### Cursor

1. Open Cursor and navigate to **Settings** -> **Features** -> **MCP**.
2. Click **+ Add New MCP Server**.
3. Fill in the fields:
   - **Name**: `reversecore`
   - **Type**: `command`
   - **Command**: `docker run -i --rm -v /path/to/your/samples:/app/workspace -e REVERSECORE_WORKSPACE=/app/workspace -e MCP_TRANSPORT=stdio ghcr.io/sjkim1127/reversecore_mcp:latest`
4. Click **Save**.

---

## Step 3: Try Your First Analysis Prompts

Once connected, you can interact with the server by asking the AI questions in natural language. The AI will translate your questions into tool calls behind the scenes.

> [!IMPORTANT]
> Because your local directory is mounted to `/app/workspace` inside the container, you must always refer to files by their **filename only** (e.g. `malware.elf`), not by their full local absolute path.

### 1. Basic File Triage
Ask the AI to identify a suspicious file:
> *"What type of file is malware.elf? Extract its strings and let me know if you see anything suspicious."*

*Under the hood, the AI will call:*
1. `run_file(file_path="malware.elf")`
2. `run_strings(file_path="malware.elf")`

### 2. Disassembly & Decompilation
Request pseudocode generation:
> *"Decompile the main function of malware.elf. What parameters is it expecting?"*

*Under the hood, the AI will call:*
1. `r2_decompile(file_path="malware.elf", function_name="main")`

### 3. Backdoor & Logic Bomb Hunting
Instruct the AI to check for hidden paths:
> *"Run the dormant detector on malware.elf. Are there any functions that have no callers or appear triggered by specific dates?"*

*Under the hood, the AI will call:*
1. `dormant_detector(file_path="malware.elf")`

### 4. Automated Vaccine Generation
Generate YARA signatures and proposed binary modifications:
> *"Create an adaptive vaccine for malware.elf so we can detect and patch this threat."*

*Under the hood, the AI will call:*
1. `adaptive_vaccine(file_path="malware.elf")`

---

## Next Steps

- Check the [User Guide](../user-guide/overview.md) for more details on each tool category.
- Read about [Environment Configuration](configuration.md) to customize server limits, pool sizes, and SMTP report settings.
- Explore the [API Reference](../api/core/config.md) for a comprehensive list of tools and python types.
