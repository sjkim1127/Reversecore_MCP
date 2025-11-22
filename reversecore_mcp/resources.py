from fastmcp import FastMCP
from pathlib import Path
from collections import deque
import json

# Import tools at module level for better performance
# These imports are used by resource functions below
from reversecore_mcp.tools import cli_tools, lib_tools

# Resources 폴더 경로 (AI용 데이터)
RESOURCES_PATH = Path("/app/resources")

def register_resources(mcp: FastMCP):
    """Register MCP resources for AI agents."""

    # ============================================================================
    # 정적 리소스 (Static Resources)
    # ============================================================================
    
    @mcp.resource("reversecore://guide")
    def get_guide() -> str:
        """Reversecore MCP Tool Usage Guide"""
        guide_path = RESOURCES_PATH / "FILE_COPY_TOOL_GUIDE.md"
        if guide_path.exists():
            return guide_path.read_text(encoding="utf-8")
        return "Guide not found."

    @mcp.resource("reversecore://guide/structures")
    def get_structure_guide() -> str:
        """Structure Recovery and Cross-Reference Analysis Technical Guide"""
        doc_path = RESOURCES_PATH / "XREFS_AND_STRUCTURES_IMPLEMENTATION.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Documentation not found."

    @mcp.resource("reversecore://logs")
    def get_logs() -> str:
        """Application logs (last 100 lines)"""
        log_file = Path("/var/log/reversecore/app.log")
        if log_file.exists():
            try:
                # OPTIMIZED: Use deque to read only last N lines efficiently
                # This avoids loading the entire log file into memory
                with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                    # deque with maxlen automatically keeps only last N items
                    last_lines = deque(f, maxlen=100)
                    return "".join(last_lines)
            except Exception as e:
                return f"Error reading logs: {e}"
        return "No logs found."

    # ============================================================================
    # 동적 리소스 (Dynamic Resources) - Binary Virtual File System
    # ============================================================================
    
    @mcp.resource("reversecore://{filename}/strings")
    async def get_file_strings(filename: str) -> str:
        """Extract all strings from a binary file"""
        try:
            result = await cli_tools.run_strings(f"/app/workspace/{filename}")
            if result.status == "success":
                # Get content from ToolResult
                content = result.content[0].text if result.content else result.data
                return f"# Strings from {filename}\n\n{content}"
            return f"Error extracting strings: {result.message if hasattr(result, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/iocs")
    async def get_file_iocs(filename: str) -> str:
        """Extract IOCs (IPs, URLs, Emails) from a binary file"""
        try:
            # 1. Extract strings
            strings_res = await cli_tools.run_strings(f"/app/workspace/{filename}")
            if strings_res.status != "success":
                return f"Failed to extract strings from {filename}"
            
            # 2. Extract IOCs from strings
            strings_data = strings_res.content[0].text if strings_res.content else strings_res.data
            ioc_res = lib_tools.extract_iocs(strings_data)
            
            # 3. Format output
            if ioc_res.status == "success":
                data = ioc_res.data
                ipv4_list = data.get('ipv4', [])
                urls_list = data.get('urls', [])
                emails_list = data.get('emails', [])
                
                return f"""# IOC Report for {filename}

## IPv4 Addresses ({len(ipv4_list)})
{chr(10).join(f"- {ip}" for ip in ipv4_list) if ipv4_list else "No IPv4 addresses found"}

## URLs ({len(urls_list)})
{chr(10).join(f"- {url}" for url in urls_list) if urls_list else "No URLs found"}

## Email Addresses ({len(emails_list)})
{chr(10).join(f"- {email}" for email in emails_list) if emails_list else "No emails found"}
"""
            return f"Error extracting IOCs: {ioc_res.message if hasattr(ioc_res, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/func/{address}/code")
    async def get_decompiled_code(filename: str, address: str) -> str:
        """Get decompiled pseudo-C code for a specific function"""
        try:
            result = await cli_tools.smart_decompile(
                f"/app/workspace/{filename}", 
                address, 
                use_ghidra=True
            )
            
            if result.status == "success":
                content = result.content[0].text if result.content else result.data
                return f"""# Decompiled Code: {filename} @ {address}

```c
{content}
```
"""
            return f"Error decompiling {address}: {result.message if hasattr(result, 'message') else 'Decompilation failed'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/func/{address}/asm")
    async def get_disassembly(filename: str, address: str) -> str:
        """Get disassembly for a specific function"""
        try:
            result = await cli_tools.run_radare2(
                f"/app/workspace/{filename}", 
                f"pdf @ {address}"
            )
            
            if result.status == "success":
                content = result.content[0].text if result.content else result.data
                return f"""# Disassembly: {filename} @ {address}

```asm
{content}
```
"""
            return f"Error disassembling {address}: {result.message if hasattr(result, 'message') else 'Disassembly failed'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/func/{address}/cfg")
    async def get_function_cfg(filename: str, address: str) -> str:
        """Get Control Flow Graph (Mermaid) for a specific function"""
        try:
            result = await cli_tools.generate_function_graph(
                f"/app/workspace/{filename}", 
                address,
                format="mermaid"
            )
            
            if result.status == "success":
                content = result.content[0].text if result.content else result.data
                return f"""# Control Flow Graph: {filename} @ {address}

{content}
"""
            return f"Error generating CFG for {address}: {result.message if hasattr(result, 'message') else 'CFG generation failed'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/functions")
    async def get_function_list(filename: str) -> str:
        """Get list of all functions in the binary"""
        try:
            result = await cli_tools.run_radare2(
                f"/app/workspace/{filename}", 
                "aflj"  # List functions in JSON format
            )
            
            if result.status == "success":
                content = result.content[0].text if result.content else result.data
                
                try:
                    functions = json.loads(content)
                    func_list = []
                    for func in functions[:50]:  # Limit to first 50 for readability
                        name = func.get('name', 'unknown')
                        offset = func.get('offset', 0)
                        size = func.get('size', 0)
                        func_list.append(f"- `{name}` @ 0x{offset:x} (size: {size} bytes)")
                    
                    total = len(functions)
                    shown = min(50, total)
                    
                    return f"""# Functions in {filename}

Total functions: {total}
Showing: {shown}

{chr(10).join(func_list)}
"""
                except:
                    return f"# Functions in {filename}\n\n{content}"
                    
            return f"Error listing functions: {result.message if hasattr(result, 'message') else 'Failed to list functions'}"
        except Exception as e:
            return f"Error: {str(e)}"
