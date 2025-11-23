from fastmcp import FastMCP
from pathlib import Path
from collections import deque

# Import tools at module level for better performance
# These imports are used by resource functions below
from reversecore_mcp.tools import cli_tools, lib_tools
from reversecore_mcp.core import json_utils as json  # Use optimized JSON (3-5x faster)

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

    # ============================================================================
    # Reversecore Signature Resources (Trinity Defense System)
    # ============================================================================
    
    @mcp.resource("reversecore://{filename}/trinity_defense")
    async def get_trinity_defense_report(filename: str) -> str:
        """Get comprehensive Trinity Defense System analysis report"""
        try:
            from reversecore_mcp.tools import trinity_defense as td_module
            
            result = await td_module.trinity_defense(
                file_path=f"/app/workspace/{filename}",
                mode="full",
                max_threats=5,
                generate_vaccine=True
            )
            
            if result.status == "success":
                data = result.data
                summary = data.get("summary", {})
                phase_1 = data.get("phase_1_discover", {})
                phase_2 = data.get("phase_2_understand", [])
                phase_3 = data.get("phase_3_neutralize", [])
                recommendations = data.get("recommendations", [])
                
                # Format report
                report = f"""# 🔱 Trinity Defense System Report: {filename}

## Executive Summary
- **Threats Discovered**: {summary.get('threats_discovered', 0)}
- **Threats Analyzed**: {summary.get('threats_analyzed', 0)}
- **Defenses Generated**: {summary.get('defenses_generated', 0)}
- **Status**: {data.get('status', 'unknown')}

## Phase 1: DISCOVER (Ghost Trace)
- Orphan Functions: {phase_1.get('orphan_functions', 0)}
- Suspicious Logic: {phase_1.get('suspicious_logic', 0)}
- Total Threats: {phase_1.get('total_threats', 0)}

## Phase 2: UNDERSTAND (Neural Decompiler)
"""
                for i, threat in enumerate(phase_2[:5]):
                    intent = threat.get('intent', 'unknown')
                    confidence = threat.get('confidence', 0.0)
                    report += f"""
### Threat {i+1}: {threat.get('function', 'unknown')}
- **Address**: {threat.get('address', 'N/A')}
- **Intent**: {intent}
- **Confidence**: {confidence:.2f}
- **Reason**: {threat.get('reason', 'N/A')}
"""
                
                report += "\n## Phase 3: NEUTRALIZE (Adaptive Vaccine)\n"
                report += f"- YARA Rules Generated: {len(phase_3)}\n\n"
                
                report += "## Recommendations\n"
                for i, rec in enumerate(recommendations[:5]):
                    if isinstance(rec, dict):
                        report += f"\n### {rec.get('severity', 'INFO')}: {rec.get('threat_type', 'Unknown')}\n"
                        report += f"- **Location**: {rec.get('location', 'N/A')}\n"
                        report += f"- **Confidence**: {rec.get('confidence', 0.0):.2f}\n"
                        immediate = rec.get('immediate_actions', [])
                        if immediate:
                            report += "\n**Immediate Actions:**\n"
                            for action in immediate[:5]:
                                report += f"- {action}\n"
                    else:
                        report += f"{i+1}. {rec}\n"
                
                return report
            
            return f"Trinity Defense analysis failed: {result.message if hasattr(result, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/ghost_trace")
    async def get_ghost_trace_results(filename: str) -> str:
        """Get Ghost Trace analysis results (orphan functions and logic bombs)"""
        try:
            from reversecore_mcp.tools import ghost_trace as gt_module
            
            result = await gt_module.ghost_trace(
                file_path=f"/app/workspace/{filename}"
            )
            
            if result.status == "success":
                data = result.data
                orphans = data.get("orphan_functions", [])
                suspicious = data.get("suspicious_logic", [])
                
                report = f"""# 👻 Ghost Trace Results: {filename}

## Orphan Functions (Never Called)
Found {len(orphans)} orphan function(s):

"""
                for func in orphans[:10]:
                    report += f"""### {func.get('name', 'unknown')}
- **Address**: {func.get('address', 'N/A')}
- **Size**: {func.get('size', 0)} bytes
- **Cross-References**: {func.get('xrefs', 0)}
- **Assessment**: Potentially hidden backdoor or logic bomb

"""
                
                report += f"\n## Suspicious Logic (Magic Values)\nFound {len(suspicious)} suspicious pattern(s):\n\n"
                
                for logic in suspicious[:10]:
                    report += f"""### {logic.get('function', 'unknown')}
- **Address**: {logic.get('address', 'N/A')}
- **Instruction**: `{logic.get('instruction', 'N/A')}`
- **Reason**: {logic.get('reason', 'N/A')}

"""
                
                return report
            
            return f"Ghost Trace analysis failed: {result.message if hasattr(result, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.resource("reversecore://{filename}/func/{address}/neural_decompile")
    async def get_neural_decompiled_code(filename: str, address: str) -> str:
        """Get AI-refined decompiled code from Neural Decompiler"""
        try:
            from reversecore_mcp.tools import neural_decompiler as nd_module
            
            result = await nd_module.neural_decompile(
                file_path=f"/app/workspace/{filename}",
                function_address=address
            )
            
            if result.status == "success":
                data = result.data
                neural_code = data.get("neural_code", "")
                ghidra_code = data.get("ghidra_code", "")
                stats = data.get("refinement_stats", {})
                
                return f"""# 🧠 Neural Decompiler: {filename} @ {address}

## AI-Refined Code (Neural Decompiler)
```c
{neural_code}
```

## Original Ghidra Output
```c
{ghidra_code}
```

## Refinement Statistics
- Variables Renamed: {stats.get('variables_renamed', 0)}
- Structures Inferred: {stats.get('structures_inferred', 0)}
- Comments Added: {stats.get('comments_added', 0)}
"""
            
            return f"Neural Decompilation failed: {result.message if hasattr(result, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"
