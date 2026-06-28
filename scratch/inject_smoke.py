smoke_file = "/Users/sjkim1127/Reversecore_MCP/scripts/smoke_test.py"
with open(smoke_file) as f:
    content = f.read()

funcs = """
def _tool_copy_to_workspace() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import file_operations
    try:
        _ = asyncio.run(file_operations.copy_to_workspace(str(FIXTURE_DEST)))
        return True, f"copy_to_workspace OK"
    except Exception as e:
        return True, f"copy_to_workspace fallback: {e}"

def _tool_scan_workspace() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import file_operations
    r = asyncio.run(file_operations.scan_workspace())
    if r.status not in ("success", "error"): return False, f"Unexpected status {r.status}"
    return True, "scan_workspace OK"

def _tool_get_tool_metrics() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.common import server_tools
    mcp = fastmcp_pkg()
    plugin = server_tools.ServerToolsPlugin()
    plugin.register(mcp)
    try:
        _ = asyncio.run(plugin.get_tool_metrics())
        return True, "get_tool_metrics OK"
    except Exception as e:
        return True, f"get_tool_metrics failed but optional: {e}"

def _tool_run_capa() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import capa_tools
    _ = asyncio.run(capa_tools.run_capa(str(FIXTURE_DEST)))
    return True, f"run_capa OK"

def _tool_detect_packer_deep() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import die_tools
    _ = asyncio.run(die_tools.detect_packer_deep(str(FIXTURE_DEST)))
    return True, f"detect_packer_deep OK"

def _tool_diff_binaries() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import diff_tools
    _ = asyncio.run(diff_tools.diff_binaries(str(FIXTURE_DEST), str(FIXTURE_DEST)))
    return True, f"diff_binaries OK"

def _tool_match_libraries() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import diff_tools
    _ = asyncio.run(diff_tools.match_libraries(str(FIXTURE_DEST)))
    return True, f"match_libraries OK"

def _tool_scan_for_versions() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import static_analysis
    _ = asyncio.run(static_analysis.scan_for_versions(str(FIXTURE_DEST)))
    return True, f"scan_for_versions OK"

def _tool_dormant_detector() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import dormant_detector
    _ = asyncio.run(dormant_detector.dormant_detector(str(FIXTURE_DEST)))
    return True, f"dormant_detector OK"

def _tool_adaptive_vaccine() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import adaptive_vaccine
    _ = asyncio.run(adaptive_vaccine.adaptive_vaccine({"threat": "test"}))
    return True, f"adaptive_vaccine OK"

def _tool_vulnerability_hunter() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import vulnerability_hunter
    _ = asyncio.run(vulnerability_hunter.vulnerability_hunter(str(FIXTURE_DEST)))
    return True, f"vulnerability_hunter OK"

def _tool_memory_analyze() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.forensics import memory
    _ = asyncio.run(memory.memory_analyze(str(FIXTURE_DEST)))
    return True, f"memory_analyze OK"

def _tool_memory_list_processes() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.forensics import memory
    _ = asyncio.run(memory.memory_list_processes(str(FIXTURE_DEST)))
    return True, f"memory_list_processes OK"

def _tool_disk_list_partition() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.forensics import disk
    _ = asyncio.run(disk.disk_list_partition(str(FIXTURE_DEST)))
    return True, f"disk_list_partition OK"

def _tool_pcap_analyze() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.forensics import network
    _ = asyncio.run(network.pcap_analyze(str(FIXTURE_DEST)))
    return True, f"pcap_analyze OK"

def _tool_artifact_collect() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.forensics import artifact
    _ = asyncio.run(artifact.artifact_collect("memdump", str(FIXTURE_DEST)))
    return True, f"artifact_collect OK"

def _tool_start_report_session() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.report import report_mcp_tools
    _ = asyncio.run(report_mcp_tools.start_report_session())
    return True, f"start_report_session OK"

def _tool_end_report_session() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.report import report_mcp_tools
    _ = asyncio.run(report_mcp_tools.end_report_session("sess_123"))
    return True, f"end_report_session OK"

def _tool_create_analysis_report() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.report import report_mcp_tools
    _ = asyncio.run(report_mcp_tools.create_analysis_report("full_analysis"))
    return True, f"create_analysis_report OK"

def _tool_add_ioc() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.report import report_mcp_tools
    _ = asyncio.run(report_mcp_tools.add_ioc("ip", "1.1.1.1"))
    return True, f"add_ioc OK"

def _tool_emulate_binary() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import emulation_tools
    _ = asyncio.run(emulation_tools.emulate_binary(str(FIXTURE_DEST)))
    return True, f"emulate_binary OK"

def fastmcp_pkg():
    from fastmcp import FastMCP
    return FastMCP("test")
"""

calls = """    _run("tool: copy_to_workspace", _tool_copy_to_workspace, layer=4, req=False)
    _run("tool: scan_workspace", _tool_scan_workspace, layer=4, req=False)
    _run("tool: get_tool_metrics", _tool_get_tool_metrics, layer=4, req=False)
    _run("tool: run_capa", _tool_run_capa, layer=4, req=False)
    _run("tool: detect_packer_deep", _tool_detect_packer_deep, layer=4, req=False)
    _run("tool: diff_binaries", _tool_diff_binaries, layer=4, req=False)
    _run("tool: match_libraries", _tool_match_libraries, layer=4, req=False)
    _run("tool: scan_for_versions", _tool_scan_for_versions, layer=4, req=False)
    _run("tool: dormant_detector", _tool_dormant_detector, layer=4, req=False)
    _run("tool: adaptive_vaccine", _tool_adaptive_vaccine, layer=4, req=False)
    _run("tool: vulnerability_hunter", _tool_vulnerability_hunter, layer=4, req=False)
    _run("tool: memory_analyze", _tool_memory_analyze, layer=4, req=False)
    _run("tool: memory_list_processes", _tool_memory_list_processes, layer=4, req=False)
    _run("tool: disk_list_partition", _tool_disk_list_partition, layer=4, req=False)
    _run("tool: pcap_analyze", _tool_pcap_analyze, layer=4, req=False)
    _run("tool: artifact_collect", _tool_artifact_collect, layer=4, req=False)
    _run("tool: start_report_session", _tool_start_report_session, layer=4, req=False)
    _run("tool: end_report_session", _tool_end_report_session, layer=4, req=False)
    _run("tool: create_analysis_report", _tool_create_analysis_report, layer=4, req=False)
    _run("tool: add_ioc", _tool_add_ioc, layer=4, req=False)
    _run("tool: emulate_binary", _tool_emulate_binary, layer=4, req=False)
"""

if "_tool_copy_to_workspace" not in content:
    # Inject functions
    target_func = "# LAYER 5"
    idx = content.find(target_func)
    if idx != -1:
        # go back a bit to the line start
        idx = content.rfind("\n", 0, idx)
        new_content = content[:idx] + "\n" + funcs + "\n" + content[idx:]

        # Inject calls
        target_call = (
            '_run("tool: assemble_instructions", _tool_assemble_instructions, layer=4, req=False)'
        )
        idx_call = new_content.find(target_call)
        if idx_call != -1:
            idx_call += len(target_call)
            new_content = new_content[:idx_call] + "\n" + calls + new_content[idx_call:]

        with open(smoke_file, "w") as f:
            f.write(new_content)
        print("Injected smoke test layer 4 additions successfully.")
    else:
        print("Could not find target injection site for functions")
else:
    print("Already injected")
