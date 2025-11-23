import unittest
from unittest.mock import AsyncMock, MagicMock
import json
import asyncio
from typing import Dict, Any, List, Optional

# --- Mocks for dependencies ---

class ToolResult:
    def __init__(self, content, is_error=False):
        self.content = content
        self.is_error = is_error

class TextContent:
    def __init__(self, text):
        self.text = text

def success(data):
    return ToolResult([TextContent(json.dumps(data))])

def failure(msg):
    return ToolResult([TextContent(msg)], is_error=True)

async def execute_subprocess_async(cmd, timeout=30):
    pass # Mocked

def validate_file_path(path):
    return path

# --- Code under test (Copied from ghost_trace.py) ---

async def _run_r2_cmd(file_path: str, cmd: str, timeout: int = 30) -> str:
    full_cmd = ["radare2", "-q", "-c", cmd, str(file_path)]
    output, _ = await execute_subprocess_async(full_cmd, timeout=timeout)
    return output

async def ghost_trace(
    file_path: str,
    focus_function: Optional[str] = None,
    hypothesis: Optional[Dict[str, Any]] = None,
    timeout: int = 300,
    ctx = None,
) -> ToolResult:
    validated_path = validate_file_path(file_path)
    
    if focus_function and hypothesis:
        return await _verify_hypothesis_with_emulation(
            validated_path, focus_function, hypothesis, timeout
        )

    cmd = "aaa; aflj"
    output = await _run_r2_cmd(validated_path, cmd, timeout=timeout)
    
    try:
        lines = output.strip().split('\n')
        json_str = ""
        for line in reversed(lines):
            if line.strip().endswith(']'):
                json_str = line
                break
        if not json_str:
            json_str = output
        functions = json.loads(json_str)
    except Exception as e:
        return failure(f"Failed to parse function list: {e}")

    orphans = await _find_orphan_functions(validated_path, functions)
    suspicious_logic = await _identify_conditional_paths(validated_path, functions[:20])
    
    return success({
        "scan_type": "discovery",
        "orphan_functions": orphans,
        "suspicious_logic": suspicious_logic,
        "description": "Found potential logic bombs."
    })

async def _find_orphan_functions(file_path, functions):
    orphans = []
    for func in functions:
        name = func.get("name", "")
        if name.startswith("sym.imp") or "main" in name or "entry" in name:
            continue
        refs = func.get("codexrefs", [])
        if not refs and func.get("size", 0) > 50:
            orphans.append({
                "name": name,
                "address": hex(func.get("offset", 0)),
                "size": func.get("size"),
                "reason": "No code cross-references found"
            })
    return orphans

async def _identify_conditional_paths(file_path, functions):
    suspicious = []
    for func in functions:
        addr = func.get("offset")
        name = func.get("name")
        if not addr: continue
        
        cmd = f"pdfj @ {addr}"
        out = await _run_r2_cmd(file_path, cmd)
        
        try:
            ops = json.loads(out).get("ops", [])
            for op in ops:
                disasm = op.get("disasm", "")
                if "cmp" in disasm and "0x" in disasm:
                    args = disasm.split(",")
                    if len(args) > 1:
                        val = args[1].strip()
                        if val.startswith("0x") and len(val) > 4:
                             suspicious.append({
                                "function": name,
                                "address": hex(op.get("offset", 0)),
                                "instruction": disasm,
                                "reason": "Magic value comparison detected"
                            })
        except:
            pass
    return suspicious

async def _verify_hypothesis_with_emulation(file_path, function_name, hypothesis, timeout):
    regs = hypothesis.get("registers", {})
    max_steps = hypothesis.get("max_steps", 50)
    
    cmds = ["aaa", "aei", "aeim", f"s {function_name}"]
    for reg, val in regs.items():
        cmds.append(f"aer {reg}={val}")
    cmds.append(f"aes {max_steps}")
    cmds.append("aerj")
    
    full_cmd = "; ".join(cmds)
    output = await _run_r2_cmd(file_path, full_cmd, timeout=timeout)
    
    try:
        lines = output.strip().split('\n')
        json_str = ""
        for line in reversed(lines):
            if line.strip().endswith('}'):
                json_str = line
                break
        final_regs = json.loads(json_str) if json_str else {}
        
        return success({
            "status": "emulation_complete",
            "steps_executed": max_steps,
            "final_registers": final_regs
        })
    except Exception as e:
        return failure(f"Emulation failed: {e}")

# --- Tests ---

class TestGhostTraceStandalone(unittest.IsolatedAsyncioTestCase):
    
    async def test_discovery(self):
        global execute_subprocess_async
        execute_subprocess_async = AsyncMock()
        
        # Mock data
        functions_json = [
            {"name": "main", "offset": 4096, "size": 100, "codexrefs": [{"addr": 0x1000}]},
            {"name": "orphan_func", "offset": 8192, "size": 200, "codexrefs": []}
        ]
        ops_json = {
            "ops": [
                {"offset": 8200, "disasm": "cmp eax, 0xCAFEBABE"}
            ]
        }
        
        async def side_effect(cmd, timeout=30):
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
            if "aflj" in cmd_str:
                return json.dumps(functions_json), ""
            if "pdfj" in cmd_str:
                return json.dumps(ops_json), ""
            return "{}", ""
        
        execute_subprocess_async.side_effect = side_effect
        
        result = await ghost_trace("/tmp/test")
        
        self.assertFalse(result.is_error)
        data = result.content[0].text
        self.assertIn("orphan_func", data)
        self.assertIn("0xCAFEBABE", data)

    async def test_emulation(self):
        global execute_subprocess_async
        execute_subprocess_async = AsyncMock()
        
        final_regs = {"eax": 0x1234}
        
        async def side_effect(cmd, timeout=30):
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
            if "aerj" in cmd_str:
                return json.dumps(final_regs), ""
            return "", ""
            
        execute_subprocess_async.side_effect = side_effect
        
        result = await ghost_trace(
            "/tmp/test",
            focus_function="orphan_func",
            hypothesis={"registers": {"eax": "0xCAFEBABE"}}
        )
        
        self.assertFalse(result.is_error)
        self.assertIn("4660", result.content[0].text)

if __name__ == '__main__':
    unittest.main()
