import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import asyncio
import pytest

# Save original modules to restore after tests
_original_modules = {}
_mocked_module_names = [
    "fastmcp",
    "fastmcp.Context",
    "dotenv",
    "pydantic",
    "pydantic.BaseModel",
]

for name in _mocked_module_names:
    if name in sys.modules:
        _original_modules[name] = sys.modules[name]

# Mock fastmcp before importing ghost_trace
sys.modules["fastmcp"] = MagicMock()
sys.modules["fastmcp.Context"] = MagicMock()
sys.modules["dotenv"] = MagicMock()
sys.modules["pydantic"] = MagicMock()
sys.modules["pydantic.BaseModel"] = MagicMock()

from reversecore_mcp.tools.ghost_trace import ghost_trace


@pytest.fixture(scope="module", autouse=True)
def cleanup_mocked_modules():
    """Ensure mocked modules are cleaned up after this test module."""
    yield
    # Clean up mocked modules
    for name in _mocked_module_names:
        if name in sys.modules and isinstance(sys.modules[name], MagicMock):
            del sys.modules[name]
    # Restore original modules
    for name, module in _original_modules.items():
        sys.modules[name] = module

class TestGhostTrace(unittest.IsolatedAsyncioTestCase):
    
    async def test_ghost_trace_discovery(self):
        """Test Ghost Trace in discovery mode (scanning for orphans and logic bombs)."""
        
        # Mock execute_subprocess_async to return simulated r2 output
        with patch("reversecore_mcp.tools.ghost_trace.execute_subprocess_async", new_callable=AsyncMock) as mock_exec:
            # Mock output for 'aaa; aflj'
            functions_json = [
                {
                    "name": "main",
                    "offset": 4096,
                    "size": 100,
                    "codexrefs": [{"addr": 0x1000, "type": "CALL"}] # Referenced
                },
                {
                    "name": "orphan_func",
                    "offset": 8192,
                    "size": 200,
                    "codexrefs": [] # No references -> Orphan
                }
            ]
            
            # Mock output for 'pdfj @ 8192' (orphan_func)
            ops_json = {
                "ops": [
                    {"offset": 8192, "disasm": "push ebp"},
                    {"offset": 8193, "disasm": "mov ebp, esp"},
                    {"offset": 8200, "disasm": "cmp eax, 0xCAFEBABE"}, # Magic value!
                    {"offset": 8205, "disasm": "je 0xdeadbeef"}
                ]
            }
            
            # Configure mock side effects
            async def side_effect(cmd, timeout=30):
                cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
                if "aflj" in cmd_str:
                    return str(functions_json).replace("'", '"'), ""
                if "pdfj" in cmd_str:
                    return str(ops_json).replace("'", '"'), ""
                return "{}", ""
                
            mock_exec.side_effect = side_effect
            
            # Run tool
            result = await ghost_trace(file_path="/tmp/test_binary")
            
            # Verify results
            self.assertFalse(result.is_error)
            data = result.content[0].text
            self.assertIn("orphan_func", str(data))
            self.assertIn("0xCAFEBABE", str(data))
            self.assertIn("discovery", str(data))

    async def test_ghost_trace_emulation(self):
        """Test Ghost Trace in emulation mode."""
        
        with patch("reversecore_mcp.tools.ghost_trace.execute_subprocess_async", new_callable=AsyncMock) as mock_exec:
            # Mock final registers (aerj output)
            final_regs = {"eax": 0x1234, "ebx": 0}
            
            async def side_effect(cmd, timeout=30):
                cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
                if "aerj" in cmd_str:
                    return str(final_regs).replace("'", '"'), ""
                return "", ""
                
            mock_exec.side_effect = side_effect
            
            # Run tool
            hypothesis = {
                "registers": {"eax": "0xCAFEBABE"},
                "max_steps": 50
            }
            
            result = await ghost_trace(
                file_path="/tmp/test_binary",
                focus_function="orphan_func",
                hypothesis=hypothesis
            )
            
            # Verify results
            self.assertFalse(result.is_error)
            self.assertIn("emulation_complete", str(result.content[0].text))
            self.assertIn("1234", str(result.content[0].text))

if __name__ == '__main__':
    unittest.main()
