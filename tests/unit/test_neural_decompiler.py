import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import pytest

# Save original modules to restore after tests
_original_modules = {}
_mocked_module_names = [
    "fastmcp",
    "fastmcp.Context",
    "reversecore_mcp.core.logging_config",
    "reversecore_mcp.core.result",
    "reversecore_mcp.core.decorators",
    "reversecore_mcp.core.security",
    "reversecore_mcp.core",
]

for name in _mocked_module_names:
    if name in sys.modules:
        _original_modules[name] = sys.modules[name]

# Mock dependencies
sys.modules["fastmcp"] = MagicMock()
sys.modules["fastmcp.Context"] = MagicMock()
sys.modules["reversecore_mcp.core.logging_config"] = MagicMock()
sys.modules["reversecore_mcp.core.result"] = MagicMock()
sys.modules["reversecore_mcp.core.decorators"] = MagicMock()
sys.modules["reversecore_mcp.core.security"] = MagicMock()
sys.modules["reversecore_mcp.core"] = MagicMock()

# Mock decorators
def log_execution(tool_name):
    def decorator(func):
        return func
    return decorator
sys.modules["reversecore_mcp.core.decorators"].log_execution = log_execution

# Mock result helpers
def success(data):
    return data
def failure(msg):
    return {"error": msg}
sys.modules["reversecore_mcp.core.result"].success = success
sys.modules["reversecore_mcp.core.result"].failure = failure

# Import tool
from reversecore_mcp.tools.neural_decompiler import _refine_code, neural_decompile


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

class TestNeuralDecompiler(unittest.IsolatedAsyncioTestCase):
    
    def test_refine_code_socket(self):
        """Test variable renaming for socket API."""
        raw_code = """
        void func() {
            int iVar1;
            iVar1 = socket(2, 1, 0);
            if (iVar1 < 0) return;
            connect(iVar1, addr, 16);
        }
        """
        refined = _refine_code(raw_code)
        self.assertIn("sock_fd = socket", refined)
        self.assertIn("connect(sock_fd", refined)
        self.assertIn("Renamed from iVar1", refined)

    def test_refine_code_structure(self):
        """Test structure inference from pointer arithmetic."""
        raw_code = """
        void func(void *ptr) {
            *(int *)(ptr + 4) = 100;
            *(long *)(ptr + 0x10) = 200;
        }
        """
        refined = _refine_code(raw_code)
        self.assertIn("ptr->field_4 = 100", refined)
        self.assertIn("ptr->field_0x10 = 200", refined)

    def test_refine_code_magic(self):
        """Test magic value annotation."""
        raw_code = """
        if (val == 0xCAFEBABE) {
            return;
        }
        """
        refined = _refine_code(raw_code)
        self.assertIn("0xCAFEBABE /* Magic Value */", refined)

    def test_unique_variable_naming(self):
        """Test that multiple variables using same API get unique names."""
        raw_code = """
        void func() {
            int fd1 = socket(2, 1, 0);
            int fd2 = socket(2, 1, 0);
            connect(fd1, addr1, 16);
            connect(fd2, addr2, 16);
        }
        """
        refined = _refine_code(raw_code)
        # First socket should be sock_fd, second should be sock_fd_2
        self.assertIn("sock_fd =", refined)
        self.assertIn("sock_fd_2 =", refined)
        # Both should be renamed in connect calls
        self.assertIn("connect(sock_fd,", refined)
        self.assertIn("connect(sock_fd_2,", refined)

    async def test_neural_decompile_tool(self):
        """Test the main tool function."""
        # Mock ghidra helper
        with patch("reversecore_mcp.core.ghidra_helper.decompile_function_with_ghidra") as mock_decomp:
            mock_decomp.return_value = ("iVar1 = socket(2,1,0);", {})
            
            result = await neural_decompile("/tmp/test", "main")
            
            self.assertIn("neural_code", result)
            self.assertIn("sock_fd", result["neural_code"])

if __name__ == '__main__':
    unittest.main()
