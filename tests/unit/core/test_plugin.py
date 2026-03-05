"""Unit tests for Plugin interface and Tool."""

from reversecore_mcp.core.plugin import Plugin, Tool


class ConcretePlugin(Plugin):
    """Concrete plugin for testing."""

    @property
    def name(self) -> str:
        return "concrete_test"

    @property
    def description(self) -> str:
        return "A test plugin description"

    def register(self, mcp_server) -> None:
        mcp_server.tool(lambda: None, name="test_tool")


class TestTool:
    """Tests for Tool model."""

    def test_tool_creation(self):
        def dummy():
            pass

        t = Tool(name="dummy", description="A dummy tool", func=dummy)
        assert t.name == "dummy"
        assert t.description == "A dummy tool"
        assert t.func is dummy
        assert t.parameters is None

    def test_tool_with_parameters(self):
        t = Tool(name="n", description="d", func=lambda: None, parameters={"type": "object"})
        assert t.parameters == {"type": "object"}


class TestPlugin:
    """Tests for Plugin base and concrete implementation."""

    def test_concrete_plugin_name(self):
        p = ConcretePlugin()
        assert p.name == "concrete_test"

    def test_concrete_plugin_description(self):
        p = ConcretePlugin()
        assert p.description == "A test plugin description"

    def test_concrete_plugin_register(self):
        p = ConcretePlugin()
        mock_server = type("MCP", (), {"tool": lambda self, fn, name=None: None})()
        p.register(mock_server)  # no raise
