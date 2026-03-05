"""Unit tests for PluginLoader."""

from unittest.mock import patch, MagicMock

from reversecore_mcp.core.loader import PluginLoader
from reversecore_mcp.core.plugin import Plugin


class _StubPlugin(Plugin):
    @property
    def name(self) -> str:
        return "stub"

    def register(self, mcp_server) -> None:
        pass


class TestPluginLoader:
    """Tests for PluginLoader."""

    def test_init_empty_plugins(self):
        loader = PluginLoader()
        assert loader.get_all_plugins() == []
        assert loader.get_plugin("nonexistent") is None

    def test_discover_plugins_skips_init_modules(self):
        """walk_packages yields modules; we skip those ending with .__init__."""
        loader = PluginLoader()
        with patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk:
            walk.return_value = [
                (None, "reversecore_mcp.tools.__init__", True),
                (None, "reversecore_mcp.tools.analysis.__init__", True),
            ]
            with patch("importlib.import_module") as imp:
                result = loader.discover_plugins("/fake/path")
            assert result == []
            imp.assert_not_called()

    def test_discover_plugins_handles_import_error(self):
        """Failed import is logged and iteration continues."""
        loader = PluginLoader()
        with patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk:
            walk.return_value = [(None, "reversecore_mcp.tools.bad_module", False)]
            with patch("importlib.import_module", side_effect=ImportError("No module")):
                result = loader.discover_plugins("/fake/path")
            assert result == []

    def test_get_plugin_and_get_all_plugins(self):
        """get_plugin and get_all_plugins return manually registered plugin."""
        loader = PluginLoader()
        p = _StubPlugin()
        loader._plugins["stub"] = p
        assert loader.get_plugin("stub") is p
        assert loader.get_plugin("stub").name == "stub"
        assert loader.get_all_plugins() == [p]
        assert loader.get_plugin("nonexistent") is None
