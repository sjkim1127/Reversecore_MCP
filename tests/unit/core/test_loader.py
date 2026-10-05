"""Unit tests for PluginLoader."""

from unittest.mock import patch

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

    def test_discover_plugins_instantiation_failure(self):
        """Plugin class instantiation throws exception, loader continues."""
        loader = PluginLoader()

        class BadPlugin(Plugin):
            @property
            def name(self) -> str:
                return "bad"

            def register(self, mcp_server) -> None:
                pass

            def __init__(self):
                raise ValueError("Oops, failed to initialize")

        with patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk:
            walk.return_value = [(None, "reversecore_mcp.tools.faulty", False)]

            class DummyModule:
                pass

            dummy_module = DummyModule()
            dummy_module.BadPlugin = BadPlugin

            with patch("importlib.import_module", return_value=dummy_module):
                result = loader.discover_plugins("/fake/path")

        assert result == []
        assert loader.get_plugin("bad") is None

    def test_discover_plugins_success(self):
        """Plugin class instantiation succeeds, loader registers it."""
        loader = PluginLoader()

        class GoodPlugin(Plugin):
            @property
            def name(self) -> str:
                return "good"

            def register(self, mcp_server) -> None:
                pass

        with patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk:
            walk.return_value = [(None, "reversecore_mcp.tools.good_module", False)]

            class DummyModule:
                pass

            dummy_module = DummyModule()
            dummy_module.GoodPlugin = GoodPlugin

            with patch("importlib.import_module", return_value=dummy_module):
                result = loader.discover_plugins("/fake/path")

        assert len(result) == 1
        assert result[0].name == "good"
        assert loader.get_plugin("good") is result[0]

    def test_discover_plugins_isolates_unexpected_import_exception(self):
        """Unexpected runtime/syntax error in one module does not abort discovery of others (Issue #269)."""
        loader = PluginLoader()

        class WorkingPlugin(Plugin):
            @property
            def name(self) -> str:
                return "working"

            def register(self, mcp_server) -> None:
                pass

        class DummyGoodModule:
            WorkingPluginClass = WorkingPlugin

        def fake_import_module(mod_name):
            if mod_name == "reversecore_mcp.tools.broken_module":
                raise RuntimeError("Catastrophic module initialization error")
            if mod_name == "reversecore_mcp.tools.working_module":
                return DummyGoodModule()
            raise ImportError(f"No module named {mod_name}")

        with patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk:
            walk.return_value = [
                (None, "reversecore_mcp.tools.broken_module", False),
                (None, "reversecore_mcp.tools.working_module", False),
            ]
            with patch("importlib.import_module", side_effect=fake_import_module):
                result = loader.discover_plugins("/fake/path")

        # Broken module recorded in failed_modules
        assert "reversecore_mcp.tools.broken_module" in loader.failed_modules
        assert "Catastrophic" in loader.failed_modules["reversecore_mcp.tools.broken_module"]

        # Working module still discovered despite the previous failure
        assert len(result) == 1
        assert result[0].name == "working"
        assert loader.get_plugin("working") is not None

    def test_failed_modules_property_returns_copy(self):
        """failed_modules should return a copy of internal dictionary."""
        loader = PluginLoader()
        loader._failed_modules["mod.a"] = "err a"
        res = loader.failed_modules
        res["mod.b"] = "err b"
        assert "mod.b" not in loader.failed_modules
