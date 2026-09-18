"""Unit tests for tool profile architecture and PluginLoader profile filtering."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from reversecore_mcp.core.loader import MODULE_TO_PLUGIN_NAME, TOOL_PROFILES, PluginLoader
from reversecore_mcp.core.plugin import Plugin


class _DummyPlugin(Plugin):
    def __init__(self, name: str):
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def register(self, mcp_server) -> None:
        pass


class TestToolProfiles:
    """Test tool profile definitions and loader filtering."""

    def test_standard_profiles_exist(self):
        """Standard profiles must exist and contain core tools."""
        assert "full" in TOOL_PROFILES
        assert "static" in TOOL_PROFILES
        assert "malware" in TOOL_PROFILES
        assert "forensics" in TOOL_PROFILES
        assert "vuln-research" in TOOL_PROFILES
        assert "vuln_research" in TOOL_PROFILES

        # server_tools and common_tools must be in all standard profiles
        for prof in ("static", "malware", "forensics", "vuln-research"):
            assert "server_tools" in TOOL_PROFILES[prof]
            assert "common_tools" in TOOL_PROFILES[prof]

    def test_full_profile_allows_all(self):
        """Full profile allows all plugins unconditionally."""
        loader = PluginLoader(profile="full")
        assert loader.is_plugin_allowed("any_plugin_name") is True
        assert loader.is_plugin_allowed("custom_tool") is True
        assert loader.is_plugin_allowed("malware_tools") is True

    def test_static_profile_filtering(self):
        """Static profile permits only static analysis tools."""
        loader = PluginLoader(profile="static")
        assert loader.is_plugin_allowed("radare2_mcp_tools") is True
        assert loader.is_plugin_allowed("analysis_tools") is True
        assert loader.is_plugin_allowed("report_tools") is True
        assert loader.is_plugin_allowed("malware_tools") is False
        assert loader.is_plugin_allowed("forensics_tools") is False

    def test_malware_profile_filtering(self):
        """Malware profile permits malware analysis tools."""
        loader = PluginLoader(profile="malware")
        assert loader.is_plugin_allowed("malware_tools") is True
        assert loader.is_plugin_allowed("deobfuscation_tools") is True
        assert loader.is_plugin_allowed("analysis_tools") is True
        assert loader.is_plugin_allowed("cve_hunter_tools") is False

    def test_forensics_profile_filtering(self):
        """Forensics profile permits forensics tools."""
        loader = PluginLoader(profile="forensics")
        assert loader.is_plugin_allowed("forensics_tools") is True
        assert loader.is_plugin_allowed("memory_tools") is True
        assert loader.is_plugin_allowed("radare2_mcp_tools") is False

    def test_vuln_research_profile_filtering(self):
        """Vuln research profile permits CVE hunting and fuzzing tools."""
        loader = PluginLoader(profile="vuln-research")
        assert loader.is_plugin_allowed("cve_hunter_tools") is True
        assert loader.is_plugin_allowed("source_auditor") is True
        assert loader.is_plugin_allowed("radare2_mcp_tools") is True
        assert loader.is_plugin_allowed("forensics_tools") is False

    def test_custom_comma_separated_profile(self):
        """Comma-separated plugin list allows only the specified plugins."""
        loader = PluginLoader(profile="malware_tools, report_tools")
        assert loader.is_plugin_allowed("malware_tools") is True
        assert loader.is_plugin_allowed("report_tools") is True
        assert loader.is_plugin_allowed("radare2_mcp_tools") is False

    def test_profile_resolution_from_config(self, patched_config):
        """Loader reads profile from config when not passed explicitly."""
        patched_config._settings.tool_profile = "static"
        loader = PluginLoader()
        assert loader.is_plugin_allowed("radare2_mcp_tools") is True
        assert loader.is_plugin_allowed("malware_tools") is False

    def test_discover_plugins_with_profile_filter(self):
        """discover_plugins excludes plugins not allowed by profile."""
        loader = PluginLoader(profile="static")

        class StaticPlugin(Plugin):
            @property
            def name(self) -> str:
                return "analysis_tools"

            def register(self, mcp_server) -> None:
                pass

        class MalwarePlugin(Plugin):
            @property
            def name(self) -> str:
                return "malware_tools"

            def register(self, mcp_server) -> None:
                pass

        with patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk:
            walk.return_value = [
                (None, "reversecore_mcp.tools.analysis", False),
                (None, "reversecore_mcp.tools.malware", False),
            ]

            class DummyModuleStatic:
                P1 = StaticPlugin

            class DummyModuleMalware:
                P2 = MalwarePlugin

            def fake_import(name):
                if "analysis" in name:
                    return DummyModuleStatic()
                return DummyModuleMalware()

            with patch("importlib.import_module", side_effect=fake_import):
                discovered = loader.discover_plugins("/fake/path")

        assert len(discovered) == 1
        assert discovered[0].name == "analysis_tools"
        assert loader.get_plugin("analysis_tools") is not None
        assert loader.get_plugin("malware_tools") is None

    def test_is_module_allowed_manifest(self):
        """is_module_allowed correctly consults MODULE_TO_PLUGIN_NAME and profile."""
        loader = PluginLoader(profile="static")
        # Allowed in static
        assert loader.is_module_allowed("reversecore_mcp.tools.analysis.diff_tools") is True
        assert loader.is_module_allowed("reversecore_mcp.tools.radare2.r2_analysis") is True
        # Excluded in static
        assert loader.is_module_allowed("reversecore_mcp.tools.malware.yara_tools") is False
        assert loader.is_module_allowed("reversecore_mcp.tools.forensics.memory") is False
        assert (
            loader.is_module_allowed("reversecore_mcp.tools.cve_hunter.asan_crash_triager") is False
        )
        # Unknown/test module outside manifest should be allowed
        assert loader.is_module_allowed("reversecore_mcp.tools.custom_vendor.new_tool") is True

    def test_pre_import_skipping_prevents_unneeded_imports(self):
        """Modules excluded by profile must NOT be imported via importlib."""
        loader = PluginLoader(profile="static")
        imported_modules = []

        def track_import(name):
            imported_modules.append(name)
            m = MagicMock()
            m.TestPlugin = Plugin
            return m

        with (
            patch("reversecore_mcp.core.loader.pkgutil.walk_packages") as walk,
            patch("importlib.import_module", side_effect=track_import),
        ):
            walk.return_value = [
                (None, "reversecore_mcp.tools.analysis.cache", False),
                (None, "reversecore_mcp.tools.malware.dormant", False),
                (None, "reversecore_mcp.tools.forensics.disk", False),
            ]
            loader.discover_plugins("/fake/path")

        assert "reversecore_mcp.tools.analysis.cache" in imported_modules
        assert "reversecore_mcp.tools.malware.dormant" not in imported_modules
        assert "reversecore_mcp.tools.forensics.disk" not in imported_modules

    def test_all_real_plugins_mapped_in_manifest(self):
        """Contract: Every real plugin discovered in reversecore_mcp.tools must be mapped in MODULE_TO_PLUGIN_NAME."""
        tools_dir = (
            Path(__file__).resolve().parent.parent.parent.parent / "reversecore_mcp" / "tools"
        )
        loader = PluginLoader(profile="full")
        plugins = loader.discover_plugins(str(tools_dir), "reversecore_mcp.tools")
        mapped_plugin_names = set(MODULE_TO_PLUGIN_NAME.values())

        for plugin in plugins:
            assert plugin.name in mapped_plugin_names, (
                f"Plugin '{plugin.name}' was discovered but is missing from MODULE_TO_PLUGIN_NAME manifest. "
                f"Register its module prefix in MODULE_TO_PLUGIN_NAME to ensure pre-import profile isolation."
            )
