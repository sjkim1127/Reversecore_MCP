"""
Plugin loader for dynamically discovering and loading plugins.
"""

import importlib
import inspect
import pkgutil

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


TOOL_PROFILES: dict[str, set[str]] = {
    "full": {
        "analysis_tools",
        "source_auditor",
        "common_tools",
        "memory_tools",
        "server_tools",
        "cve_hunter_tools",
        "deobfuscation_tools",
        "forensics_tools",
        "malware_tools",
        "radare2_mcp_tools",
        "report_tools",
    },
    "static": {
        "common_tools",
        "server_tools",
        "analysis_tools",
        "radare2_mcp_tools",
        "report_tools",
    },
    "malware": {
        "common_tools",
        "server_tools",
        "malware_tools",
        "analysis_tools",
        "deobfuscation_tools",
        "report_tools",
    },
    "forensics": {
        "common_tools",
        "server_tools",
        "forensics_tools",
        "memory_tools",
        "report_tools",
    },
    "vuln-research": {
        "common_tools",
        "server_tools",
        "cve_hunter_tools",
        "analysis_tools",
        "radare2_mcp_tools",
        "source_auditor",
        "report_tools",
    },
}
# Alias
TOOL_PROFILES["vuln_research"] = TOOL_PROFILES["vuln-research"]


# Manifest mapping module prefixes to plugin names for pre-import filtering.
# Prevents importing unnecessary dependencies and running import-time side effects
# for plugins excluded by the active profile.
MODULE_TO_PLUGIN_NAME: dict[str, str] = {
    "reversecore_mcp.tools.analysis.source_auditor": "source_auditor",
    "reversecore_mcp.tools.analysis": "analysis_tools",
    "reversecore_mcp.tools.common.memory_tools": "memory_tools",
    "reversecore_mcp.tools.common.server_tools": "server_tools",
    "reversecore_mcp.tools.common": "common_tools",
    "reversecore_mcp.tools.cve_hunter": "cve_hunter_tools",
    "reversecore_mcp.tools.deobfuscation": "deobfuscation_tools",
    "reversecore_mcp.tools.forensics": "forensics_tools",
    "reversecore_mcp.tools.malware": "malware_tools",
    "reversecore_mcp.tools.radare2": "radare2_mcp_tools",
    "reversecore_mcp.tools.report": "report_tools",
}


class PluginLoader:
    """Responsible for discovering and loading plugins."""

    def __init__(self, profile: str | None = None):
        self._plugins: dict[str, Plugin] = {}
        self._profile = profile

    def is_plugin_allowed(self, plugin_name: str, profile: str | None = None) -> bool:
        """Check if a plugin is allowed under the active or given tool profile."""
        active_profile = profile or self._profile
        if active_profile is None:
            try:
                from reversecore_mcp.core.config import get_config

                active_profile = get_config().tool_profile
            except Exception:
                active_profile = "full"

        normalized = active_profile.strip().lower() if active_profile else "full"
        if normalized in ("full", "*", "", "all"):
            return True

        if normalized in TOOL_PROFILES:
            return plugin_name.lower() in TOOL_PROFILES[normalized]

        # Comma-separated list of plugin names
        allowed = {p.strip().lower() for p in normalized.split(",") if p.strip()}
        return plugin_name.lower() in allowed

    def is_module_allowed(self, module_name: str, profile: str | None = None) -> bool:
        """Check if a module should be imported based on module manifest and active profile."""
        for prefix in sorted(MODULE_TO_PLUGIN_NAME.keys(), key=len, reverse=True):
            if module_name == prefix or module_name.startswith(f"{prefix}."):
                plugin_name = MODULE_TO_PLUGIN_NAME[prefix]
                return self.is_plugin_allowed(plugin_name, profile=profile)
        return True

    def discover_plugins(
        self,
        package_path: str,
        package_name: str = "reversecore_mcp.tools",
        profile: str | None = None,
    ) -> list[Plugin]:
        """
        Discover and load plugins from a package directory (including subdirectories).

        Args:
            package_path: Absolute path to the package directory
            package_name: Python package name prefix
            profile: Optional tool profile override ('full', 'static', 'malware', etc.)

        Returns:
            List of instantiated Plugin objects
        """
        logger.info(f"Discovering plugins in {package_path}")

        discovered_plugins = []

        # Use walk_packages to recursively iterate over all modules including subdirectories
        for _importer, name, _is_pkg in pkgutil.walk_packages(
            [package_path], prefix=f"{package_name}."
        ):
            # Skip __init__ modules and __pycache__ directories
            if name.endswith(".__init__") or "__pycache__" in name:
                continue

            # Pre-import check: avoid importing heavy modules that are excluded by profile
            if not self.is_module_allowed(name, profile=profile):
                logger.debug(f"Skipping module import {name}: excluded by active profile")
                continue

            try:
                module = importlib.import_module(name)

                # Find Plugin subclasses in the module
                for item_name, item in inspect.getmembers(module):
                    if inspect.isclass(item) and issubclass(item, Plugin) and item is not Plugin:
                        try:
                            # Instantiate the plugin
                            plugin_instance = item()
                            if plugin_instance.name in self._plugins:
                                logger.debug(
                                    f"Plugin {plugin_instance.name} already loaded, skipping duplicate registration"
                                )
                                continue

                            if not self.is_plugin_allowed(plugin_instance.name, profile=profile):
                                logger.debug(
                                    f"Plugin {plugin_instance.name} skipped: not included in profile"
                                )
                                continue

                            self._plugins[plugin_instance.name] = plugin_instance
                            discovered_plugins.append(plugin_instance)
                            logger.info(f"Loaded plugin: {plugin_instance.name}")
                        except Exception as e:
                            logger.error(f"Failed to instantiate plugin {item_name}: {e}")

            except ImportError as e:
                logger.warning(f"Failed to import module {name}: {e}")
                continue

        return discovered_plugins

    def get_plugin(self, name: str) -> Plugin | None:
        """Get a loaded plugin by name."""
        return self._plugins.get(name)

    def get_all_plugins(self) -> list[Plugin]:
        """Get all loaded plugins."""
        return list(self._plugins.values())
