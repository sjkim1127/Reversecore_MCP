"""
Plugin loader for dynamically discovering and loading plugins.
"""

import importlib
import inspect
import pkgutil

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class PluginLoader:
    """Responsible for discovering and loading plugins."""

    def __init__(self):
        self._plugins: dict[str, Plugin] = {}

    def discover_plugins(
        self, package_path: str, package_name: str = "reversecore_mcp.tools"
    ) -> list[Plugin]:
        """
        Discover and load plugins from a package directory (including subdirectories).

        Args:
            package_path: Absolute path to the package directory
            package_name: Python package name prefix

        Returns:
            List of instantiated Plugin objects
        """
        logger.info(f"Discovering plugins in {package_path}")

        discovered_plugins = []

        # Use walk_packages to recursively iterate over all modules including subdirectories
        for importer, name, is_pkg in pkgutil.walk_packages(
            [package_path], prefix=f"{package_name}."
        ):
            # Skip __init__ modules and __pycache__ directories
            if name.endswith(".__init__") or "__pycache__" in name:
                continue

            try:
                module = importlib.import_module(name)

                # Find Plugin subclasses in the module
                for item_name, item in inspect.getmembers(module):
                    if inspect.isclass(item) and issubclass(item, Plugin) and item is not Plugin:
                        try:
                            # Instantiate the plugin
                            plugin_instance = item()
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
