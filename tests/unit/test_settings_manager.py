"""
Unit tests for context-based settings manager.
"""

import pytest
import asyncio
from pathlib import Path
from reversecore_mcp.core.settings_manager import (
    SettingsManager,
    get_settings,
    set_settings,
    clear_settings,
)
from reversecore_mcp.core.config import Settings


class TestSettingsManager:
    """Tests for SettingsManager."""
    
    def setup_method(self):
        """Clear settings before each test."""
        clear_settings()
    
    def teardown_method(self):
        """Clear settings after each test."""
        clear_settings()
    
    def test_get_creates_default_settings(self):
        """Test that get() creates default settings when none exist."""
        settings = SettingsManager.get()
        assert isinstance(settings, Settings)
        # Settings are configured in conftest for tests
        assert settings.reversecore_workspace.name == "workspace"
    
    def test_get_returns_same_instance(self):
        """Test that get() returns the same instance within a context."""
        settings1 = SettingsManager.get()
        settings2 = SettingsManager.get()
        assert settings1 is settings2
    
    def test_set_and_get(self):
        """Test setting and getting custom settings."""
        custom_settings = Settings(
            reversecore_workspace=Path("/custom/workspace")
        )
        SettingsManager.set(custom_settings)
        
        retrieved = SettingsManager.get()
        assert retrieved is custom_settings
        assert retrieved.reversecore_workspace == Path("/custom/workspace")
    
    def test_clear_removes_settings(self):
        """Test that clear() removes current settings."""
        custom_settings = Settings(
            reversecore_workspace=Path("/custom/workspace")
        )
        SettingsManager.set(custom_settings)
        
        SettingsManager.clear()
        
        # Getting after clear should create new default settings
        new_settings = SettingsManager.get()
        assert new_settings is not custom_settings
        # Default settings are configured by conftest in tests
        assert new_settings.reversecore_workspace.name == "workspace"
    
    @pytest.mark.asyncio
    async def test_with_settings_context_manager(self, tmp_path):
        """Test with_settings context manager."""
        # Set initial settings
        initial_settings = Settings(
            reversecore_workspace=Path("/initial")
        )
        SettingsManager.set(initial_settings)
        
        # Use context manager with different settings
        custom_settings = Settings(
            reversecore_workspace=tmp_path / "custom"
        )
        
        async with SettingsManager.with_settings(custom_settings):
            # Inside context, should use custom settings
            current = SettingsManager.get()
            assert current is custom_settings
            assert current.reversecore_workspace == tmp_path / "custom"
        
        # Outside context, should restore initial settings
        restored = SettingsManager.get()
        assert restored is initial_settings
        assert restored.reversecore_workspace == Path("/initial")
    
    @pytest.mark.asyncio
    async def test_with_settings_nesting(self, tmp_path):
        """Test nested with_settings contexts."""
        settings1 = Settings(reversecore_workspace=Path("/path1"))
        settings2 = Settings(reversecore_workspace=Path("/path2"))
        settings3 = Settings(reversecore_workspace=Path("/path3"))
        
        SettingsManager.set(settings1)
        
        async with SettingsManager.with_settings(settings2):
            assert SettingsManager.get() is settings2
            
            async with SettingsManager.with_settings(settings3):
                assert SettingsManager.get() is settings3
            
            # After inner context, should be back to settings2
            assert SettingsManager.get() is settings2
        
        # After all contexts, should be back to settings1
        assert SettingsManager.get() is settings1
    
    @pytest.mark.asyncio
    async def test_concurrent_contexts(self, tmp_path):
        """Test that different async contexts have independent settings."""
        results = []
        
        async def task_with_settings(workspace: Path):
            """Task that uses specific settings."""
            custom_settings = Settings(reversecore_workspace=workspace)
            async with SettingsManager.with_settings(custom_settings):
                # Simulate some async work
                await asyncio.sleep(0.01)
                # Verify settings are still correct
                current = SettingsManager.get()
                results.append(current.reversecore_workspace)
        
        # Run multiple tasks concurrently with different settings
        workspaces = [tmp_path / f"ws{i}" for i in range(5)]
        await asyncio.gather(
            *[task_with_settings(ws) for ws in workspaces]
        )
        
        # Each task should have seen its own workspace
        assert len(results) == 5
        # Results may be in different order due to concurrency
        assert set(results) == set(workspaces)


class TestBackwardCompatibleAPI:
    """Tests for backward compatible API functions."""
    
    def setup_method(self):
        """Clear settings before each test."""
        clear_settings()
    
    def teardown_method(self):
        """Clear settings after each test."""
        clear_settings()
    
    def test_get_settings_function(self):
        """Test get_settings() function."""
        settings = get_settings()
        assert isinstance(settings, Settings)
    
    def test_set_settings_function(self):
        """Test set_settings() function."""
        custom_settings = Settings(
            reversecore_workspace=Path("/custom")
        )
        set_settings(custom_settings)
        
        retrieved = get_settings()
        assert retrieved is custom_settings
    
    def test_clear_settings_function(self):
        """Test clear_settings() function."""
        custom_settings = Settings(
            reversecore_workspace=Path("/custom")
        )
        set_settings(custom_settings)
        
        clear_settings()
        
        new_settings = get_settings()
        assert new_settings is not custom_settings


class TestMultiTenantScenario:
    """Tests for multi-tenant scenarios."""
    
    def setup_method(self):
        """Clear settings before each test."""
        clear_settings()
    
    def teardown_method(self):
        """Clear settings after each test."""
        clear_settings()
    
    @pytest.mark.asyncio
    async def test_different_clients_different_workspaces(self, tmp_path):
        """Test that different clients can have different workspaces."""
        client1_workspace = tmp_path / "client1"
        client2_workspace = tmp_path / "client2"
        
        client1_workspace.mkdir()
        client2_workspace.mkdir()
        
        results = {}
        
        async def process_for_client(client_id: str, workspace: Path):
            """Process request for a specific client."""
            client_settings = Settings(reversecore_workspace=workspace)
            async with SettingsManager.with_settings(client_settings):
                await asyncio.sleep(0.01)  # Simulate work
                current = SettingsManager.get()
                results[client_id] = current.reversecore_workspace
        
        # Process requests for different clients concurrently
        await asyncio.gather(
            process_for_client("client1", client1_workspace),
            process_for_client("client2", client2_workspace),
        )
        
        # Each client should have seen their own workspace
        assert results["client1"] == client1_workspace
        assert results["client2"] == client2_workspace


class TestTestIsolation:
    """Tests to verify proper test isolation."""
    
    def test_isolation_test1(self):
        """First test that modifies settings."""
        settings1 = Settings(reversecore_workspace=Path("/test1"))
        set_settings(settings1)
        assert get_settings().reversecore_workspace == Path("/test1")
        # Cleanup
        clear_settings()
    
    def test_isolation_test2(self):
        """Second test that should not see test1's settings."""
        # Should get default settings (from conftest), not test1's settings
        settings = get_settings()
        # Default settings from conftest use tmp_path/workspace
        assert settings.reversecore_workspace.name == "workspace"
        # Cleanup
        clear_settings()
    
    def test_isolation_test3(self):
        """Third test to verify test1 and test2 didn't affect it."""
        settings = get_settings()
        # Default settings from conftest use tmp_path/workspace
        assert settings.reversecore_workspace.name == "workspace"
        # Cleanup
        clear_settings()
