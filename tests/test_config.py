"""Tests for configuration management."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from aibughunter.config.manager import (
    ConfigManager,
    AIHuntSettings,
    QwenConfig,
    ScanConfig,
    ToolConfig,
    ReportConfig,
    ScopeConfig,
)


@pytest.fixture
def config_manager(tmp_path):
    """Create a config manager with temporary directory."""
    with patch.object(ConfigManager, "_instance", None):
        manager = ConfigManager()
        manager._config_file = tmp_path / "config.json"
        return manager


class TestAIHuntSettings:
    """Test settings model."""
    
    def test_default_settings(self):
        """Test default settings are reasonable."""
        settings = AIHuntSettings()
        
        assert settings.qwen.api_url == "http://localhost:8080"
        assert settings.qwen.model == "qwen-coder-plus"
        assert settings.scan.max_concurrent_scans == 5
        assert settings.scan.rate_limit == 0.1
        assert settings.reports.default_format == "markdown"
        assert settings.tools.auto_install is True
    
    def test_settings_from_env(self):
        """Test settings can be overridden by environment."""
        import os
        os.environ["AIBH_QWEN_MODEL"] = "test-model"
        
        try:
            settings = AIHuntSettings()
            assert settings.qwen.model == "test-model"
        finally:
            del os.environ["AIBH_QWEN_MODEL"]


class TestConfigManager:
    """Test configuration manager."""
    
    def test_singleton_pattern(self):
        """Test ConfigManager is a singleton."""
        with patch.object(ConfigManager, "_instance", None):
            manager1 = ConfigManager()
            manager2 = ConfigManager.load()
            assert manager1 is manager2
    
    def test_get_default_value(self, config_manager):
        """Test getting default values."""
        value = config_manager.get("qwen-model")
        assert value == "qwen-coder-plus"
    
    def test_set_and_get_override(self, config_manager):
        """Test setting and getting overrides."""
        config_manager.set("custom-setting", "custom-value")
        assert config_manager.get("custom-setting") == "custom-value"
    
    def test_save_and_load(self, config_manager):
        """Test saving and loading configuration."""
        config_manager.set("test-key", "test-value")
        config_manager.save()
        
        # Load fresh instance
        with patch.object(ConfigManager, "_instance", None):
            new_manager = ConfigManager()
            new_manager._config_file = config_manager._config_file
            new_manager._load_from_file()
            
            assert new_manager.get("test-key") == "test-value"
    
    def test_reset(self, config_manager):
        """Test reset clears overrides."""
        config_manager.set("key1", "value1")
        config_manager.reset()
        assert config_manager.get("key1", "default") == "default"
    
    def test_display_items(self, config_manager):
        """Test display returns items."""
        items = config_manager.display_items()
        assert isinstance(items, list)
        assert len(items) > 0
        
        # Should have key-value tuples
        for item in items:
            assert isinstance(item, tuple)
            assert len(item) == 2
    
    def test_get_source(self, config_manager):
        """Test source reporting."""
        config_manager.set("custom", "value")
        assert config_manager.get_source("custom") == "user"
        assert config_manager.get_source("qwen-model") == "default"
    
    def test_load_from_nonexistent_file(self, config_manager):
        """Test loading from missing file."""
        config_manager._config_file = Path("/nonexistent/config.json")
        config_manager._load_from_file()  # Should not raise
        assert config_manager._overrides == {}
    
    def test_save_creates_directory(self, config_manager, tmp_path):
        """Test save creates parent directories."""
        config_file = tmp_path / "nested" / "dir" / "config.json"
        config_manager._config_file = config_file
        
        config_manager.set("key", "value")
        config_manager.save()
        
        assert config_file.exists()
