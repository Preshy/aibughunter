"""Configuration management system."""

from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class QwenConfig(BaseModel):
    """Qwen AI API configuration."""
    api_url: str = Field(default="http://localhost:8080", description="Qwen API endpoint URL")
    api_key: Optional[str] = Field(default=None, description="API key for authentication")
    model: str = Field(default="qwen-coder-plus", description="Model to use")
    timeout: int = Field(default=120, description="Request timeout in seconds")
    max_tokens: int = Field(default=8192, description="Maximum tokens in response")
    temperature: float = Field(default=0.3, description="Sampling temperature")


class ScanConfig(BaseModel):
    """Scanning configuration."""
    max_concurrent_scans: int = Field(default=5, description="Maximum concurrent scans")
    request_timeout: int = Field(default=30, description="HTTP request timeout")
    rate_limit: float = Field(default=0.1, description="Delay between requests (seconds)")
    user_agent: str = Field(
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        description="User agent string",
    )
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    max_depth: int = Field(default=3, description="Maximum crawling depth")
    max_pages: int = Field(default=1000, description="Maximum pages to scan")


class ToolConfig(BaseModel):
    """Tools management configuration."""
    tools_dir: str = Field(default="./tools", description="Directory for security tools")
    auto_install: bool = Field(default=True, description="Auto-install missing tools")
    update_on_start: bool = Field(default=False, description="Update tools on start")


class ReportConfig(BaseModel):
    """Report generation configuration."""
    output_dir: str = Field(default="./reports", description="Default output directory")
    default_format: str = Field(default="markdown", description="Default report format")
    default_template: str = Field(default="hackerone", description="Default template")
    include_poc: bool = Field(default=True, description="Include proof of concept")
    include_remediation: bool = Field(default=True, description="Include remediation advice")
    include_screenshots: bool = Field(default=True, description="Include screenshots")


class ScopeConfig(BaseModel):
    """Scope management configuration."""
    default_program: str = Field(default="default", description="Default bug bounty program")
    respect_robots_txt: bool = Field(default=False, description="Respect robots.txt")
    max_subdomains: int = Field(default=1000, description="Maximum subdomains to track")


class AIHuntSettings(BaseSettings):
    """Main application settings."""
    model_config = {"env_prefix": "AIBH_", "env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
    
    # AI Configuration
    qwen: QwenConfig = Field(default_factory=QwenConfig)
    
    # Scanning
    scan: ScanConfig = Field(default_factory=ScanConfig)
    
    # Tools
    tools: ToolConfig = Field(default_factory=ToolConfig)
    
    # Reports
    reports: ReportConfig = Field(default_factory=ReportConfig)
    
    # Scope
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    
    # General
    verbose: bool = Field(default=False, description="Enable verbose output")
    log_level: str = Field(default="INFO", description="Logging level")
    data_dir: str = Field(default="./data", description="Data storage directory")


class ConfigManager:
    """Manages application configuration."""
    
    _instance: Optional["ConfigManager"] = None
    _settings: AIHuntSettings
    _overrides: dict[str, Any] = {}
    
    def __init__(self):
        self._settings = AIHuntSettings()
        self._config_file = Path.home() / ".aibughunter" / "config.json"
        self._load_from_file()
    
    @classmethod
    def load(cls) -> "ConfigManager":
        """Load configuration (singleton)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def _load_from_file(self):
        """Load configuration from JSON file."""
        if self._config_file.exists():
            import json
            try:
                with open(self._config_file) as f:
                    self._overrides = json.load(f)
            except Exception:
                self._overrides = {}
    
    def save(self):
        """Save configuration to file."""
        self._config_file.parent.mkdir(parents=True, exist_ok=True)
        import json
        with open(self._config_file, "w") as f:
            json.dump(self._overrides, f, indent=2)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key."""
        if key in self._overrides:
            return self._overrides[key]
        
        # Try to get from settings object
        parts = key.split("-")
        value = self._settings
        try:
            for part in parts:
                part = part.replace("-", "_")
                if hasattr(value, part):
                    value = getattr(value, part)
                else:
                    return default
            return value
        except Exception:
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self._overrides[key] = value
    
    def reset(self):
        """Reset configuration to defaults."""
        self._overrides = {}
    
    def display_items(self) -> list[tuple[str, Any]]:
        """Get all configuration items for display."""
        items = []
        items.append(("qwen-api-url", self._settings.qwen.api_url))
        items.append(("qwen-model", self._settings.qwen.model))
        items.append(("scan-max-concurrent", self._settings.scan.max_concurrent_scans))
        items.append(("scan-rate-limit", self._settings.scan.rate_limit))
        items.append(("tools-dir", self._settings.tools.tools_dir))
        items.append(("reports-dir", self._settings.reports.output_dir))
        items.append(("scope-default-program", self._settings.scope.default_program))
        items.append(("verbose", self._settings.verbose))
        items.append(("log-level", self._settings.log_level))
        
        # Add overrides
        for key, value in self._overrides.items():
            items.append((key, value))
        
        return items
    
    def get_source(self, key: str) -> str:
        """Get configuration value source."""
        if key in self._overrides:
            return "user"
        return "default"
