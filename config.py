"""
Configuration management for EDGI Cloud Portal
Supports environment variables, TOML files, and secrets
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field
import tomllib


@dataclass
class Config:
    """Configuration class with defaults and validation"""
    # Database settings
    portal_db_path: Optional[str] = None
    data_dir: str = "data"
    static_dir: str = "static"

    # Security settings
    csrf_secret_key: Optional[str] = None
    admin_password: Optional[str] = None

    # App settings
    app_url: str = "http://localhost:8001"
    debug: bool = False

    # File limits (in bytes)
    max_file_size_in_mb: int = 500
    max_img_size_in_mb: int = 5
    # Feature flags
    maintenance_mode: bool = False
    registration_enabled: bool = True

    # Additional settings
    extra_settings: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate configuration after initialization"""
        if not self.portal_db_path:
            self.portal_db_path = os.path.join(self.data_dir, "portal.db")

        if not self.csrf_secret_key:
            raise ValueError("CSRF_SECRET_KEY must be set for security")

def load_config(config_file: Optional[str] = None) -> Config:
    """
    Load configuration from multiple sources in order of precedence:
    1. Environment variables (highest priority)
    2. config.toml file
    3. Default values (lowest priority)
    """
    config_data = {}

    # 1. Load from TOML file if specified or if exists
    config_files_to_try = []
    if config_file:
        config_files_to_try.append(config_file)

    # Try common config file locations
    config_files_to_try.extend([
        "config.toml",
        "config/production.toml",
        "config/development.toml",
        os.path.expanduser("~/.edgi-cloud/config.toml")
    ])

    for config_path in config_files_to_try:
        if os.path.exists(config_path) and tomllib:
            try:
                with open(config_path, 'rb') as f:
                    toml_config = tomllib.load(f)
                    config_data.update(toml_config)
                    print(f"Loaded config from: {config_path}")
                break
            except Exception as e:
                print(f"Warning: Could not load {config_path}: {e}")

    # 2. Override with environment variables
    env_mappings = {
        'PORTAL_DB_PATH': 'portal_db_path',
        'RESETTE_DATA_DIR': 'data_dir',
        'RESETTE_STATIC_DIR': 'static_dir',
        'CSRF_SECRET_KEY': 'csrf_secret_key',
        'DEFAULT_PASSWORD': 'default_password',
        'APP_URL': 'app_url',
        'DEBUG': 'debug',
        'MAX_FILE_SIZE_IN_MB': 'max_file_size_in_mb',
        'MAX_IMG_SIZE_IN_MB': 'max_img_size_in_mb',
        'MAINTENANCE_MODE': 'maintenance_mode',
        'REGISTRATION_ENABLED': 'registration_enabled',
    }

    for env_var, config_key in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value is not None:
            # Type conversion for non-string values
            if config_key in ['debug', 'maintenance_mode', 'registration_enabled']:
                config_data[config_key] = env_value.lower() in ('true', '1', 'yes', 'on')
            elif config_key in ['max_file_size_in_mb', 'max_img_size_in_mb']:
                config_data[config_key] = int(env_value)
            else:
                config_data[config_key] = env_value

    # 3. Create config object with validated data
    return Config(**config_data)

# Global config instance
_config: Optional[Config] = None

def get_config(config_file: Optional[str] = None) -> Config:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = load_config(config_file)
    return _config

def reload_config(config_file: Optional[str] = None) -> Config:
    """Reload configuration from sources"""
    global _config
    _config = load_config(config_file)
    return _config
