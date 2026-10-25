import os
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / '.env'

def _load_env_file() -> Dict[str, str]:
    """Load key=value pairs from .env file."""
    env_vars = {}
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
    return env_vars

def get_config() -> Dict[str, Any]:
    """
    Get configuration with precedence:
    1. Environment variables
    2. .env file
    3. Defaults
    """
    # Start with defaults
    config: Dict[str, Any] = {
        # Server settings
        'HOST': '127.0.0.1',
        'PORT': 8765,
        # Investigation settings
        'MAX_JOBS': 200,
        'HEALTH_CHECK_TIMEOUT': 30,
        'HEALTH_CHECK_INTERVAL': 1.0,
        'HEALTH_CHECK_MAX_RETRIES': 30,
        # Paths
        'DATA_DIR': str(ROOT / 'data'),
        # Features
        'ENABLE_AI': False,
        # Logging
        'LOG_LEVEL': 'INFO',
    }

    # Override with .env file
    env_file_vars = _load_env_file()
    config.update(env_file_vars)

    # Override with environment variables (highest precedence)
    for key, value in os.environ.items():
        if key in config:
            # Attempt to preserve type for known config keys
            if isinstance(config[key], bool):
                config[key] = value.lower() in ('true', '1', 'yes', 'on')
            elif isinstance(config[key], int):
                try:
                    config[key] = int(value)
                except ValueError:
                    pass  # Keep default if conversion fails
            elif isinstance(config[key], float):
                try:
                    config[key] = float(value)
                except ValueError:
                    pass
            else:
                config[key] = value
        else:
            # New environment variable - treat as string
            config[key] = value

    return config

def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get a secret value from environment or .env file.
    Secrets should not be logged or exposed in UI.
    """
    # Check environment first
    value = os.environ.get(key)
    if value is not None:
        return value
    # Check .env file
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith(f'{key}='):
                return line.split('=', 1)[1].strip()
    return default