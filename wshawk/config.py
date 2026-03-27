#!/usr/bin/env python3
"""
WSHawk Configuration Manager
YAML-based config with env var overrides and secrets support

Author: Regaan (@regaan)
"""

import os
import copy
from pathlib import Path
from typing import Any, Dict, Optional

from wshawk.secret_store import SecretStore

try:
    import yaml
except ImportError:
    yaml = None


# ─── Default Configuration ──────────────────────────────────────

DEFAULT_CONFIG = {
    'scanner': {
        'rate_limit': 10,
        'timeout': 5,
        'learning_duration': 5,
        'max_payload_count': 100,
        'verify_ssl': True,
        'user_agent': 'WSHawk/4.0.0',
        'features': {
            'playwright': False,
            'oast': True,
            'binary_analysis': False,
            'smart_payloads': False,
            'ai_fuzzing': False,
        },
    },
    'ai': {
        'provider': 'ollama',    # ollama, openai, custom
        'model': 'codellama',
        'base_url': '',          # override default provider URL
        'api_key': '',           # or env:WSHAWK_AI_KEY
    },
    'reporting': {
        'output_dir': './reports',
        'formats': ['html'],
        'auto_open': False,
    },
    'integrations': {
        'defectdojo': {
            'enabled': False,
            'url': '',
            'api_key': '',       # or env:DEFECTDOJO_API_KEY
            'product_id': None,
            'product_name': 'WSHawk Scans',
            'auto_create_engagement': True,
            'verify_ssl': True,
        },
        'jira': {
            'enabled': False,
            'url': '',
            'email': '',         # or env:JIRA_EMAIL
            'api_token': '',     # or env:JIRA_API_TOKEN
            'project_key': 'SEC',
            'issue_type': 'Bug',
            'min_severity': 'LOW',
        },
        'webhook': {
            'enabled': False,
            'url': '',           # or env:WSHAWK_WEBHOOK_URL
            'platform': 'generic',
            'notify_on': 'all',
            'min_severity': 'LOW',
        },
    },
    'web': {
        'host': '0.0.0.0',
        'port': 5000,
        'debug': False,
        'auth': {
            'enabled': False,
            'username': 'admin',
            'password': '',      # or env:WSHAWK_WEB_PASSWORD
        },
        'database': 'sqlite:///wshawk.db',
    },
}

# Config file search paths (in priority order)
CONFIG_PATHS = [
    Path('./wshawk.yaml'),
    Path('./wshawk.yml'),
    Path.home() / '.wshawk' / 'config.yaml',
    Path.home() / '.wshawk' / 'config.yml',
    Path('/etc/wshawk/config.yaml'),
]


class WSHawkConfig:
    """
    Hierarchical configuration manager.
    
    Priority order (highest to lowest):
    1. CLI arguments
    2. Environment variables
    3. Config file (wshawk.yaml)
    4. Default values
    
    Secrets resolution:
    - Values starting with 'env:' are resolved from environment variables
    - Values starting with 'file:' are read from the specified file
    
    Usage:
        config = WSHawkConfig.load()
        rate = config.get('scanner.rate_limit')
        dd_key = config.get('integrations.defectdojo.api_key')
    """
    
    def __init__(self, data: Dict = None):
        self._data = data or copy.deepcopy(DEFAULT_CONFIG)
        self._resolved_cache: Dict[str, Any] = {}
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'WSHawkConfig':
        """
        Load configuration from file, with defaults and env overrides.
        
        Args:
            config_path: Explicit path to config file. If None, searches default locations.
        """
        config = cls(copy.deepcopy(DEFAULT_CONFIG))
        
        # Find and load config file
        file_path = None
        if config_path:
            file_path = Path(config_path)
        else:
            for candidate in CONFIG_PATHS:
                if candidate.exists():
                    file_path = candidate
                    break
        
        if file_path and file_path.exists():
            file_config = config._load_file(file_path)
            if file_config:
                config._deep_merge(config._data, file_config)
        
        # Apply environment variable overrides
        config._apply_env_overrides()
        
        return config
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a config value by dot-separated path.
        
        Args:
            key_path: Dot-separated key path (e.g., 'scanner.rate_limit')
            default: Default value if key not found
            
        Returns:
            The config value, with secrets resolved
        """
        # Check cache first
        if key_path in self._resolved_cache:
            return self._resolved_cache[key_path]
        
        value = self._get_nested(self._data, key_path.split('.'))
        if value is None:
            return default
        
        # Resolve secrets
        resolved = self._resolve_secret(value)
        self._resolved_cache[key_path] = resolved
        return resolved
    
    def set(self, key_path: str, value: Any):
        """Set a config value by dot-separated path."""
        keys = key_path.split('.')
        obj = self._data
        for key in keys[:-1]:
            if key not in obj:
                obj[key] = {}
            obj = obj[key]
        obj[keys[-1]] = value
        
        # Invalidate cache
        self._resolved_cache.pop(key_path, None)
    
    def get_section(self, section: str) -> Dict:
        """Get an entire config section as a dict."""
        value = self._get_nested(self._data, section.split('.'))
        if isinstance(value, dict):
            return self._resolve_dict(copy.deepcopy(value))
        return {}
    
    def to_dict(self) -> Dict:
        """Export full config as dict (with secrets resolved)."""
        return self._resolve_dict(copy.deepcopy(self._data))
    
    def save(self, path: str = None):
        """Save current config to file."""
        if not yaml:
            raise ImportError("PyYAML required for config save. Install: pip install pyyaml")
        
        save_path = Path(path) if path else Path.home() / '.wshawk' / 'config.yaml'
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(save_path, 'w') as f:
            yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
    
    # ─── Internal Methods ───────────────────────────────────────
    
    def _load_file(self, path: Path) -> Optional[Dict]:
        """Load config from YAML file."""
        if not yaml:
            return None
        try:
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return None
    
    def _deep_merge(self, base: Dict, override: Dict):
        """Deep merge override into base dict (in-place)."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _get_nested(self, data: Dict, keys: list) -> Any:
        """Get a nested value from a dict by key list."""
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    def _resolve_secret(self, value: Any) -> Any:
        """Resolve secret references in config values."""
        if not isinstance(value, str):
            return value
        
        # env:VAR_NAME — read from environment
        if value.startswith('env:'):
            env_var = value[4:]
            return os.environ.get(env_var, '')
        
        # file:/path/to/secret — read from file
        if value.startswith('file:'):
            file_path = value[5:]
            try:
                with open(file_path) as f:
                    return f.read().strip()
            except (IOError, OSError):
                return ''

        # secret:namespace:key — read from platform-aware secret storage
        if value.startswith('secret:'):
            return SecretStore.resolve_reference(value, default='')
        
        return value
    
    def _resolve_dict(self, data: Dict) -> Dict:
        """Recursively resolve all secrets in a dict."""
        resolved = {}
        for key, value in data.items():
            if isinstance(value, dict):
                resolved[key] = self._resolve_dict(value)
            elif isinstance(value, str):
                resolved[key] = self._resolve_secret(value)
            else:
                resolved[key] = value
        return resolved
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides."""
        env_map = {
            'WSHAWK_RATE_LIMIT': 'scanner.rate_limit',
            'WSHAWK_TIMEOUT': 'scanner.timeout',
            'WSHAWK_OUTPUT_DIR': 'reporting.output_dir',
            'DEFECTDOJO_URL': 'integrations.defectdojo.url',
            'DEFECTDOJO_API_KEY': 'integrations.defectdojo.api_key',
            'DEFECTDOJO_PRODUCT_ID': 'integrations.defectdojo.product_id',
            'JIRA_URL': 'integrations.jira.url',
            'JIRA_EMAIL': 'integrations.jira.email',
            'JIRA_API_TOKEN': 'integrations.jira.api_token',
            'JIRA_PROJECT': 'integrations.jira.project_key',
            'WSHAWK_WEBHOOK_URL': 'integrations.webhook.url',
            'WSHAWK_WEBHOOK_PLATFORM': 'integrations.webhook.platform',
            'WSHAWK_WEB_HOST': 'web.host',
            'WSHAWK_WEB_PORT': 'web.port',
            'WSHAWK_WEB_PASSWORD': 'web.auth.password',
            'WSHAWK_AI_PROVIDER': 'ai.provider',
            'WSHAWK_AI_MODEL': 'ai.model',
            'WSHAWK_AI_KEY': 'ai.api_key',
            'WSHAWK_AI_BASE_URL': 'ai.base_url',
        }
        
        for env_var, config_path in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Type coercion
                if config_path.endswith(('rate_limit', 'timeout', 'port', 'product_id', 'learning_duration')):
                    try:
                        value = int(value)
                    except ValueError:
                        continue
                elif value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                
                self.set(config_path, value)


# ─── Convenience Functions ──────────────────────────────────────

def generate_sample_config(path: str = './wshawk.yaml'):
    """Generate a sample configuration file."""
    if not yaml:
        # Fallback to manual YAML writing
        sample = """# WSHawk Configuration File
# https://github.com/regaan/wshawk

scanner:
  rate_limit: 10
  timeout: 5
  learning_duration: 5
  max_payload_count: 100
  verify_ssl: true
    features:
      playwright: false
      oast: true
      binary_analysis: false
      smart_payloads: false
      ai_fuzzing: false

ai:
  provider: ollama
  model: codellama
  # api_key: env:WSHAWK_AI_KEY
  # base_url: http://localhost:11434/api/generate

reporting:
  output_dir: ./reports
  formats:
    - html
    - json
    - sarif

integrations:
  defectdojo:
    enabled: false
    url: https://defectdojo.company.com
    api_key: env:DEFECTDOJO_API_KEY
    product_name: WSHawk Scans
    auto_create_engagement: true

  jira:
    enabled: false
    url: https://company.atlassian.net
    email: env:JIRA_EMAIL
    api_token: env:JIRA_API_TOKEN
    project_key: SEC
    issue_type: Bug
    min_severity: MEDIUM

  webhook:
    enabled: false
    url: env:WSHAWK_WEBHOOK_URL
    platform: generic
    notify_on: all

web:
  host: 0.0.0.0
  port: 5000
  debug: false
  auth:
    enabled: false
    username: admin
    password: env:WSHAWK_WEB_PASSWORD
"""
        with open(path, 'w') as f:
            f.write(sample)
    else:
        config = WSHawkConfig()
        config.save(path)
    
    return path
