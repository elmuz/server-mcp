"""
Server Management Library

Shared components for server management MCPs:

- Configuration loading (YAML + environment + XDG paths)
- Security validation (commands, queries, paths)
- SSH connection management (host key verification by default)
- InfluxDB and Prometheus HTTP clients
"""

from .config import (
    DEFAULT_CONFIG,
    ConfigError,
    ConfigNotFoundError,
    load_config,
    resolve_config_path,
)
from .http_clients import InfluxDBClient, PrometheusClient
from .security import SecurityValidator
from .ssh_manager import SSHConfigurationError, SSHManager

__all__ = [
    "DEFAULT_CONFIG",
    "ConfigError",
    "ConfigNotFoundError",
    "InfluxDBClient",
    "PrometheusClient",
    "SSHConfigurationError",
    "SSHManager",
    "SecurityValidator",
    "load_config",
    "resolve_config_path",
]
