"""
Server Management Library

Shared components for server management MCPs:

- Configuration loading (YAML + environment + XDG paths)
- Security validation (commands, queries, paths)
- SSH connection management (host key verification by default)
- InfluxDB and Prometheus HTTP clients
"""

from .audit import AuditLogger
from .config import (
    DEFAULT_CONFIG,
    ConfigError,
    ConfigNotFoundError,
    load_config,
    resolve_config_path,
)
from .http_clients import InfluxDBClient, PrometheusClient, parse_duration
from .output import DEFAULT_MAX_OUTPUT_BYTES, sanitize_output, strip_ansi
from .security import SecurityValidator
from .ssh_manager import (
    RemoteDirEntry,
    RemoteFileError,
    RemotePathError,
    SSHConfigurationError,
    SSHManager,
)

__all__ = [
    "DEFAULT_CONFIG",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "AuditLogger",
    "ConfigError",
    "ConfigNotFoundError",
    "InfluxDBClient",
    "PrometheusClient",
    "RemoteDirEntry",
    "RemoteFileError",
    "RemotePathError",
    "SSHConfigurationError",
    "SSHManager",
    "SecurityValidator",
    "load_config",
    "parse_duration",
    "resolve_config_path",
    "sanitize_output",
    "strip_ansi",
]
