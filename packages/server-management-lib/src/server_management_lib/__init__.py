"""
Server Management Library

Shared components for server management MCPs:

- Configuration loading (YAML + environment + XDG paths)
- Security validation (commands, queries, paths)
- SSH connection management (host key verification by default)
- InfluxDB and Prometheus HTTP clients
"""

from .audit import AuditLogger
from .base import (
    ExecutorBase,
    ExecutorError,
    RemoteDirEntry,
    RemoteFileError,
    RemotePathError,
)
from .config import (
    DEFAULT_CONFIG,
    ConfigError,
    ConfigNotFoundError,
    load_config,
    resolve_config_path,
)
from .executor import Executor, create_executor
from .http_clients import InfluxDBClient, PrometheusClient, parse_duration
from .local_executor import LocalExecutor
from .output import DEFAULT_MAX_OUTPUT_BYTES, sanitize_output, strip_ansi
from .security import SecurityValidator
from .ssh_manager import SSHConfigurationError, SSHManager

__all__ = [
    "DEFAULT_CONFIG",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "AuditLogger",
    "ConfigError",
    "ConfigNotFoundError",
    "Executor",
    "ExecutorBase",
    "ExecutorError",
    "InfluxDBClient",
    "LocalExecutor",
    "PrometheusClient",
    "RemoteDirEntry",
    "RemoteFileError",
    "RemotePathError",
    "SSHConfigurationError",
    "SSHManager",
    "SecurityValidator",
    "__version__",
    "create_executor",
    "load_config",
    "parse_duration",
    "resolve_config_path",
    "sanitize_output",
    "strip_ansi",
]

__version__ = "0.2.0"
