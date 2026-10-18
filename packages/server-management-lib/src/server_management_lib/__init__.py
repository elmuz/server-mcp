"""
Server Management Library

Shared components for server management MCPs:

- Configuration loading (YAML + environment + XDG paths)
- Security validation (commands, queries, paths)
- SSH connection management (host key verification by default)
- InfluxDB and Prometheus HTTP clients
"""

from .audit import AuditLogger, create_audit_logger
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
from .operations import Operation
from .output import DEFAULT_MAX_OUTPUT_BYTES, sanitize_output, strip_ansi
from .redaction import REDACTED_VALUE, redact_env_content
from .security import (
    FileAccess,
    SecurityValidator,
    ServiceFilePath,
)
from .ssh_manager import SSHConfigurationError, SSHManager
from .tunnel import (
    ActiveTunnel,
    SSHTunnel,
    SSHTunnelError,
    TunnelConfig,
    TunnelEndpoint,
    close_metric_tunnels,
    open_metric_tunnels,
)

__all__ = [
    "DEFAULT_CONFIG",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "REDACTED_VALUE",
    "ActiveTunnel",
    "AuditLogger",
    "ConfigError",
    "ConfigNotFoundError",
    "Executor",
    "ExecutorBase",
    "ExecutorError",
    "FileAccess",
    "InfluxDBClient",
    "LocalExecutor",
    "Operation",
    "PrometheusClient",
    "RemoteDirEntry",
    "RemoteFileError",
    "RemotePathError",
    "SSHConfigurationError",
    "SSHManager",
    "SSHTunnel",
    "SSHTunnelError",
    "SecurityValidator",
    "ServiceFilePath",
    "TunnelConfig",
    "TunnelEndpoint",
    "__version__",
    "close_metric_tunnels",
    "create_audit_logger",
    "create_executor",
    "load_config",
    "open_metric_tunnels",
    "parse_duration",
    "redact_env_content",
    "resolve_config_path",
    "sanitize_output",
    "strip_ansi",
]

__version__ = "0.2.0"
