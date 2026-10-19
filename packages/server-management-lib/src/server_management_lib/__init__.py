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
    config_schema,
    load_config,
    redact_config_values,
    resolve_config_path,
)
from .executor import Executor, create_executor
from .http_clients import InfluxDBClient, PrometheusClient, parse_duration
from .local_executor import LocalExecutor
from .operations import Operation
from .output import DEFAULT_MAX_OUTPUT_BYTES, sanitize_output, strip_ansi
from .rate_limit import (
    RateLimitConfig,
    RateLimiter,
    create_rate_limiter,
)
from .redaction import REDACTED_VALUE, redact_env_content, redact_secrets
from .responses import (
    ToolOutput,
    ToolResponse,
    build_response,
    make_structured_tool,
)
from .security import (
    SNAPRAID_STATUS_SUDO_ARGV,
    FileAccess,
    SecurityValidator,
    ServiceFilePath,
)
from .ssh_manager import SSHConfigurationError, SSHManager
from .transport import (
    BearerTokenMiddleware,
    is_loopback_host,
    run_streamable_http,
    validate_http_binding,
)
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
    "SNAPRAID_STATUS_SUDO_ARGV",
    "ActiveTunnel",
    "AuditLogger",
    "BearerTokenMiddleware",
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
    "RateLimitConfig",
    "RateLimiter",
    "RemoteDirEntry",
    "RemoteFileError",
    "RemotePathError",
    "SSHConfigurationError",
    "SSHManager",
    "SSHTunnel",
    "SSHTunnelError",
    "SecurityValidator",
    "ServiceFilePath",
    "ToolOutput",
    "ToolResponse",
    "TunnelConfig",
    "TunnelEndpoint",
    "__version__",
    "build_response",
    "close_metric_tunnels",
    "config_schema",
    "create_audit_logger",
    "create_executor",
    "create_rate_limiter",
    "is_loopback_host",
    "load_config",
    "make_structured_tool",
    "open_metric_tunnels",
    "parse_duration",
    "redact_config_values",
    "redact_env_content",
    "redact_secrets",
    "resolve_config_path",
    "run_streamable_http",
    "sanitize_output",
    "strip_ansi",
    "validate_http_binding",
]

__version__ = "0.2.0"
