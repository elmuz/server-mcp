"""
Configuration loader for Server Management Library.

Loads YAML configuration with sensible defaults for SSH, security,
InfluxDB, Prometheus, and host data source settings.

Resolution order (first match wins):

1. explicit ``config_path`` argument (``--config``)
2. the path in ``env_var`` (for example ``REMOTE_SERVER_MCP_CONFIG``)
3. ``$XDG_CONFIG_HOME/<app_name>/config.yaml`` (``~/.config`` by default)
4. ``./config.yaml`` (repo checkout / local development)

Values from the environment override the YAML file, so secrets can stay out of
the config file. A ``.env`` file next to the config file is loaded first (when
``python-dotenv`` is installed), which matches the ``.env.example`` files.
"""

import copy
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from .security import DEFAULT_HOST_UNITS

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    # "ssh" (default) or "local" (run on the host where the MCP server runs)
    "executor": "ssh",
    # Container runtime used by the remote-server MCP operation catalog.
    "container_runtime": "docker",
    # MCP transport. stdio is the default; streamable-http is opt-in.
    "transport": {
        "type": "stdio",
        "host": "127.0.0.1",
        "port": 8000,
        "path": "/mcp",
        # Required for a non-loopback bind. Prefer MCP_HTTP_TOKEN over YAML.
        "token": None,
    },
    # Sliding-window limit for destructive/state-changing tool calls.
    "rate_limit": {
        "enabled": True,
        "max_calls": 10,
        "window_seconds": 60,
    },
    "ssh": {
        "host": "localhost",
        "port": 22,
        # None means: use the current user / ~/.ssh/config / ssh-agent.
        "username": None,
        "password": None,
        "key_path": None,
        # Path to known_hosts, or "none" to disable verification (insecure).
        "known_hosts": "~/.ssh/known_hosts",
        "connect_timeout": 10,
    },
    "security": {
        # Service directory base path (for remote-server-mcp)
        "services_path": "/srv",
        # NEVER allow generic command execution
        "allow_generic_commands": False,
        # Container names that may be managed without a matching service
        # directory. Containers that belong to a compose project below
        # services_path do not need to be listed here.
        "allowed_containers": [],
        # Host systemd units that get_host_service_status/logs may inspect.
        "host_units": list(DEFAULT_HOST_UNITS),
    },
    "host": {
        "enabled": False,
    },
    "health": {
        # Absolute mount points reported by remote-server-mcp's
        # get_server_health. NAS pools are separate mounts, so list each one.
        "disk_paths": ["/"],
    },
    "influxdb": {
        "enabled": False,
        "host": "localhost",
        "port": 8181,
        "use_https": False,
        "database": None,
        "token": None,
        "query_limit": 1000,
        # Optional local port forward to a loopback-only InfluxDB. When
        # enabled, host/port are rewritten to the tunnel endpoint at startup.
        "ssh_tunnel": {
            "enabled": False,
            "remote_host": "127.0.0.1",
            "remote_port": None,
            "local_host": "127.0.0.1",
            "local_port": 0,
        },
    },
    "prometheus": {
        "enabled": False,
        "host": "localhost",
        "port": 9090,
        "use_https": False,
        "token": None,
        "query_timeout": "30s",
        "ssh_tunnel": {
            "enabled": False,
            "remote_host": "127.0.0.1",
            "remote_port": None,
            "local_host": "127.0.0.1",
            "local_port": 0,
        },
    },
    "output": {
        # Maximum bytes returned to the model per command/file/query.
        "max_bytes": 64000,
    },
    "audit": {
        "enabled": False,
        "path": "~/.local/state/server-management/audit.jsonl",
    },
}

# Environment variable -> (section, key, converter)
ENV_OVERRIDES: dict[str, tuple[str, str, type]] = {
    "EXECUTOR": ("executor", "executor", str),
    "CONTAINER_RUNTIME": ("container_runtime", "container_runtime", str),
    "SSH_HOST": ("ssh", "host", str),
    "SSH_PORT": ("ssh", "port", int),
    "SSH_USERNAME": ("ssh", "username", str),
    "SSH_PASSWORD": ("ssh", "password", str),
    "SSH_KEY_PATH": ("ssh", "key_path", str),
    "SSH_KNOWN_HOSTS": ("ssh", "known_hosts", str),
    "INFLUXDB_HOST": ("influxdb", "host", str),
    "INFLUXDB_PORT": ("influxdb", "port", int),
    "INFLUXDB_USE_HTTPS": ("influxdb", "use_https", bool),
    "INFLUXDB_DATABASE": ("influxdb", "database", str),
    "INFLUXDB_TOKEN": ("influxdb", "token", str),
    "PROMETHEUS_HOST": ("prometheus", "host", str),
    "PROMETHEUS_PORT": ("prometheus", "port", int),
    "PROMETHEUS_USE_HTTPS": ("prometheus", "use_https", bool),
    "PROMETHEUS_TOKEN": ("prometheus", "token", str),
    "MCP_TRANSPORT": ("transport", "type", str),
    "MCP_HTTP_HOST": ("transport", "host", str),
    "MCP_HTTP_PORT": ("transport", "port", int),
    "MCP_HTTP_PATH": ("transport", "path", str),
    "MCP_HTTP_TOKEN": ("transport", "token", str),
    "OUTPUT_MAX_BYTES": ("output", "max_bytes", int),
    "AUDIT_ENABLED": ("audit", "enabled", bool),
    "AUDIT_LOG_PATH": ("audit", "path", str),
}


class ConfigError(Exception):
    """Base class for configuration problems."""


class ConfigNotFoundError(ConfigError, FileNotFoundError):
    """No configuration file could be located."""


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _convert(value: str, converter: type) -> Any:
    if converter is bool:
        return _as_bool(value)
    return converter(value)


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict:
    """Merge ``override`` on top of ``base`` without mutating either."""
    result: dict[str, Any] = copy.deepcopy(dict(base))
    for key, value in override.items():
        current = result.get(key)
        if value is None and isinstance(current, dict):
            # An empty YAML section (e.g. ``influxdb:``) keeps the defaults.
            continue
        if isinstance(value, Mapping) and isinstance(current, Mapping):
            result[key] = _deep_merge(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def resolve_config_path(
    explicit: Path | str | None = None,
    *,
    env_var: str | None = None,
    app_name: str | None = None,
) -> Path | None:
    """Return the configuration file path, or ``None`` if none was found.

    An explicit path is returned even if the file does not exist; the caller
    decides whether that is an error.
    """
    if explicit is not None:
        return Path(explicit).expanduser()

    if env_var:
        value = os.environ.get(env_var)
        if value:
            return Path(value).expanduser()

    if app_name:
        xdg_home = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg_home).expanduser() if xdg_home else Path.home() / ".config"
        candidate = base / app_name / "config.yaml"
        if candidate.exists():
            return candidate

    cwd_candidate = Path.cwd() / "config.yaml"
    if cwd_candidate.exists():
        return cwd_candidate

    return None


def _apply_env_overrides(
    config: dict[str, Any],
    env: Mapping[str, str],
) -> None:
    for env_name, (section, key, converter) in ENV_OVERRIDES.items():
        value = env.get(env_name)
        if value is None or value == "":
            continue
        try:
            section_config = config.get(section)
            if not isinstance(section_config, dict):
                section_config = {}
                config[section] = section_config
            section_config[key] = _convert(value, converter)
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid value for %s", env_name)


def _load_dotenv(config_file: Path) -> None:
    """Load ``.env`` next to the config file (best effort)."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - optional dependency
        return

    env_file = config_file.parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)


def load_config(
    config_path: Path | str | None = None,
    *,
    env_var: str | None = None,
    app_name: str | None = None,
    required: bool = False,
    env: Mapping[str, str] | None = None,
    use_dotenv: bool = True,
    log_missing: bool = True,
) -> dict:
    """Load configuration from YAML, merged over :data:`DEFAULT_CONFIG`.

    Args:
        config_path: Explicit path; when ``None`` the usual locations are probed.
        env_var: Environment variable holding a config path.
        app_name: Application name used for the XDG location.
        required: Raise :class:`ConfigNotFoundError` instead of using defaults.
        env: Environment mapping for overrides (defaults to ``os.environ``).
        use_dotenv: Load a ``.env`` file next to the resolved config file.
        log_missing: Log a warning when no config file is found. Disable this
            for the best-effort import-time load in servers.

    Raises:
        ConfigNotFoundError: No config found (or explicit path missing) and
            ``required`` is true.
        ConfigError: The config file exists but cannot be parsed, and
            ``required`` is true.
    """
    resolved = resolve_config_path(config_path, env_var=env_var, app_name=app_name)

    searched = _describe_search_paths(config_path, env_var, app_name)

    if resolved is None or not resolved.exists():
        if required:
            raise ConfigNotFoundError(
                "No configuration file found. Searched: "
                f"{searched}. Create one from config.example.yaml or pass "
                "--config / set the config environment variable."
            )
        if log_missing:
            logger.warning(
                "No configuration file found (searched: %s); using defaults",
                searched,
            )
        return _deep_merge(DEFAULT_CONFIG, {})

    if use_dotenv and env is None:
        _load_dotenv(resolved)

    try:
        with open(resolved) as f:
            loaded = yaml.safe_load(f)
    except Exception as e:
        if required:
            raise ConfigError(f"Error loading config from {resolved}: {e}") from e
        logger.error("Error loading config from %s: %s", resolved, e)
        logger.warning("Using default configuration")
        return _deep_merge(DEFAULT_CONFIG, {})

    if loaded is None:
        loaded = {}
    if not isinstance(loaded, Mapping):
        message = f"Configuration in {resolved} must be a YAML mapping"
        if required:
            raise ConfigError(message)
        logger.error(message)
        return _deep_merge(DEFAULT_CONFIG, {})

    config = _deep_merge(DEFAULT_CONFIG, loaded)
    _apply_env_overrides(config, os.environ if env is None else env)
    logger.info("Loaded configuration from %s", resolved)
    return config


# Values that must never be published by the config-schema MCP resource.
SECRET_CONFIG_KEYS = frozenset({"token", "password"})


def redact_config_values(value: Any) -> Any:
    """Return a copy of a config mapping with credential-like values masked."""
    if isinstance(value, Mapping):
        return {
            key: (
                "***"
                if str(key).lower() in SECRET_CONFIG_KEYS
                else redact_config_values(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_config_values(item) for item in value]
    return value


def config_schema() -> dict[str, Any]:
    """Describe the configuration defaults and environment overrides.

    Used by the MCP config resource. Credential-like values are masked, and
    environment variable names are listed without their values.
    """
    return {
        "defaults": redact_config_values(DEFAULT_CONFIG),
        "environment_overrides": {
            name: {"section": section, "key": key}
            for name, (section, key, _converter) in sorted(ENV_OVERRIDES.items())
        },
    }


def _describe_search_paths(
    config_path: Path | str | None,
    env_var: str | None,
    app_name: str | None,
) -> str:
    if config_path is not None:
        return str(Path(config_path).expanduser())
    parts = []
    if env_var:
        parts.append(f"${env_var}")
    if app_name:
        parts.append(f"$XDG_CONFIG_HOME/{app_name}/config.yaml (~/.config fallback)")
    parts.append("./config.yaml")
    return ", ".join(parts)
