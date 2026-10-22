"""
MCP Server for Remote Server Management

SECURITY MODEL:
- NO generic command execution
- ONLY specific, safe operations
- All paths restricted to the configured services directory
- No access to credentials, keys, or sensitive system files
- Docker operations limited to service management (not arbitrary commands)

Design Principle: Whitelist operations, don't blacklist commands.
"""

import argparse
import asyncio
import json
import logging
import os
import re
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from server_management_lib import (
    DEFAULT_MAX_OUTPUT_BYTES,
    ConfigNotFoundError,
    FileAccess,
    InfluxDBClient,
    Operation,
    PrometheusClient,
    SecurityValidator,
    ToolOutput,
    close_metric_tunnels,
    config_schema,
    create_audit_logger,
    create_executor,
    create_rate_limiter,
    influxdb_group_by_advisory,
    load_config,
    make_structured_tool,
    open_metric_tunnels,
    parse_duration,
    redact_secrets,
    resolve_config_path,
    run_streamable_http,
    sanitize_output,
)

from .operations import (
    DISK_USAGE,
    ECHO_CONNECTION,
    FREE_MEMORY,
    LS_SERVICES,
    SYSTEMCTL_STATUS,
    UPTIME,
    build_container_catalog,
    journalctl_unit_operation,
)
from .resolution import (
    Resolution,
    ResolutionError,
    collect_containers,
    collect_service_directories,
    command_failure,
    format_container_table,
    resolve_service_target,
    service_target,
)

APP_NAME = "remote-server-mcp"
CONFIG_ENV_VAR = "REMOTE_SERVER_MCP_CONFIG"

logger = logging.getLogger(__name__)

# Best-effort load so the module stays importable (tests, tooling). The server
# itself refuses to start without a real configuration file (see main()).
config = load_config(env_var=CONFIG_ENV_VAR, app_name=APP_NAME, log_missing=False)
security = SecurityValidator(config)
executor = create_executor(config, security)
catalog = build_container_catalog(security.container_runtime)
rate_limiter = create_rate_limiter(config)

mcp = MCPServer("remote-server-mcp")

# Tools keep returning readable strings; the MCP-facing wrapper returns a
# structured ToolResponse alongside the same text block.
structured_tool = make_structured_tool(
    lambda name, tool, annotations: mcp.tool(name=name, annotations=annotations)(tool)
)

READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
WRITE_ACTION = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=False,
)
DESTRUCTIVE_ACTION = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)

# Compose projects have one of these files at their project root. Its absence
# (together with a missing compose project label) identifies an
# Ansible-managed service that must be changed through its role, not Compose.
COMPOSE_FILE_NAMES = frozenset(
    {
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    }
)

# Services that write their logs to files instead of stdout/stderr. Docker
# logs are empty for these, so a "no matches" result needs a pointer to the
# mounted log directory.
FILE_LOG_SERVICES = frozenset({"nginx", "swag"})

_ENV_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*="
)

# Docker accepts a bare Go duration (``2h``, ``1h30m``); journalctl wants the
# same duration with a leading minus. RFC3339 timestamps and dates are passed
# through unchanged.
_JOURNAL_DURATION_PATTERN = re.compile(r"^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)){1,4}$")


def _max_output_bytes() -> int:
    output_config = config.get("output", {}) or {}
    return int(output_config.get("max_bytes", DEFAULT_MAX_OUTPUT_BYTES))


def _cap_composite(text: str) -> str:
    """Apply the response cap to output assembled from several commands."""
    return sanitize_output(text, _max_output_bytes(), label="tool output")


def _audit(event: str, **fields: object) -> None:
    """Record a policy decision that happens before the executor is called."""
    create_audit_logger(config).log(event, **fields)


def _rate_limited(action: str) -> str | None:
    """Return a rate-limit error when the sliding window is exhausted."""
    if rate_limiter is None:
        return None
    retry_after = rate_limiter.check()
    if retry_after is None:
        return None
    _audit("rate_limited", action=action, retry_after=round(retry_after, 1))
    return (
        f"❌ Rate limit exceeded for {action}. No change was made.\n"
        f"Try again in {retry_after:.0f}s (see rate_limit in config.yaml)."
    )


def _confirmation_required(action: str, target: str, command: str) -> str:
    """Explain that a state-changing operation needs explicit confirmation."""
    return (
        f"⚠️ Confirmation required to {action} '{target}'. No change was made.\n"
        f"Command: {command}\n"
        "Call the tool again with confirm=true after verifying the target."
    )


_metric_clients: dict[tuple[str, int], InfluxDBClient | PrometheusClient] = {}


def _cached_client(name, cfg, factory):
    """Return one long-lived client per config object and service.

    A client owns a shared ``aiohttp.ClientSession`` (opened lazily), so
    reusing the client avoids a new session on every tool call. The key
    includes the config object identity so a test/config swap gets a fresh
    client; :func:`apply_config` clears the cache explicitly.
    """
    key = (name, id(cfg))
    client = _metric_clients.get(key)
    if client is None:
        client = factory()
        _metric_clients[key] = client
    return client


def _get_influxdb_client() -> InfluxDBClient:
    cfg = config.get("influxdb", {}) or {}
    return _cached_client("influxdb", cfg, _make_influxdb_client)  # type: ignore[return-value]


def _get_prometheus_client() -> PrometheusClient:
    cfg = config.get("prometheus", {}) or {}
    return _cached_client("prometheus", cfg, _make_prometheus_client)  # type: ignore[return-value]


async def close_metric_clients() -> None:
    """Close every cached HTTP client session on shutdown."""
    clients = list(_metric_clients.values())
    _metric_clients.clear()
    for client in clients:
        try:
            await client.close()
        except Exception as e:  # pragma: no cover - best effort
            logger.debug("Error while closing %s: %s", type(client).__name__, e)


def _make_influxdb_client() -> InfluxDBClient:
    """Create an InfluxDB client with the shared audit logger."""
    cfg = config.get("influxdb", {}) or {}
    return InfluxDBClient(
        host=cfg.get("host", "localhost"),
        port=cfg.get("port", 8181),
        use_https=cfg.get("use_https", False),
        database=cfg.get("database"),
        token=cfg.get("token"),
        query_limit=cfg.get("query_limit", 1000),
        max_output_bytes=_max_output_bytes(),
        audit=create_audit_logger(config),
    )


def _make_prometheus_client() -> PrometheusClient:
    """Create a Prometheus client with the shared audit logger."""
    cfg = config.get("prometheus", {}) or {}
    return PrometheusClient(
        host=cfg.get("host", "localhost"),
        port=cfg.get("port", 9090),
        use_https=cfg.get("use_https", False),
        token=cfg.get("token"),
        max_output_bytes=_max_output_bytes(),
        timeout=parse_duration(cfg.get("query_timeout", "30s")),
        audit=create_audit_logger(config),
    )


async def _resolve_service(service: str) -> Resolution:
    """Validate a target and resolve it to allowed Docker containers."""
    if not security.validate_service_name(service):
        raise ResolutionError(f"❌ Invalid service name: {service}")
    return await resolve_service_target(executor, security, service, catalog)


def _not_compose_message(service: str, reason: str) -> str:
    """Explain why a service directory cannot be managed with Compose."""
    return (
        f"❌ '{service}' is not a compose project. {reason}\n"
        "Use start_service/restart_service/stop_service for its containers, "
        "or re-run the Ansible role that manages it. No Compose command was run."
    )


async def _compose_management(directory: str) -> str | None:
    """Return a reason when a directory is not a Compose project, else ``None``.

    The compose file at the project root is the signal. This check uses the
    existing directory listing, not Docker, so a directory managed by Ansible's
    ``docker_container`` module is refused without first producing Docker's raw
    "no configuration file provided" error.
    """
    try:
        entries = await executor.list_remote_dir(directory, allowed_base=directory)
    except Exception:
        entries = []
    if any(entry.name in COMPOSE_FILE_NAMES for entry in entries):
        return None
    return (
        "No compose.yaml, compose.yml, docker-compose.yaml or "
        "docker-compose.yml was found. A directory managed by Ansible's "
        "docker_container module has no Compose project file."
    )


async def _compose_directory(service: str) -> str:
    """Return the compose project directory for a service, or raise."""
    if not security.validate_service_name(service):
        raise ResolutionError(f"❌ Invalid service name: {service}")
    if not await executor.check_service_exists(service):
        raise ResolutionError(
            f"❌ Service '{service}' does not exist in "
            f"{security.services_base_path}/\n"
            "Compose operations require a service directory below services_path."
        )
    directory = f"{security.services_base_path.rstrip('/')}/{service}"
    reason = await _compose_management(directory)
    if reason is not None:
        raise ResolutionError(_not_compose_message(service, reason))
    return directory


def _container_block(resolution: Resolution, container: str, body: str) -> str:
    """Label a per-container block only when several containers are involved."""
    if resolution.multiple:
        return f"=== Container: {container} ===\n{body}"
    return body


def _select_containers(
    resolution: Resolution, container: str | None
) -> tuple[str, ...]:
    """Restrict a resolved service to one of its containers when requested."""
    if container is None:
        return resolution.containers

    if not security.validate_service_name(container):
        raise ResolutionError(f"❌ Invalid container name: {container}")

    if container not in resolution.containers:
        available = ", ".join(resolution.containers)
        raise ResolutionError(
            f"❌ Container '{container}' is not part of '{resolution.target}'.\n"
            f"Containers for this target: {available}"
        )

    return (container,)


def _log_time_error(field: str, value: str | None) -> str | None:
    """Return a user-facing error for an invalid ``since``/``until`` value."""
    if value is None:
        return None
    if security.validate_log_time(value, field):
        return None
    return (
        f"❌ Invalid {field} time: {value}\n"
        "Use an RFC3339 timestamp (e.g. 2026-10-18T21:00:00Z), a date "
        "(2026-10-18) or a relative duration (e.g. 30m, 2h, 1h30m)."
    )


def _journal_time_error(field: str, value: str | None) -> str | None:
    """Return an error for an invalid journalctl ``--since`` value."""
    if value is None:
        return None
    candidate = value[1:] if value.startswith("-") else value
    if security.validate_log_time(candidate, field):
        return None
    return (
        f"❌ Invalid {field} time: {value}\n"
        "Use an RFC3339 timestamp (e.g. 2026-10-18T21:00:00Z), a date "
        "(2026-10-18) or a relative duration (e.g. 2h, -2h, 1h30m)."
    )


def _journal_since(value: str | None) -> str | None:
    """Return a journalctl-compatible ``--since`` value."""
    if value is None or value.startswith("-"):
        return value
    if _JOURNAL_DURATION_PATTERN.match(value):
        return f"-{value}"
    return value


def _resolution_error_text(error: ResolutionError, target: str) -> str:
    """Add a host-unit hint when a container tool was given a systemd unit."""
    text = str(error)
    if security.validate_host_unit(target):
        text += (
            f"\n\n💡 '{target}' is a host systemd unit, not a container — "
            f"use get_host_service_logs('{target}') or "
            f"get_host_service_status('{target}')."
        )
    return text


def _file_logs_hint(service: str | None) -> str:
    """Explain that a service writes logs to files instead of Docker stdout."""
    if not service or service not in FILE_LOG_SERVICES:
        return ""
    return (
        f"\n\n💡 '{service}' writes its logs to files, not to container stdout. "
        "nginx/swag keep them under `/config/log/nginx/` inside the container; "
        "if that directory is mounted into the service, use "
        f"list_service_files('{service}', 'config/log/nginx') and then "
        f"get_service_file('{service}', 'config/log/nginx/error.log')."
    )


def _redact_env_file(content: str) -> tuple[str, list[str]]:
    """Mask credential values in a dotenv file and keep benign keys readable.

    :func:`redact_secrets` understands key names such as ``DB_PASSWORD``,
    ``JWT_SECRET`` and ``API_KEY`` while leaving ordinary configuration
    (``DB_HOST``, ``TZ``) visible. A non-assignment line is still masked, so a
    quoted multi-line secret cannot leak through a continuation line.
    """
    lines: list[str] = []
    redacted_keys: list[str] = []
    for line in content.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue

        match = _ENV_ASSIGNMENT_PATTERN.match(line)
        if match is None:
            lines.append("***")
            continue

        redacted = redact_secrets(line)
        if redacted != line:
            redacted_keys.append(match.group("key"))
        lines.append(redacted)

    redacted = "\n".join(lines)
    if content.endswith("\n"):
        redacted += "\n"
    return redacted, redacted_keys


def _render_logs_command(
    container: str,
    lines: int,
    since: str | None,
    until: str | None,
) -> str:
    """Render ``docker logs`` for one container with optional time filters."""
    operation = catalog.logs(since=since, until=until)
    params: dict[str, str | int] = {"service": container, "lines": lines}
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    return operation.render(**params)


def _container_running(inspect_output: str) -> bool | None:
    """Return the ``State.Running`` value from inspect output, if present."""
    for line in inspect_output.splitlines():
        if line.startswith("Running:"):
            return line.split(":", 1)[1].strip().lower() == "true"
    return None


def _inspect_fields(container: str, inspect_output: str) -> dict[str, object]:
    """Parse the catalog's ``docker inspect`` format into structured fields."""
    fields: dict[str, object] = {"container": container}
    for line in inspect_output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        key = key.strip()
        if key == "Running":
            fields["running"] = value.lower() == "true"
        elif key in {"FailingStreak", "RestartCount", "ExitCode"}:
            try:
                fields[key.lower()] = int(value)
            except ValueError:
                fields[key.lower()] = value
        elif key:
            fields[key.lower()] = value
    return fields


def _resource_usage(inspect_output: str, stats_output: str) -> str:
    """Replace zeroed ``docker stats`` data for a stopped container."""
    if _container_running(inspect_output) is False:
        return "Container is not running; resource usage is unavailable."
    return stats_output


def _host_unit_error(unit: str) -> str:
    """Explain why a host unit was rejected and list the allowed names."""
    allowed = ", ".join(sorted(security.allowed_host_units)) or "(none configured)"
    return (
        f"❌ Host unit not allowed: '{unit}'\n"
        "Host infrastructure services are restricted to an explicit allowlist.\n"
        f"Allowed units (security.host_units): {allowed}"
    )


async def _run_on_containers(
    resolution: Resolution, operation: Operation, action: str
) -> ToolOutput:
    """Run a container action for each resolved container and collect output."""
    blocks = []
    failed = []
    for container in resolution.containers:
        output = await executor.execute_safe_command(
            operation.render(service=container)
        )
        if command_failure(output) is not None:
            failed.append(container)
        blocks.append(_container_block(resolution, container, output))

    message = f"Service '{resolution.target}' {action}"
    if failed:
        message = f"⚠️ {message} with failures: {', '.join(failed)}"
    else:
        message = f"✅ {message}"
    text = _cap_composite(f"{message}\n" + "\n\n".join(blocks))
    return ToolOutput(
        text,
        ok=not failed,
        data={
            "target": resolution.target,
            "service": resolution.service,
            "action": action,
            "containers": list(resolution.containers),
            "failed": failed,
        },
    )


def configure_logging() -> None:
    """Configure logging from MCP_LOG_LEVEL (called at startup, not on import)."""
    level_name = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level)


def apply_config(config_path: Path | None = None) -> Path:
    """(Re)load configuration and rebuild the dependent objects in place."""
    global security, executor, catalog, rate_limiter

    _metric_clients.clear()
    resolved = resolve_config_path(
        config_path, env_var=CONFIG_ENV_VAR, app_name=APP_NAME
    )
    if resolved is None:
        # Raises ConfigNotFoundError with an actionable message.
        load_config(
            config_path,
            env_var=CONFIG_ENV_VAR,
            app_name=APP_NAME,
            required=True,
        )
        raise ConfigNotFoundError("No configuration file found")

    new_config = load_config(resolved, required=True)
    config.clear()
    config.update(new_config)
    security = SecurityValidator(config)
    executor = create_executor(config, security)
    catalog = build_container_catalog(security.container_runtime)
    rate_limiter = create_rate_limiter(config)
    return resolved


@structured_tool(READ_ONLY)
async def list_services() -> str | ToolOutput:
    """List all services in /srv/ directory.

    Returns:
        List of service directories and their status
    """
    try:
        base_path = security.services_base_path.rstrip("/") + "/"
        services = await executor.execute_safe_command(
            LS_SERVICES.render(path=base_path)
        )
        docker = await executor.execute_safe_command(catalog.ps.render())
        text = _cap_composite(
            f"=== Services in {base_path} ===\n{services}\n"
            f"=== Docker Status ===\n{docker}"
        )
        return ToolOutput(
            text,
            data={
                "services_path": security.services_base_path,
                "services": [line for line in services.splitlines() if line.strip()],
                "docker_status": docker,
            },
        )
    except Exception as e:
        return f"❌ Error listing services: {e}"


@structured_tool(READ_ONLY)
async def list_containers() -> str | ToolOutput:
    """List every Docker container, including stopped and crashed ones.

    Shows each container's name, compose project, service directory mapping
    and Docker status. A container can be addressed by name when it belongs to
    a service directory or is listed in security.allowed_containers.

    Returns:
        Container table with names, projects and status
    """
    try:
        containers = await collect_containers(executor, catalog)
    except ResolutionError as e:
        return str(e)
    except Exception as e:
        return f"❌ Error listing containers: {e}"

    if not containers:
        return "No Docker containers found."

    directory_warning = ""
    try:
        directories = await collect_service_directories(executor, security)
    except ResolutionError as e:
        directories = set()
        directory_warning = (
            "\n\n⚠️ Could not map service directories; SERVICE shows '-' where "
            f"the mapping is unknown.\n{e}"
        )

    table = format_container_table(
        containers,
        directories=directories,
        allowed_containers=security.allowed_containers,
    )
    text = _cap_composite(
        f"=== Docker Containers ({len(containers)}) ===\n{table}{directory_warning}"
    )
    return ToolOutput(
        text,
        data={
            "count": len(containers),
            "containers": [
                {
                    "name": container.name,
                    "project": container.project,
                    "service": service_target(
                        container,
                        directories,
                        security.allowed_containers,
                    ),
                    "status": container.status,
                }
                for container in containers
            ],
        },
    )


@structured_tool(READ_ONLY)
async def get_host_service_status(unit: str) -> str | ToolOutput:
    """Get the systemd status of an allowlisted host infrastructure service.

    Host services such as telegraf, smartmontools or docker are systemd units,
    not Docker containers, so they are not reachable through get_service_status.
    Only units listed in security.host_units may be inspected.

    Args:
        unit: Host service unit name (e.g. 'telegraf', 'docker')

    Returns:
        systemctl status output for the unit
    """
    if not security.validate_host_unit(unit):
        _audit("host_unit_blocked", unit=unit, tool="get_host_service_status")
        return _host_unit_error(unit)

    try:
        output = await executor.execute_safe_command(SYSTEMCTL_STATUS.render(unit=unit))
        status = redact_secrets(output)
        text = _cap_composite(f"=== Host Service: {unit} ===\n{status}")
        return ToolOutput(
            text,
            data={
                "unit": unit,
                "source": "systemctl",
                "status": status,
                "entries": status.splitlines(),
            },
        )
    except Exception as e:
        return f"❌ Error getting host service status: {e}"


def _render_host_logs(unit: str, lines: int, since: str | None) -> str:
    """Render ``journalctl`` for one allowlisted unit."""
    normalized_since = _journal_since(since)
    operation = journalctl_unit_operation(since=normalized_since)
    params: dict[str, str | int] = {"unit": unit, "lines": lines}
    if normalized_since:
        params["since"] = normalized_since
    return operation.render(**params)


@structured_tool(READ_ONLY)
async def get_host_service_logs(
    unit: str, lines: int = 100, since: str | None = None
) -> str | ToolOutput:
    """Get recent journal entries for an allowlisted host service.

    Host infrastructure services such as telegraf, smartmontools or docker write
    to the systemd journal instead of a Docker log. Only units listed in
    security.host_units may be read.

    Args:
        unit: Host service unit name (e.g. 'telegraf', 'docker')
        lines: Number of journal lines (default: 100, max: 5000)
        since: Only entries newer than this time (RFC3339, date or `-30m`)

    Returns:
        Recent journal entries with ISO timestamps
    """
    if not security.validate_host_unit(unit):
        _audit("host_unit_blocked", unit=unit, tool="get_host_service_logs")
        return _host_unit_error(unit)

    error = _journal_time_error("since", since)
    if error is not None:
        return error

    lines = max(1, min(lines, 5000))
    try:
        output = await executor.execute_safe_command(
            _render_host_logs(unit, lines, since)
        )
        entries = redact_secrets(output).splitlines()
        window = f", since {since}" if since else ""
        text = _cap_composite(
            f"=== Journal: {unit} (last {lines} lines{window}) ===\n"
            + "\n".join(entries)
        )
        return ToolOutput(
            text,
            data={
                "unit": unit,
                "lines": lines,
                "since": since,
                "source": "journalctl",
                "entries": entries,
            },
        )
    except Exception as e:
        return f"❌ Error getting host service logs: {e}"


@structured_tool(READ_ONLY)
async def search_host_service_logs(
    unit: str, pattern: str, lines: int = 1000, since: str | None = None
) -> str | ToolOutput:
    """Search an allowlisted host service's journal for a literal pattern.

    Args:
        unit: Host service unit name (e.g. 'telegraf', 'docker')
        pattern: Literal text to search for (no regex; punctuation is preserved)
        lines: Number of journal lines to search (default: 1000, max: 5000)
        since: Only entries newer than this time (RFC3339, date or `-30m`)

    Returns:
        Matching journal lines with ISO timestamps
    """
    if not security.validate_host_unit(unit):
        _audit("host_unit_blocked", unit=unit, tool="search_host_service_logs")
        return _host_unit_error(unit)

    try:
        exact_pattern = security.validate_search_pattern(pattern)
    except ValueError as e:
        return f"❌ Invalid search pattern: {e}"

    error = _journal_time_error("since", since)
    if error is not None:
        return error

    lines = max(1, min(lines, 5000))
    try:
        output = await executor.execute_safe_command(
            _render_host_logs(unit, lines, since)
        )
        entries = [
            line
            for line in redact_secrets(output).splitlines()
            if exact_pattern in line
        ]
        if not entries:
            return ToolOutput(
                f"No matches found for '{exact_pattern}' in last {lines} journal "
                f"lines for {unit}",
                data={
                    "unit": unit,
                    "pattern": exact_pattern,
                    "lines": lines,
                    "since": since,
                    "matches": [],
                },
            )
        return ToolOutput(
            _cap_composite("\n".join(entries)),
            data={
                "unit": unit,
                "pattern": exact_pattern,
                "lines": lines,
                "since": since,
                "matches": entries,
            },
        )
    except Exception as e:
        return f"❌ Error searching host service logs: {e}"


@structured_tool(READ_ONLY)
async def get_service_logs(
    service: str,
    lines: int = 100,
    since: str | None = None,
    until: str | None = None,
    container: str | None = None,
) -> str | ToolOutput:
    """Get timestamped logs for a service directory or a container name.

    Args:
        service: Service directory or container name
        lines: Number of log lines per container (default: 100, max: 1000)
        since: Only logs newer than this time (RFC3339, date or `30m`)
        until: Only logs older than this time (RFC3339, date or `2h`)
        container: Optional container name to target within a compose project

    Returns:
        Service logs with Docker timestamps, labelled per container
    """
    for field, value in (("since", since), ("until", until)):
        error = _log_time_error(field, value)
        if error is not None:
            return error

    try:
        resolution = await _resolve_service(service)
        containers = _select_containers(resolution, container)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    # Limit lines to prevent abuse
    lines = max(1, min(lines, 1000))

    try:
        blocks = []
        for name in containers:
            # Use '--' to prevent Docker option injection even if service
            # validation is somehow bypassed (defense in depth)
            cmd = _render_logs_command(name, lines, since, until)
            result = await executor.execute_safe_command(cmd)
            blocks.append(_container_block(resolution, name, result))
        text = _cap_composite("\n\n".join(blocks))
        return ToolOutput(
            text,
            data={
                "target": resolution.target,
                "service": resolution.service,
                "containers": list(containers),
                "lines": lines,
                "since": since,
                "until": until,
            },
        )
    except Exception as e:
        return f"❌ Error getting logs: {e}"


@structured_tool(READ_ONLY)
async def get_service_status(service: str) -> str | ToolOutput:
    """Get detailed status of a service directory or container name.

    Args:
        service: Service directory or container name

    Returns:
        Docker state, resource usage and ports per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    try:
        blocks = []
        container_data: list[dict] = []
        for container in resolution.containers:
            inspect_output = await executor.execute_safe_command(
                catalog.inspect.render(service=container)
            )
            container_data.append(_inspect_fields(container, inspect_output))
            status = f"=== Docker Status ===\n{inspect_output}"

            # ``docker stats`` waits 1-2 seconds per container and ``docker
            # port`` is also meaningless for a stopped container. Inspect is
            # the source of truth, so skip both calls when it is not running.
            if _container_running(inspect_output) is False:
                status += (
                    "\n\n=== Resource Usage ===\n"
                    "Container is not running; resource usage is unavailable."
                    "\n\n=== Ports ===\n"
                    "Container is not running; ports are unavailable."
                )
            else:
                stats_output = await executor.execute_safe_command(
                    catalog.stats.render(service=container)
                )
                status += (
                    "\n\n=== Resource Usage ===\n"
                    f"{_resource_usage(inspect_output, stats_output)}"
                )

                ports_output = await executor.execute_safe_command(
                    catalog.ports.render(service=container)
                )
                status += f"\n\n=== Ports ===\n{ports_output}"

            blocks.append(_container_block(resolution, container, status))
        text = _cap_composite("\n\n".join(blocks))
        return ToolOutput(
            text,
            data={
                "target": resolution.target,
                "service": resolution.service,
                "source": resolution.source,
                "containers": list(resolution.containers),
                "container_details": container_data,
            },
        )
    except Exception as e:
        return f"❌ Error getting service status: {e}"


def _format_container_health(container: str, output: str, entries: int) -> str:
    """Render the health JSON of one container, or a clear error text."""
    try:
        health = json.loads(output)
    except json.JSONDecodeError:
        # Docker errors are already human-readable and may include an exit code.
        return output

    if not health:
        return f"Container '{container}' has no healthcheck configured."

    status = health.get("Status", "unknown")
    failing_streak = health.get("FailingStreak", 0)
    log = health.get("Log") or []
    recent = log[-entries:]

    lines = [
        f"=== Health: {container} ===",
        f"Status: {status}",
        f"FailingStreak: {failing_streak}",
        "",
    ]
    if not recent:
        lines.append("No healthcheck probe results recorded yet.")
        return "\n".join(lines)

    lines.append(f"Last {len(recent)} probe(s):")
    for probe in recent:
        started_at = probe.get("Start", "unknown")
        exit_code = probe.get("ExitCode", "?")
        probe_output = str(probe.get("Output", "")).strip()
        lines.append(f"  [{started_at}] exit {exit_code}")
        for line in probe_output.splitlines():
            lines.append(f"    {line}")
    return "\n".join(lines)


@structured_tool(READ_ONLY)
async def get_container_health(service: str, entries: int = 5) -> str | ToolOutput:
    """Get the Docker healthcheck status and recent probe output.

    Args:
        service: Service directory or container name
        entries: Number of recent probe results to return (default: 5, max: 20)

    Returns:
        Health status, failing streak and recent probe output
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    entries = max(1, min(entries, 20))
    try:
        blocks = []
        for container in resolution.containers:
            output = await executor.execute_safe_command(
                catalog.health.render(service=container)
            )
            body = _format_container_health(container, output, entries)
            blocks.append(_container_block(resolution, container, body))
        text = _cap_composite("\n\n".join(blocks))
        return ToolOutput(
            text,
            data={
                "target": resolution.target,
                "service": resolution.service,
                "containers": list(resolution.containers),
                "entries": entries,
            },
        )
    except Exception as e:
        return f"❌ Error getting container health: {e}"


@structured_tool(DESTRUCTIVE_ACTION)
async def restart_service(service: str, confirm: bool = False) -> str | ToolOutput:
    """Restart a service directory or container (all resolved containers).

    State-changing by definition, so ``confirm`` must be true.

    Args:
        service: Service directory or container name
        confirm: Must be true to execute; false returns a dry-run preview

    Returns:
        Restart result per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    if not confirm:
        return _confirmation_required(
            "restart",
            resolution.target,
            " ".join(
                catalog.restart.render(service=name) for name in resolution.containers
            ),
        )
    limited = _rate_limited("restart_service")
    if limited is not None:
        return limited

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        return await _run_on_containers(resolution, catalog.restart, "restarted")
    except Exception as e:
        return f"❌ Error restarting service: {e}"


@structured_tool(WRITE_ACTION)
async def start_service(service: str, confirm: bool = False) -> str | ToolOutput:
    """Start a stopped service directory or container.

    Containers that are already running are reported as such and are not
    passed to ``docker start``. State-changing by definition when a container
    is stopped, so ``confirm`` must be true.

    Args:
        service: Service directory or container name
        confirm: Must be true to execute; false returns a dry-run preview

    Returns:
        Start result per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    if not confirm:
        return _confirmation_required(
            "start",
            resolution.target,
            " ".join(
                catalog.start.render(service=name) for name in resolution.containers
            ),
        )
    limited = _rate_limited("start_service")
    if limited is not None:
        return limited

    try:
        blocks: list[str] = []
        already_running: list[str] = []
        started: list[str] = []
        failed: list[str] = []
        for container in resolution.containers:
            inspect_output = await executor.execute_safe_command(
                catalog.inspect.render(service=container)
            )
            if _container_running(inspect_output) is True:
                already_running.append(container)
                blocks.append(
                    _container_block(
                        resolution,
                        container,
                        f"✅ {container} is already running; no action taken.",
                    )
                )
                continue

            output = await executor.execute_safe_command(
                catalog.start.render(service=container)
            )
            if command_failure(output) is not None:
                failed.append(container)
            else:
                started.append(container)
            blocks.append(_container_block(resolution, container, output))

        if failed:
            message = (
                f"⚠️ Service '{resolution.target}' started with failures: "
                f"{', '.join(failed)}"
            )
        elif started:
            message = f"✅ Service '{resolution.target}' started"
        else:
            message = f"✅ Service '{resolution.target}' was already running"
        text = _cap_composite(f"{message}\n" + "\n\n".join(blocks))
        return ToolOutput(
            text,
            ok=not failed,
            data={
                "target": resolution.target,
                "service": resolution.service,
                "action": "started",
                "containers": list(resolution.containers),
                "already_running": already_running,
                "started": started,
                "failed": failed,
                "changed": bool(started),
            },
        )
    except Exception as e:
        return f"❌ Error starting service: {e}"


@structured_tool(DESTRUCTIVE_ACTION)
async def stop_service(service: str, confirm: bool = False) -> str | ToolOutput:
    """Stop a running service directory or container.

    State-changing by definition, so ``confirm`` must be true.

    Args:
        service: Service directory or container name
        confirm: Must be true to execute; false returns a dry-run preview

    Returns:
        Stop result per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    if not confirm:
        return _confirmation_required(
            "stop",
            resolution.target,
            " ".join(
                catalog.stop.render(service=name) for name in resolution.containers
            ),
        )
    limited = _rate_limited("stop_service")
    if limited is not None:
        return limited

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        return await _run_on_containers(resolution, catalog.stop, "stopped")
    except Exception as e:
        return f"❌ Error stopping service: {e}"


@structured_tool(READ_ONLY)
async def compose_ps(service: str) -> str | ToolOutput:
    """Show containers for a compose project directory.

    Compose commands are scoped to ``services_path/<service>``; the service
    name is validated before execution and no arbitrary compose arguments are
    accepted.

    Args:
        service: Service directory name below services_path

    Returns:
        ``compose ps`` output for the project
    """
    try:
        directory = await _compose_directory(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    try:
        output = await executor.execute_safe_command(
            catalog.compose_ps.render(directory=directory)
        )
        text = _cap_composite(f"=== Compose Status: {service} ===\n{output}")
        return ToolOutput(
            text,
            ok=command_failure(output) is None,
            data={
                "service": service,
                "directory": directory,
                "runtime": catalog.runtime,
            },
        )
    except Exception as e:
        return f"❌ Error getting compose status: {e}"


async def _run_compose_action(
    service: str, operation: Operation, action: str, confirm: bool
) -> str | ToolOutput:
    """Run a mutating compose action after confirmation and rate limiting."""
    try:
        directory = await _compose_directory(service)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    command = operation.render(directory=directory)
    if not confirm:
        return _confirmation_required(f"compose {action}", service, command)

    limited = _rate_limited(f"compose_{action}")
    if limited is not None:
        return limited

    try:
        output = await executor.execute_safe_command(command)
    except Exception as e:
        return f"❌ Error running compose {action}: {e}"

    ok = command_failure(output) is None
    marker = "✅" if ok else "⚠️"
    text = _cap_composite(
        f"{marker} compose {action} '{service}'\n\n{output.strip() or '(no output)'}"
    )
    return ToolOutput(
        text,
        ok=ok,
        data={
            "service": service,
            "directory": directory,
            "runtime": catalog.runtime,
            "action": action,
        },
    )


@structured_tool(WRITE_ACTION)
async def compose_pull(service: str, confirm: bool = False) -> str | ToolOutput:
    """Pull the images of a compose project (requires confirm=true).

    Args:
        service: Service directory name below services_path
        confirm: Must be true to execute; false returns a dry-run preview

    Returns:
        ``compose pull`` output
    """
    return await _run_compose_action(service, catalog.compose_pull, "pull", confirm)


@structured_tool(WRITE_ACTION)
async def compose_up(service: str, confirm: bool = False) -> str | ToolOutput:
    """Start a compose project in the background (requires confirm=true).

    Args:
        service: Service directory name below services_path
        confirm: Must be true to execute; false returns a dry-run preview

    Returns:
        ``compose up`` output
    """
    return await _run_compose_action(service, catalog.compose_up, "up", confirm)


@structured_tool(DESTRUCTIVE_ACTION)
async def compose_down(service: str, confirm: bool = False) -> str | ToolOutput:
    """Stop and remove a compose project (requires confirm=true).

    Args:
        service: Service directory name below services_path
        confirm: Must be true to execute; false returns a dry-run preview

    Returns:
        ``compose down`` output
    """
    return await _run_compose_action(service, catalog.compose_down, "down", confirm)


@structured_tool(READ_ONLY)
async def get_service_file(service: str, file_path: str) -> str | ToolOutput:
    """Get the contents of a file within a service directory.

    Args:
        service: Service name (must exist in /srv/)
        file_path: Relative path within /srv/{service}/ (e.g., 'docker-compose.yml')

    Returns:
        File contents. Values in ``.env`` files are masked; private keys,
        credential stores and other sensitive files are refused.
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Construct and validate the full path, including the sensitive-file policy
    check = security.check_service_file_path(service, file_path)
    if check.path is None:
        if check.access is FileAccess.BLOCKED_SENSITIVE:
            _audit(
                "file_blocked_sensitive",
                service=service,
                path=file_path,
                reason=check.reason,
            )
            return (
                f"❌ Blocked by the sensitive-file policy: {file_path}\n"
                f"{check.reason}. Private keys, credential stores and secret "
                "files are never returned. Use ``.env`` files for compose "
                "variable names; their values are masked."
            )
        return (
            f"❌ Invalid file path: {file_path}\n"
            f"{check.reason}. The path must be relative and resolve inside "
            f"{security.services_base_path.rstrip('/')}/{service}/"
        )

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    service_base = f"{security.services_base_path.rstrip('/')}/{service}"
    try:
        content = await executor.read_remote_file(check.path, allowed_base=service_base)
    except Exception as e:
        return f"❌ Error reading file: {e}"

    redacted_keys: list[str] = []
    if check.access is FileAccess.REDACT:
        redacted_text, redacted_keys = _redact_env_file(content)
        redacted = redacted_text != content
        text = _cap_composite(
            f"{redacted_text}\n\n"
            "(Credential values are masked by key name; non-assignment lines "
            "are masked too.)"
        )
    else:
        redacted_content = redact_secrets(content)
        redacted = redacted_content != content
        text = _cap_composite(redacted_content)
        if redacted:
            text += "\n\n(Sensitive values are masked by the security policy.)"
    return ToolOutput(
        text,
        data={
            "service": service,
            "path": check.path,
            "redacted": redacted,
            "redacted_keys": redacted_keys,
        },
    )


@structured_tool(READ_ONLY)
async def list_service_files(service: str, subdirectory: str = "") -> str | ToolOutput:
    """List files in a service directory.

    Args:
        service: Service name (must exist in /srv/)
        subdirectory: Optional subdirectory within /srv/{service}/

    Returns:
        List of files
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Validate subdirectory path, including the sensitive-file policy
    if subdirectory:
        check = security.check_service_file_path(service, subdirectory)
        if check.path is None:
            if check.access is FileAccess.BLOCKED_SENSITIVE:
                _audit(
                    "file_blocked_sensitive",
                    service=service,
                    path=subdirectory,
                    reason=check.reason,
                    tool="list_service_files",
                )
                return (
                    f"❌ Blocked by the sensitive-file policy: {subdirectory}\n"
                    f"{check.reason}"
                )
            return (
                f"❌ Invalid subdirectory: {subdirectory}\n"
                f"{check.reason}. The path must be relative and resolve inside "
                f"{security.services_base_path.rstrip('/')}/{service}/"
            )
        full_path = check.path
    else:
        base_path = security.services_base_path.rstrip("/")
        full_path = f"{base_path}/{service}"

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    service_base = f"{security.services_base_path.rstrip('/')}/{service}"
    try:
        entries = await executor.list_remote_dir(full_path, allowed_base=service_base)
    except Exception as e:
        return (
            f"❌ Error listing files in {full_path}: {e}\n"
            f"The path must be inside {service_base}/; the directory may not "
            "exist. Call list_service_files without a subdirectory to list "
            "the service root."
        )

    if not entries:
        return ToolOutput(
            f"No files found in {full_path}",
            data={"service": service, "path": full_path, "entries": []},
        )
    text = _cap_composite("\n".join(entry.longname for entry in entries))
    return ToolOutput(
        text,
        data={
            "service": service,
            "path": full_path,
            "entries": [{"name": entry.name, "size": entry.size} for entry in entries],
        },
    )


@structured_tool(READ_ONLY)
async def search_service_logs(
    service: str,
    pattern: str,
    lines: int = 1000,
    since: str | None = None,
    until: str | None = None,
    container: str | None = None,
) -> str | ToolOutput:
    """Search service logs for a literal text pattern.

    Args:
        service: Service directory or container name
        pattern: Literal text to search for (no regex; punctuation is preserved)
        lines: Number of log lines to search per container (default: 1000, max: 5000)
        since: Only logs newer than this time (RFC3339, date or `30m`)
        until: Only logs older than this time (RFC3339, date or `2h`)
        container: Optional container name to target within a compose project

    Returns:
        Matching log lines, labelled per container for multi-container services
    """
    try:
        exact_pattern = security.validate_search_pattern(pattern)
    except ValueError as e:
        return f"❌ Invalid search pattern: {e}"

    for field, value in (("since", since), ("until", until)):
        error = _log_time_error(field, value)
        if error is not None:
            return error

    try:
        resolution = await _resolve_service(service)
        containers = _select_containers(resolution, container)
    except ResolutionError as e:
        return _resolution_error_text(e, service)

    # Limit lines
    lines = max(1, min(lines, 5000))

    try:
        matches = []
        for name in containers:
            cmd = _render_logs_command(name, lines, since, until)
            output = await executor.execute_safe_command(cmd)

            # Filter locally: no shell pipe, so the local executor works too.
            container_matches = [
                line for line in output.splitlines() if exact_pattern in line
            ]
            if resolution.multiple:
                matches.extend(f"[{name}] {line}" for line in container_matches)
            else:
                matches.extend(container_matches)

        if not matches:
            hint = _file_logs_hint(resolution.service or resolution.target)
            return ToolOutput(
                f"No matches found for '{exact_pattern}' in last {lines} lines{hint}",
                data={
                    "target": resolution.target,
                    "pattern": exact_pattern,
                    "matches": [],
                },
            )

        text = _cap_composite("\n".join(matches))
        return ToolOutput(
            text,
            data={
                "target": resolution.target,
                "service": resolution.service,
                "pattern": exact_pattern,
                "containers": list(containers),
                "matches": matches,
            },
        )
    except Exception as e:
        return f"❌ Error searching logs: {e}"


QUERY_SUCCESS_PREFIX = "✅ Query successful"


def _query_data(result: str) -> dict:
    """Extract the JSON payload from a query response, when there is one."""
    if not result.startswith(QUERY_SUCCESS_PREFIX):
        return {}
    try:
        payload = json.loads(result.split("\n\n", 1)[1])
    except (json.JSONDecodeError, IndexError):
        return {}
    if isinstance(payload, list):
        return {"rows": payload, "row_count": len(payload)}
    return {"result": payload}


@structured_tool(READ_ONLY)
async def query_influxdb(query: str, database: str | None = None) -> str | ToolOutput:
    """Query InfluxDB v3 using SQL (read-only).

    Executes a SELECT query against the InfluxDB v3 HTTP API.
    Requires influxdb to be enabled in config.yaml.

    InfluxDB v3 SQL does not return ``GROUP BY`` keys unless they are also
    projected by the ``SELECT`` list. Write ``SELECT host, count(*) ... GROUP BY
    host`` rather than ``SELECT count(*) ... GROUP BY host`` or the rows have no
    ``host`` column.

    Args:
        query: SQL query (must start with SELECT)
        database: Database name (overrides config default)

    Returns:
        Query results in JSON format
    """
    influxdb_config = config.get("influxdb", {})
    if not influxdb_config.get("enabled", False):
        return (
            "❌ InfluxDB queries are not enabled.\n"
            "Set 'influxdb.enabled: true' in config.yaml and configure host/port."
        )

    # Validate the query
    validated_query = security.validate_influxdb_query(query)
    if validated_query is None:
        _audit("query_blocked", kind="influxdb", query_length=len(query))
        return (
            "❌ Invalid query. Queries must:\n"
            "- Be a single SELECT (read-only only)\n"
            "- Not contain SQL comments (-- or /* */)\n"
            "- Not contain control characters"
        )

    db = database or influxdb_config.get("database")
    if not db:
        return (
            "❌ No database specified. Provide 'database' parameter or set "
            "'influxdb.database' in config.yaml."
        )

    client = _get_influxdb_client()
    result = await client.query(validated_query, database=db)
    advisory = influxdb_group_by_advisory(validated_query)
    text = result if advisory is None else f"{result}\n\n💡 {advisory}"
    data: dict = {"database": db, **_query_data(result)}
    if advisory is not None:
        data["advisory"] = advisory
    return ToolOutput(text, data=data)


@structured_tool(READ_ONLY)
async def query_prometheus(query: str, time: str | None = None) -> str | ToolOutput:
    """Query Prometheus using PromQL (read-only).

    Executes an instant query against the Prometheus HTTP API.
    Requires prometheus to be enabled in config.yaml.

    Args:
        query: PromQL expression
        time: Optional RFC3339 timestamp or Unix timestamp (defaults to now)

    Returns:
        Query results in JSON format
    """
    prometheus_config = config.get("prometheus", {})
    if not prometheus_config.get("enabled", False):
        return (
            "❌ Prometheus queries are not enabled.\n"
            "Set 'prometheus.enabled: true' in config.yaml and configure host/port."
        )

    validated_query = security.validate_prometheus_query(query)
    if validated_query is None:
        _audit("query_blocked", kind="prometheus", query_length=len(query))
        return (
            "❌ Invalid query. Queries must:\n"
            "- Not contain null bytes or control characters other than newline/tab\n"
            "- Be at most 5000 characters\n"
            "- Be a single PromQL expression"
        )

    client = _get_prometheus_client()
    result = await client.query(validated_query, time)
    return ToolOutput(result, data=_query_data(result))


@structured_tool(READ_ONLY)
async def get_prometheus_targets() -> str | ToolOutput:
    """Get scrape targets from Prometheus.

    Returns the list of all configured scrape targets and their current state.
    Requires prometheus to be enabled in config.yaml.

    Returns:
        List of scrape targets with their status
    """
    prometheus_config = config.get("prometheus", {})
    if not prometheus_config.get("enabled", False):
        return (
            "❌ Prometheus queries are not enabled.\n"
            "Set 'prometheus.enabled: true' in config.yaml and configure host/port."
        )

    client = _get_prometheus_client()
    result = await client.get_targets()
    return ToolOutput(result, data=_query_data(result))


@structured_tool(READ_ONLY)
async def get_server_health() -> str | ToolOutput:
    """Get overall server health (CPU, memory, disk, containers).

    Disk usage is reported for each mount point in ``health.disk_paths``
    (default ``["/"]``), so NAS pools such as ``/mnt/storage`` appear next to
    the root filesystem. Containers whose Docker healthcheck is failing are
    listed separately.

    Returns:
        Server health metrics only
    """
    try:
        commands = [
            ("=== System Uptime ===", UPTIME.render()),
            ("=== Memory Usage ===", FREE_MEMORY.render()),
        ]
        commands.extend(
            (
                f"=== Disk Usage ({path}) ===",
                DISK_USAGE.render(path=path),
            )
            for path in security.health_disk_paths
        )
        commands.extend(
            [
                ("=== Running Services ===", catalog.ps.render()),
                ("=== Unhealthy Containers ===", catalog.ps_unhealthy.render()),
            ]
        )

        results = []
        sections: dict[str, str] = {}
        for title, cmd in commands:
            output = await executor.execute_safe_command(cmd)
            body = output.strip() or "(none)"
            results.append(f"{title}\n{body}")
            sections[title] = body

        text = _cap_composite("\n\n".join(results))
        return ToolOutput(
            text,
            data={
                "disk_paths": list(security.health_disk_paths),
                "container_runtime": catalog.runtime,
                "sections": sections,
            },
        )
    except Exception as e:
        return f"❌ Error getting server health: {e}"


# ============================================================================
# MCP resources (read-only documentation and metadata)
# ============================================================================


def _tool_metadata(name: str) -> dict:
    """Describe one registered MCP tool."""
    tool = mcp._tool_manager.get_tool(name)
    if tool is None:
        raise ValueError(f"Unknown tool: {name}")
    annotations = tool.annotations
    return {
        "name": tool.name,
        "description": tool.description,
        "read_only": bool(annotations and annotations.read_only_hint),
        "destructive": bool(annotations and annotations.destructive_hint),
        "idempotent": bool(annotations and annotations.idempotent_hint),
        "input_schema": tool.parameters,
        "output_schema": tool.output_schema,
    }


@mcp.resource(
    "server-mcp://config/schema",
    name="config-schema",
    title="Configuration schema",
    description="Configuration defaults and environment overrides (secrets masked).",
    mime_type="application/json",
)
def config_schema_resource() -> dict:
    """Return the configuration defaults with credential values masked."""
    return {"app": APP_NAME, **config_schema()}


@mcp.resource(
    "server-mcp://tools/catalog",
    name="tool-catalog",
    title="Tool catalog",
    description="Read-only, auditable list of the tools this server exposes.",
    mime_type="application/json",
)
def tool_catalog_resource() -> dict:
    """Return name, description and annotations for every tool."""
    return {
        "app": APP_NAME,
        "tools": [_tool_metadata(tool.name) for tool in mcp._tool_manager.list_tools()],
    }


@mcp.resource(
    "server-mcp://tools/{name}",
    name="tool-details",
    title="Tool details",
    description="Metadata and JSON schemas for a single tool.",
    mime_type="application/json",
)
def tool_details_resource(name: str) -> dict:
    """Return metadata for one registered tool."""
    return _tool_metadata(name)


async def main(
    config_path: Path | None = None,
    *,
    transport: str | None = None,
    http_host: str | None = None,
    http_port: int | None = None,
    http_path: str | None = None,
) -> None:
    """Run the MCP server."""
    configure_logging()

    try:
        resolved = apply_config(config_path)
    except ConfigNotFoundError as e:
        logger.error("%s", e)
        raise SystemExit(2) from e

    logger.info("Using configuration: %s", resolved)
    logger.info("Testing SSH connection...")
    try:
        result = await executor.execute_safe_command(ECHO_CONNECTION.render())
        logger.info(f"SSH connection test: {result.strip()}")
    except Exception as e:
        logger.warning(f"SSH connection test failed: {e}")
        logger.warning(
            "Server will start anyway, but tools may fail until SSH is configured"
        )

    tunnels: list = []
    try:
        tunnels = await open_metric_tunnels(config)
    except Exception as e:
        logger.error("Failed to open a configured SSH tunnel: %s", e)
        raise SystemExit(2) from e
    for active in tunnels:
        logger.info(
            "SSH tunnel for %s: %s:%s",
            active.section,
            active.endpoint.host,
            active.endpoint.port,
        )

    logger.info("Starting Remote Server MCP (SECURE MODE)...")
    logger.info(
        "Available tools: list_services, list_containers, get_service_logs, "
        "get_service_status, get_container_health, get_host_service_status, "
        "get_host_service_logs, search_host_service_logs, restart_service, "
        "start_service, stop_service, compose_ps, compose_pull, compose_up, "
        "compose_down, get_service_file, list_service_files, "
        "search_service_logs, get_server_health, query_influxdb, "
        "query_prometheus, get_prometheus_targets"
    )

    transport_config = config.get("transport", {}) or {}
    selected = transport or str(transport_config.get("type", "stdio"))
    try:
        if selected == "stdio":
            await mcp.run_stdio_async()
        elif selected in {"streamable-http", "streamable_http", "http"}:
            host = http_host or str(transport_config.get("host", "127.0.0.1"))
            port = http_port or int(transport_config.get("port", 8000))
            path = http_path or str(transport_config.get("path", "/mcp"))
            token = transport_config.get("token") or None
            await run_streamable_http(mcp, host=host, port=port, token=token, path=path)
        else:
            logger.error("Unknown transport: %s", selected)
            raise SystemExit(2)
    except ValueError as e:
        logger.error("Invalid Streamable HTTP configuration: %s", e)
        raise SystemExit(2) from e
    finally:
        await close_metric_clients()
        await close_metric_tunnels(tunnels)


def cli() -> None:
    """Console entry point."""
    parser = argparse.ArgumentParser(description="Remote Server MCP server")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=f"Path to config.yaml (default: ${CONFIG_ENV_VAR} or XDG config)",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default=None,
        help="MCP transport (default: transport.type from config, else stdio)",
    )
    parser.add_argument(
        "--http-host",
        default=None,
        help="Streamable HTTP bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=None,
        help="Streamable HTTP port (default: 8000)",
    )
    parser.add_argument(
        "--http-path",
        default=None,
        help="Streamable HTTP endpoint path (default: /mcp)",
    )
    args = parser.parse_args()
    asyncio.run(
        main(
            args.config,
            transport=args.transport,
            http_host=args.http_host,
            http_port=args.http_port,
            http_path=args.http_path,
        )
    )


if __name__ == "__main__":
    cli()
