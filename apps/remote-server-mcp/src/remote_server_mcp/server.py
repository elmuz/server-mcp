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
    close_metric_tunnels,
    create_audit_logger,
    create_executor,
    load_config,
    open_metric_tunnels,
    parse_duration,
    redact_env_content,
    resolve_config_path,
    sanitize_output,
)

from .operations import (
    DISK_USAGE,
    DOCKER_HEALTH,
    DOCKER_INSPECT,
    DOCKER_PORTS,
    DOCKER_PS,
    DOCKER_PS_UNHEALTHY,
    DOCKER_RESTART,
    DOCKER_START,
    DOCKER_STATS,
    DOCKER_STOP,
    ECHO_CONNECTION,
    FREE_MEMORY,
    JOURNALCTL_UNIT,
    LS_SERVICES,
    SYSTEMCTL_STATUS,
    UPTIME,
    docker_logs_operation,
)
from .resolution import (
    Resolution,
    ResolutionError,
    collect_containers,
    collect_service_directories,
    command_failure,
    format_container_table,
    resolve_service_target,
)

APP_NAME = "remote-server-mcp"
CONFIG_ENV_VAR = "REMOTE_SERVER_MCP_CONFIG"

logger = logging.getLogger(__name__)

# Best-effort load so the module stays importable (tests, tooling). The server
# itself refuses to start without a real configuration file (see main()).
config = load_config(env_var=CONFIG_ENV_VAR, app_name=APP_NAME, log_missing=False)
security = SecurityValidator(config)
executor = create_executor(config, security)

mcp = MCPServer("remote-server-mcp")

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


def _max_output_bytes() -> int:
    output_config = config.get("output", {}) or {}
    return int(output_config.get("max_bytes", DEFAULT_MAX_OUTPUT_BYTES))


def _cap_composite(text: str) -> str:
    """Apply the response cap to output assembled from several commands."""
    return sanitize_output(text, _max_output_bytes(), label="tool output")


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
    return await resolve_service_target(executor, security, service)


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


def _render_logs_command(
    container: str,
    lines: int,
    since: str | None,
    until: str | None,
) -> str:
    """Render ``docker logs`` for one container with optional time filters."""
    operation = docker_logs_operation(since=since, until=until)
    params: dict[str, str | int] = {"service": container, "lines": lines}
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    return operation.render(**params)


def _resource_usage(inspect_output: str, stats_output: str) -> str:
    """Replace zeroed ``docker stats`` data for a stopped container."""
    for line in inspect_output.splitlines():
        if line.startswith("Running:"):
            if line.split(":", 1)[1].strip().lower() == "false":
                return "Container is not running; resource usage is unavailable."
            break
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
) -> str:
    """Run a Docker action for each resolved container and collect the output."""
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
    return _cap_composite(f"{message}\n" + "\n\n".join(blocks))


def configure_logging() -> None:
    """Configure logging from MCP_LOG_LEVEL (called at startup, not on import)."""
    level_name = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level)


def apply_config(config_path: Path | None = None) -> Path:
    """(Re)load configuration and rebuild the dependent objects in place."""
    global security, executor

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
    return resolved


@mcp.tool(annotations=READ_ONLY)
async def list_services() -> str:
    """List all services in /srv/ directory.

    Returns:
        List of service directories and their status
    """
    try:
        base_path = security.services_base_path.rstrip("/") + "/"
        services = await executor.execute_safe_command(
            LS_SERVICES.render(path=base_path)
        )
        docker = await executor.execute_safe_command(DOCKER_PS.render())
        return _cap_composite(
            f"=== Services in {base_path} ===\n{services}\n"
            f"=== Docker Status ===\n{docker}"
        )
    except Exception as e:
        return f"❌ Error listing services: {e}"


@mcp.tool(annotations=READ_ONLY)
async def list_containers() -> str:
    """List every Docker container, including stopped and crashed ones.

    Shows each container's name, compose project, service directory mapping
    and Docker status. A container can be addressed by name when it belongs to
    a service directory or is listed in security.allowed_containers.

    Returns:
        Container table with names, projects and status
    """
    try:
        containers = await collect_containers(executor)
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
    return _cap_composite(
        f"=== Docker Containers ({len(containers)}) ===\n{table}{directory_warning}"
    )


@mcp.tool(annotations=READ_ONLY)
async def get_host_service_status(unit: str) -> str:
    """Get the systemd status of an allowlisted host infrastructure service.

    Host services such as telegraf, smartd or docker are systemd units, not
    Docker containers, so they are not reachable through get_service_status.
    Only units listed in security.host_units may be inspected.

    Args:
        unit: Host service unit name (e.g. 'telegraf', 'docker')

    Returns:
        systemctl status output for the unit
    """
    if not security.validate_host_unit(unit):
        return _host_unit_error(unit)

    try:
        output = await executor.execute_safe_command(SYSTEMCTL_STATUS.render(unit=unit))
        return _cap_composite(f"=== Host Service: {unit} ===\n{output}")
    except Exception as e:
        return f"❌ Error getting host service status: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_host_service_logs(unit: str, lines: int = 100) -> str:
    """Get recent journal entries for an allowlisted host service.

    Host infrastructure services such as telegraf, smartd or docker write to
    the systemd journal instead of a Docker log. Only units listed in
    security.host_units may be read.

    Args:
        unit: Host service unit name (e.g. 'telegraf', 'docker')
        lines: Number of journal lines (default: 100, max: 1000)

    Returns:
        Recent journal entries with ISO timestamps
    """
    if not security.validate_host_unit(unit):
        return _host_unit_error(unit)

    lines = max(1, min(lines, 1000))
    try:
        output = await executor.execute_safe_command(
            JOURNALCTL_UNIT.render(unit=unit, lines=lines)
        )
        return _cap_composite(f"=== Journal: {unit} (last {lines} lines) ===\n{output}")
    except Exception as e:
        return f"❌ Error getting host service logs: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_service_logs(
    service: str,
    lines: int = 100,
    since: str | None = None,
    until: str | None = None,
    container: str | None = None,
) -> str:
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
        return str(e)

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
        return _cap_composite("\n\n".join(blocks))
    except Exception as e:
        return f"❌ Error getting logs: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_service_status(service: str) -> str:
    """Get detailed status of a service directory or container name.

    Args:
        service: Service directory or container name

    Returns:
        Docker state, resource usage and ports per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return str(e)

    try:
        blocks = []
        for container in resolution.containers:
            inspect_output = await executor.execute_safe_command(
                DOCKER_INSPECT.render(service=container)
            )
            status = f"=== Docker Status ===\n{inspect_output}"

            stats_output = await executor.execute_safe_command(
                DOCKER_STATS.render(service=container)
            )
            status += (
                "\n\n=== Resource Usage ===\n"
                f"{_resource_usage(inspect_output, stats_output)}"
            )

            ports_output = await executor.execute_safe_command(
                DOCKER_PORTS.render(service=container)
            )
            status += f"\n\n=== Ports ===\n{ports_output}"

            blocks.append(_container_block(resolution, container, status))
        return _cap_composite("\n\n".join(blocks))
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


@mcp.tool(annotations=READ_ONLY)
async def get_container_health(service: str, entries: int = 5) -> str:
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
        return str(e)

    entries = max(1, min(entries, 20))
    try:
        blocks = []
        for container in resolution.containers:
            output = await executor.execute_safe_command(
                DOCKER_HEALTH.render(service=container)
            )
            body = _format_container_health(container, output, entries)
            blocks.append(_container_block(resolution, container, body))
        return _cap_composite("\n\n".join(blocks))
    except Exception as e:
        return f"❌ Error getting container health: {e}"


@mcp.tool(annotations=DESTRUCTIVE_ACTION)
async def restart_service(service: str) -> str:
    """Restart a service directory or container (all resolved containers).

    Args:
        service: Service directory or container name

    Returns:
        Restart result per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return str(e)

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        return await _run_on_containers(resolution, DOCKER_RESTART, "restarted")
    except Exception as e:
        return f"❌ Error restarting service: {e}"


@mcp.tool(annotations=WRITE_ACTION)
async def start_service(service: str) -> str:
    """Start a stopped service directory or container.

    Args:
        service: Service directory or container name

    Returns:
        Start result per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return str(e)

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        return await _run_on_containers(resolution, DOCKER_START, "started")
    except Exception as e:
        return f"❌ Error starting service: {e}"


@mcp.tool(annotations=DESTRUCTIVE_ACTION)
async def stop_service(service: str) -> str:
    """Stop a running service directory or container.

    Args:
        service: Service directory or container name

    Returns:
        Stop result per resolved container
    """
    try:
        resolution = await _resolve_service(service)
    except ResolutionError as e:
        return str(e)

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        return await _run_on_containers(resolution, DOCKER_STOP, "stopped")
    except Exception as e:
        return f"❌ Error stopping service: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_service_file(service: str, file_path: str) -> str:
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

    if check.access is FileAccess.REDACT:
        return _cap_composite(
            f"{redact_env_content(content)}\n\n"
            "(Environment values are masked by the sensitive-file policy.)"
        )
    return _cap_composite(content)


@mcp.tool(annotations=READ_ONLY)
async def list_service_files(service: str, subdirectory: str = "") -> str:
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
        return f"❌ Error listing files: {e}"

    if not entries:
        return f"No files found in {full_path}"
    return _cap_composite("\n".join(entry.longname for entry in entries))


@mcp.tool(annotations=READ_ONLY)
async def search_service_logs(
    service: str,
    pattern: str,
    lines: int = 1000,
    since: str | None = None,
    until: str | None = None,
    container: str | None = None,
) -> str:
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
        return str(e)

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
            return f"No matches found for '{exact_pattern}' in last {lines} lines"

        return _cap_composite("\n".join(matches))
    except Exception as e:
        return f"❌ Error searching logs: {e}"


@mcp.tool(annotations=READ_ONLY)
async def query_influxdb(query: str, database: str | None = None) -> str:
    """Query InfluxDB v3 using SQL (read-only).

    Executes a SELECT query against the InfluxDB v3 HTTP API.
    Requires influxdb to be enabled in config.yaml.

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
        return (
            "❌ Invalid query. Queries must:\n"
            "- Start with SELECT (read-only only)\n"
            "- Not contain SQL injection characters (;, --, /*, etc.)\n"
            "- Not contain shell injection characters"
        )

    db = database or influxdb_config.get("database")
    if not db:
        return (
            "❌ No database specified. Provide 'database' parameter or set "
            "'influxdb.database' in config.yaml."
        )

    client = _make_influxdb_client()
    return await client.query(validated_query, database=db)


@mcp.tool(annotations=READ_ONLY)
async def query_prometheus(query: str, time: str | None = None) -> str:
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
        return (
            "❌ Invalid query. Queries must:\n"
            "- Not contain shell injection characters (;, `, $, |, etc.)\n"
            "- Not contain quotes or newlines"
        )

    client = _make_prometheus_client()
    return await client.query(validated_query, time)


@mcp.tool(annotations=READ_ONLY)
async def get_prometheus_targets() -> str:
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

    client = _make_prometheus_client()
    return await client.get_targets()


@mcp.tool(annotations=READ_ONLY)
async def get_server_health() -> str:
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
                ("=== Running Services ===", DOCKER_PS.render()),
                ("=== Unhealthy Containers ===", DOCKER_PS_UNHEALTHY.render()),
            ]
        )

        results = []
        for title, cmd in commands:
            output = await executor.execute_safe_command(cmd)
            results.append(f"{title}\n{output.strip() or '(none)'}")

        return _cap_composite("\n\n".join(results))
    except Exception as e:
        return f"❌ Error getting server health: {e}"


async def main(config_path: Path | None = None) -> None:
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
        "get_host_service_logs, restart_service, start_service, stop_service, "
        "get_service_file, list_service_files, search_service_logs, "
        "get_server_health, query_influxdb, query_prometheus, "
        "get_prometheus_targets"
    )
    try:
        await mcp.run_stdio_async()
    finally:
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
    args = parser.parse_args()
    asyncio.run(main(args.config))


if __name__ == "__main__":
    cli()
