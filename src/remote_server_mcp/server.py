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
import logging
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from server_management_lib import (
    DEFAULT_MAX_OUTPUT_BYTES,
    ConfigNotFoundError,
    InfluxDBClient,
    PrometheusClient,
    SecurityValidator,
    create_executor,
    load_config,
    parse_duration,
    resolve_config_path,
)

from .operations import (
    DISK_USAGE,
    DOCKER_INSPECT,
    DOCKER_LOGS,
    DOCKER_PORTS,
    DOCKER_PS,
    DOCKER_RESTART,
    DOCKER_START,
    DOCKER_STATS,
    DOCKER_STOP,
    FREE_MEMORY,
    LS_SERVICES,
    UPTIME,
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
        return (
            f"=== Services in {base_path} ===\n{services}\n"
            f"=== Docker Status ===\n{docker}"
        )
    except Exception as e:
        return f"❌ Error listing services: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_service_logs(service: str, lines: int = 100) -> str:
    """Get logs for a specific service.

    Args:
        service: Service name (must exist in /srv/)
        lines: Number of log lines to retrieve (default: 100, max: 1000)

    Returns:
        Service logs
    """
    # Validate service name
    if not security.validate_service_name(service):
        msg = (
            f"❌ Invalid service name: {service}\n"
            "Service must be alphanumeric with hyphens/underscores only."
        )
        return msg

    # Check service exists
    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    # Limit lines to prevent abuse
    lines = max(1, min(lines, 1000))

    try:
        # Use '--' to prevent Docker option injection even if service
        # validation is somehow bypassed (defense in depth)
        cmd = DOCKER_LOGS.render(service=service, lines=lines)
        result = await executor.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error getting logs: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_service_status(service: str) -> str:
    """Get detailed status of a specific service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Service status including Docker state and resource usage
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        results = []
        output = await executor.execute_safe_command(
            DOCKER_INSPECT.render(service=service)
        )
        results.append(f"=== Docker Status ===\n{output}")

        output = await executor.execute_safe_command(
            DOCKER_STATS.render(service=service)
        )
        results.append(f"=== Resource Usage ===\n{output}")

        output = await executor.execute_safe_command(
            DOCKER_PORTS.render(service=service)
        )
        results.append(f"=== Ports ===\n{output}")

        return "\n\n".join(results)
    except Exception as e:
        return f"❌ Error getting service status: {e}"


@mcp.tool(annotations=DESTRUCTIVE_ACTION)
async def restart_service(service: str) -> str:
    """Restart a service (Docker container).

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Restart result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = DOCKER_RESTART.render(service=service)
        result = await executor.execute_safe_command(cmd)
        return f"✅ Service '{service}' restarted\n{result}"
    except Exception as e:
        return f"❌ Error restarting service: {e}"


@mcp.tool(annotations=WRITE_ACTION)
async def start_service(service: str) -> str:
    """Start a stopped service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Start result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = DOCKER_START.render(service=service)
        result = await executor.execute_safe_command(cmd)
        return f"✅ Service '{service}' started\n{result}"
    except Exception as e:
        return f"❌ Error starting service: {e}"


@mcp.tool(annotations=DESTRUCTIVE_ACTION)
async def stop_service(service: str) -> str:
    """Stop a running service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Stop result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = DOCKER_STOP.render(service=service)
        result = await executor.execute_safe_command(cmd)
        return f"✅ Service '{service}' stopped\n{result}"
    except Exception as e:
        return f"❌ Error stopping service: {e}"


@mcp.tool(annotations=READ_ONLY)
async def get_service_file(service: str, file_path: str) -> str:
    """Get the contents of a file within a service directory.

    Args:
        service: Service name (must exist in /srv/)
        file_path: Relative path within /srv/{service}/ (e.g., 'docker-compose.yml')

    Returns:
        File contents
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Construct and validate full path
    full_path = security.validate_service_file_path(service, file_path)
    if full_path is None:
        return (
            f"❌ Invalid file path: {file_path}\n"
            f"File must be within {security.services_base_path}/{service}/"
        )

    exists = await executor.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    service_base = f"{security.services_base_path.rstrip('/')}/{service}"
    try:
        return await executor.read_remote_file(full_path, allowed_base=service_base)
    except Exception as e:
        return f"❌ Error reading file: {e}"


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

    # Validate subdirectory path
    if subdirectory:
        full_path = security.validate_service_file_path(service, subdirectory)
        if full_path is None:
            return (
                f"❌ Invalid subdirectory: {subdirectory}\n"
                f"Must be within {security.services_base_path}/{service}/"
            )
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
    return "\n".join(entry.longname for entry in entries)


@mcp.tool(annotations=READ_ONLY)
async def search_service_logs(service: str, pattern: str, lines: int = 1000) -> str:
    """Search service logs for a specific pattern.

    Args:
        service: Service name (must exist in /srv/)
        pattern: Text pattern to search for (no regex, plain text only)
        lines: Number of log lines to search (default: 1000, max: 5000)

    Returns:
        Matching log lines
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Sanitize pattern - raises ValueError if empty after sanitization
    try:
        sanitized_pattern = security.sanitize_search_pattern(pattern)
    except ValueError as e:
        return f"❌ Invalid search pattern: {e}"

    # Limit lines
    lines = max(1, min(lines, 5000))

    try:
        cmd = DOCKER_LOGS.render(service=service, lines=lines)
        output = await executor.execute_safe_command(cmd)

        # Filter locally: no shell pipe, so the local executor works too.
        matches = [line for line in output.splitlines() if sanitized_pattern in line]
        if not matches:
            return f"No matches found for '{pattern}' in last {lines} lines"

        return "\n".join(matches)
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

    client = InfluxDBClient(
        host=influxdb_config.get("host", "localhost"),
        port=influxdb_config.get("port", 8181),
        use_https=influxdb_config.get("use_https", False),
        database=db,
        token=influxdb_config.get("token"),
        query_limit=influxdb_config.get("query_limit", 1000),
        max_output_bytes=config.get("output", {}).get(
            "max_bytes", DEFAULT_MAX_OUTPUT_BYTES
        ),
    )
    return await client.query(validated_query)


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

    client = PrometheusClient(
        host=prometheus_config.get("host", "localhost"),
        port=prometheus_config.get("port", 9090),
        use_https=prometheus_config.get("use_https", False),
        token=prometheus_config.get("token"),
        max_output_bytes=config.get("output", {}).get(
            "max_bytes", DEFAULT_MAX_OUTPUT_BYTES
        ),
        timeout=parse_duration(prometheus_config.get("query_timeout", "30s")),
    )
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

    client = PrometheusClient(
        host=prometheus_config.get("host", "localhost"),
        port=prometheus_config.get("port", 9090),
        use_https=prometheus_config.get("use_https", False),
        token=prometheus_config.get("token"),
        max_output_bytes=config.get("output", {}).get(
            "max_bytes", DEFAULT_MAX_OUTPUT_BYTES
        ),
        timeout=parse_duration(prometheus_config.get("query_timeout", "30s")),
    )
    return await client.get_targets()


@mcp.tool(annotations=READ_ONLY)
async def get_server_health() -> str:
    """Get overall server health (CPU, memory, disk) - no sensitive data.

    Returns:
        Server health metrics only
    """
    try:
        commands = [
            ("=== System Uptime ===", UPTIME.render()),
            ("=== Memory Usage ===", FREE_MEMORY.render()),
            (
                "=== Disk Usage ===",
                DISK_USAGE.render(path=security.services_base_path),
            ),
            ("=== Running Services ===", DOCKER_PS.render()),
        ]

        results = []
        for title, cmd in commands:
            output = await executor.execute_safe_command(cmd)
            results.append(f"{title}\n{output}")

        return "\n\n".join(results)
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
        result = await executor.execute_safe_command("echo 'Connection successful'")
        logger.info(f"SSH connection test: {result.strip()}")
    except Exception as e:
        logger.warning(f"SSH connection test failed: {e}")
        logger.warning(
            "Server will start anyway, but tools may fail until SSH is configured"
        )

    logger.info("Starting Remote Server MCP (SECURE MODE)...")
    logger.info(
        "Available tools: list_services, get_service_logs, get_service_status, "
        "restart_service, start_service, stop_service, get_service_file, "
        "list_service_files, search_service_logs, get_server_health, "
        "query_influxdb, query_prometheus, get_prometheus_targets"
    )
    await mcp.run_stdio_async()


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
