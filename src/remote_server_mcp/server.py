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
import shlex
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from server_management_lib import (
    ConfigNotFoundError,
    InfluxDBClient,
    PrometheusClient,
    SecurityValidator,
    SSHManager,
    load_config,
    resolve_config_path,
)

APP_NAME = "remote-server-mcp"
CONFIG_ENV_VAR = "REMOTE_SERVER_MCP_CONFIG"

logger = logging.getLogger(__name__)

# Best-effort load so the module stays importable (tests, tooling). The server
# itself refuses to start without a real configuration file (see main()).
config = load_config(env_var=CONFIG_ENV_VAR, app_name=APP_NAME, log_missing=False)
security = SecurityValidator(config)
ssh_manager = SSHManager(config, security)

mcp = MCPServer("remote-server-mcp")


def configure_logging() -> None:
    """Configure logging from MCP_LOG_LEVEL (called at startup, not on import)."""
    level_name = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level)


def apply_config(config_path: Path | None = None) -> Path:
    """(Re)load configuration and rebuild the dependent objects in place."""
    global security, ssh_manager

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
    ssh_manager = SSHManager(config, security)
    return resolved


@mcp.tool()
async def list_services() -> str:
    """List all services in /srv/ directory.

    Returns:
        List of service directories and their status
    """
    try:
        base_path = security.services_base_path.rstrip("/") + "/"
        cmd = (
            f"ls -1 {shlex.quote(base_path)} 2>&1 && "
            "echo '---DOCKER STATUS---' && "
            "docker ps --format '{{.Names}}\t{{.Status}}' 2>&1"
        )
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error listing services: {e}"


@mcp.tool()
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
    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    # Limit lines to prevent abuse
    lines = max(1, min(lines, 1000))

    try:
        # Use '--' to prevent Docker option injection even if service
        # validation is somehow bypassed (defense in depth)
        cmd = f"docker logs --tail {lines} -- {shlex.quote(service)} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error getting logs: {e}"


@mcp.tool()
async def get_service_status(service: str) -> str:
    """Get detailed status of a specific service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Service status including Docker state and resource usage
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = (
            f"docker inspect "
            f"--format='Name: {{{{.Name}}}}\nState: {{{{.State.Status}}}}\n"
            f"Running: {{{{.State.Running}}}}\n"
            f"RestartCount: {{{{.RestartCount}}}}\n"
            f"StartedAt: {{{{.State.StartedAt}}}}' -- {service} 2>&1"
        )
        results = []
        output = await ssh_manager.execute_safe_command(cmd)
        results.append(f"=== Docker Status ===\n{output}")

        cmd = (
            f"docker stats --no-stream "
            f"--format='CPU: {{{{.CPUPerc}}}}\nMemory: {{{{.MemUsage}}}}\n"
            f"Net I/O: {{{{.NetIO}}}}' -- {service} 2>&1"
        )
        output = await ssh_manager.execute_safe_command(cmd)
        results.append(f"=== Resource Usage ===\n{output}")

        cmd = f"docker port -- {service} 2>&1 || echo 'No ports exposed'"
        output = await ssh_manager.execute_safe_command(cmd)
        results.append(f"=== Ports ===\n{output}")

        return "\n\n".join(results)
    except Exception as e:
        return f"❌ Error getting service status: {e}"


@mcp.tool()
async def restart_service(service: str) -> str:
    """Restart a service (Docker container).

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Restart result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = f"docker restart -- {shlex.quote(service)} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return f"✅ Service '{service}' restarted\n{result}"
    except Exception as e:
        return f"❌ Error restarting service: {e}"


@mcp.tool()
async def start_service(service: str) -> str:
    """Start a stopped service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Start result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = f"docker start -- {shlex.quote(service)} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return f"✅ Service '{service}' started\n{result}"
    except Exception as e:
        return f"❌ Error starting service: {e}"


@mcp.tool()
async def stop_service(service: str) -> str:
    """Stop a running service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Stop result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = f"docker stop -- {shlex.quote(service)} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return f"✅ Service '{service}' stopped\n{result}"
    except Exception as e:
        return f"❌ Error stopping service: {e}"


@mcp.tool()
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

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        cmd = f"cat {shlex.quote(full_path)} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error reading file: {e}"


@mcp.tool()
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

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return (
            f"❌ Service '{service}' does not exist in {security.services_base_path}/"
        )

    try:
        cmd = f"ls -lah {shlex.quote(full_path)} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error listing files: {e}"


@mcp.tool()
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
        # Use grep with fixed strings (no regex) for safety
        cmd = (
            f"docker logs --tail {lines} -- {shlex.quote(service)} 2>&1 | "
            f"grep -F '{sanitized_pattern}'"
        )
        result = await ssh_manager.execute_safe_command(cmd)

        if not result.strip():
            return f"No matches found for '{pattern}' in last {lines} lines"

        return result
    except Exception as e:
        return f"❌ Error searching logs: {e}"


@mcp.tool()
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
    )
    return await client.query(validated_query)


@mcp.tool()
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
    )
    return await client.query(validated_query, time)


@mcp.tool()
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
    )
    return await client.get_targets()


@mcp.tool()
async def get_server_health() -> str:
    """Get overall server health (CPU, memory, disk) - no sensitive data.

    Returns:
        Server health metrics only
    """
    try:
        commands = [
            "echo '=== System Uptime ===' && uptime",
            "echo '=== Memory Usage ===' && free -h",
            "echo '=== Disk Usage ===' && "
            f"df -h {shlex.quote(security.services_base_path)}",
            (
                "echo '=== Running Services ===' && docker ps "
                "--format '{{.Names}} ({{.Status}})'"
            ),
        ]

        results = []
        for cmd in commands:
            output = await ssh_manager.execute_safe_command(cmd)
            results.append(output)

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
        result = await ssh_manager.execute_safe_command("echo 'Connection successful'")
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
