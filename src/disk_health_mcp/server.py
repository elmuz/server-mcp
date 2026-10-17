"""
MCP Server for Disk Health Diagnostics

Provides AI assistants with controlled access to disk health data:
- SMART data analysis with manufacturer-aware normalization
- NVMe health monitoring
- ZFS and RAID status
- I/O statistics
- Historical metrics from Prometheus/InfluxDB
- SMART self-test management

Security is enforced by server-management-lib (whitelisted commands only,
device name validation, read-only InfluxDB/Prometheus queries).

Design Principle: Whitelist operations, don't blacklist commands.
"""

import argparse
import asyncio
import json
import logging
import os
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

from .smart_parser import (
    SmartDevice,
    format_smart_summary,
    parse_smart_json,
    parse_smart_text,
)

APP_NAME = "disk-health-mcp"
CONFIG_ENV_VAR = "DISK_HEALTH_MCP_CONFIG"

logger = logging.getLogger(__name__)

# Best-effort load so the module stays importable (tests, tooling). The server
# itself refuses to start without a real configuration file (see main()).
config = load_config(env_var=CONFIG_ENV_VAR, app_name=APP_NAME, log_missing=False)
security = SecurityValidator(config)
ssh_manager = SSHManager(config, security)

mcp = MCPServer("disk-health-mcp")


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


# ============================================================================
# SSH-based tools
# ============================================================================


async def _run_ssh(cmd: str) -> str:
    """Execute a command over SSH, managing connection lifecycle."""
    try:
        await ssh_manager.connect()
        return await ssh_manager.execute_safe_command(cmd)
    except Exception as e:
        return f"❌ SSH error: {e}"
    finally:
        await ssh_manager.disconnect()


def _enrich_error_output(raw_output: str, device: str = "") -> str:
    """Add helpful hints when smartctl/nvme-cli fail due to privilege issues.

    These tools require root/sudo on most systems. If the MCP server runs
    without elevated privileges, the agent should suggest this as a likely cause.
    """
    lower = raw_output.lower()
    hints: list[str] = []

    # Detect privilege errors
    privilege_patterns = [
        "permission denied",
        "cannot open",
        "access denied",
        "operation not permitted",
        "eacces",
        "epem",
    ]
    # Detect command-not-found or empty output (often means path requires sudo)
    not_found_patterns = [
        "command not found",
        "not found",
        "no such file",
        "unable to detect",
        "smartctl not found",
        "nvme not found",
    ]
    # Detect device open failures
    device_fail_patterns = [
        "unable to open",
        "cannot open",
        "open failed",
        "device or resource busy",
    ]

    has_privilege_error = any(p in lower for p in privilege_patterns)
    has_not_found_error = any(p in lower for p in not_found_patterns)
    has_device_fail = any(p in lower for p in device_fail_patterns)

    if has_privilege_error or has_device_fail:
        hints.append(
            "💡 Hint: smartctl/nvme-cli require root privileges (sudo). "
            "Ensure the MCP server runs with elevated permissions or configure "
            "sudoers to allow passwordless smartctl access."
        )
    if has_not_found_error:
        hints.append(
            "💡 Hint: smartctl/nvme-cli may be installed but only accessible "
            "to root. Check that the tools are installed and the MCP server "
            "has sudo access."
        )

    if hints:
        return raw_output.rstrip() + "\n\n" + "\n".join(hints)
    return raw_output


async def _is_influxdb_available() -> bool:
    """Check if InfluxDB is enabled and reachable."""
    influx_config = config.get("influxdb", {})
    if not influx_config.get("enabled", False):
        return False
    return True


async def _get_influxdb_latest_device(device: str) -> dict | None:
    """Get the latest smart_device row for a specific device from InfluxDB.

    Returns a dict of the latest reading, or None if unavailable.
    """
    if not await _is_influxdb_available():
        return None

    client = _make_influxdb_client()
    query = (
        f"SELECT * FROM smart_device WHERE device = '{device}' "
        f"AND time > now() - INTERVAL '10 minutes' ORDER BY time DESC LIMIT 1"
    )
    try:
        result = await client.query(query)
        if result.startswith("✅ Query successful"):
            data = json.loads(result.split("\n\n", 1)[1])
            if isinstance(data, list) and len(data) > 0:
                return data[0]
    except (json.JSONDecodeError, IndexError, KeyError):
        pass
    return None


async def _get_influxdb_latest_attributes(device: str) -> list[dict] | None:
    """Get the latest smart_attribute rows for a device from InfluxDB.

    Returns a list of attribute dicts, or None if unavailable.
    """
    if not await _is_influxdb_available():
        return None

    client = _make_influxdb_client()
    query = (
        f"SELECT name, raw_value, device FROM smart_attribute "
        f"WHERE device = '{device}' AND time > now() - INTERVAL '10 minutes' "
        f"ORDER BY time DESC LIMIT 100"
    )
    try:
        result = await client.query(query)
        if result.startswith("✅ Query successful"):
            data = json.loads(result.split("\n\n", 1)[1])
            if isinstance(data, list) and len(data) > 0:
                # Deduplicate by name (take the latest for each attribute)
                seen: dict[str, dict] = {}
                for row in data:
                    name = row.get("name", "")
                    if name not in seen:
                        seen[name] = row
                return list(seen.values())
    except (json.JSONDecodeError, IndexError, KeyError):
        pass
    return None


def _format_influxdb_device_health(row: dict) -> str:
    """Format an InfluxDB smart_device row into a human-readable health report."""
    device = row.get("device", "unknown")
    model = row.get("model", "unknown")
    serial = row.get("serial_no", "unknown")
    health_ok = row.get("health_ok", None)
    temp = row.get("temp_c", 0)
    power_on_hours = row.get("power_on_hours", 0)
    power_cycles = row.get("power_cycle_count", 0)

    # Health assessment
    if health_ok is True:
        health_emoji = "✅"
        health_text = "PASSED"
    elif health_ok is False:
        health_emoji = "🔴"
        health_text = "FAILED"
    else:
        health_emoji = "⚠️"
        health_text = "Unknown"

    lines = [
        f"{health_emoji} Device Health Report: /dev/{device}",
        f"{'=' * 50}",
        "  Source: InfluxDB (Telegraf smart plugin)",
        f"  Model: {model}",
        f"  Serial: {serial}",
        f"  Health: {health_text}",
        f"  Temperature: {temp}°C{' 🔥' if temp > 55 else ''}",
        f"  Power-On Hours: {power_on_hours:,} ({power_on_hours / 8760:.1f} years)",
        f"  Power Cycles: {power_cycles}",
    ]

    # NVMe-specific fields
    if "percentage_used" in row:
        pct = row["percentage_used"]
        lines.append(f"  NVMe Life Used: {pct}%")
        if pct > 90:
            lines.append("    ⚠️  Drive is near end of life")
    if "critical_warning" in row and row["critical_warning"] != 0:
        lines.append(f"  ⚠️  NVMe Critical Warning: {row['critical_warning']}")
    if "media_errors" in row and row["media_errors"] != 0:
        lines.append(f"  ⚠️  Media Errors: {row['media_errors']}")
    if "error_log_entries" in row and row["error_log_entries"] != 0:
        lines.append(f"  Error Log Entries: {row['error_log_entries']}")
    if "available_spare" in row:
        lines.append(f"  Available Spare: {row['available_spare']}%")
    if "unsafe_shutdowns" in row:
        lines.append(f"  Unsafe Shutdowns: {row['unsafe_shutdowns']}")

    lines.append(f"{'=' * 50}")
    return "\n".join(lines)


@mcp.tool()
async def list_disks() -> str:
    """List all storage devices on the host.

    Returns device names, models, serials, sizes, and types.
    Requires host data source to be enabled in config.yaml.

    Returns:
        List of storage devices in JSON format
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    cmd = "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    return await _run_ssh(cmd)


@mcp.tool()
async def get_disk_health(device: str) -> str:
    """Get a comprehensive health analysis for a specific disk.

    Data source priority:
    1. InfluxDB (Telegraf smart plugin) - no root required
    2. Direct smartctl via SSH - requires sudo

    Args:
        device: Block device name (e.g., 'sda', 'nvme0n1')

    Returns:
        Human-readable health assessment with severity flags
    """
    if not security.validate_device_name(device):
        return f"❌ Invalid device name: {device}\nUse format: sda, nvme0n1, vda, etc."

    # Priority 1: Try InfluxDB (no root needed)
    influx_data = await _get_influxdb_latest_device(device)
    if influx_data:
        return _format_influxdb_device_health(influx_data)

    # Priority 2: Fall back to smartctl via SSH
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = f"smartctl -j -a /dev/{device} 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"

    raw_output = await _run_ssh(cmd)
    if "❌" in raw_output:
        return _enrich_error_output(raw_output, device)

    try:
        data = json.loads(raw_output)
        smart_device: SmartDevice = parse_smart_json(data)
        return format_smart_summary(smart_device)
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning(f"JSON parse failed, falling back to text: {e}")
        text_cmd = f"smartctl -a /dev/{device} 2>&1"
        raw_text = await _run_ssh(text_cmd)
        if "❌" not in raw_text:
            smart_device = parse_smart_text(raw_text)
            return format_smart_summary(smart_device)
        return _enrich_error_output(raw_text, device)


@mcp.tool()
async def get_smart_attributes(device: str) -> str:
    """Get raw SMART attributes for a specific disk.

    Data source priority:
    1. InfluxDB (Telegraf smart_attribute table) - no root required
    2. Direct smartctl via SSH - requires sudo

    Args:
        device: Block device name (e.g., 'sda', 'nvme0n1')

    Returns:
        SMART attribute table with severity annotations
    """
    if not security.validate_device_name(device):
        return f"❌ Invalid device name: {device}"

    # Priority 1: Try InfluxDB (no root needed)
    influx_attrs = await _get_influxdb_latest_attributes(device)
    if influx_attrs:
        # Fetch device summary for SSD wear cross-reference
        influx_device = await _get_influxdb_latest_device(device)

        lines = [
            f"SMART Attributes for {device} (via InfluxDB)",
            "",
        ]

        # SSD wear summary if available
        if influx_device:
            pct_used = influx_device.get("percentage_used")
            pct_life = influx_device.get("percent_lifetime_remain")
            media_errs = influx_device.get("media_errors", 0)
            avail_spare = influx_device.get("available_spare")
            if pct_used is not None or pct_life is not None:
                status = "✅"
                if pct_used is not None and pct_used >= 90:
                    status = "🔴"
                elif pct_used is not None and pct_used >= 70:
                    status = "🟡"
                lines.append(f"{status} SSD Wear Summary:")
                if pct_used is not None:
                    lines.append(f"    Percentage Used: {pct_used}%")
                if pct_life is not None:
                    lines.append(f"    Life Remaining: {pct_life}%")
                if media_errs and media_errs > 0:
                    lines.append(f"    ⚠️  Media Errors: {media_errs}")
                if avail_spare is not None:
                    lines.append(f"    Available Spare: {avail_spare}%")
                if pct_used is not None and pct_used >= 90:
                    lines.append("    ⚠️  Drive is near end of life")
                lines.append("")

        lines.append(f"{'Name':<30} {'Raw Value':>15} {'Note':<35} {'Severity':<10}")
        lines.append("-" * 95)
        for attr in influx_attrs:
            name = attr.get("name", "unknown")
            raw_val = attr.get("raw_value", 0)

            # Severity assessment for key attributes
            severity = "ok"
            icon = "✅"
            if "Reallocat" in name and raw_val > 0:
                severity = "critical"
                icon = "🔴"
            elif "Pending_Sector" in name and raw_val > 0:
                severity = "critical"
                icon = "🔴"
            elif "Uncorrectable" in name and raw_val > 0:
                severity = "warning"
                icon = "🟡"
            elif "Spin_Retry" in name and raw_val > 0:
                severity = "warning"
                icon = "🟡"

            # Add scale context for SSD wear attributes
            note = ""
            if name in ("Percent_Lifetime_Remain", "Media_Wearout_Indicator"):
                note = "(100=new, 0=EOL, norm)"
            elif name == "Percentage_Used":
                note = "(0=new, 100=EOL)"
            elif name == "Wear_Leveling_Count":
                note = "(SSD wear)"
            elif name == "Available_Reservd_Space":
                note = "(spare blocks)"

            lines.append(f"{name:<30} {raw_val:>15} {note:<35} {icon} {severity:<8}")
        return "\n".join(lines)

    # Priority 2: Fall back to smartctl via SSH
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = f"smartctl -j -a /dev/{device} 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"

    result = await _run_ssh(cmd)
    if "❌" in result:
        return _enrich_error_output(result, device)

    try:
        data = json.loads(result)
        smart_device = parse_smart_json(data)
        lines = [
            f"SMART Attributes for {device} ({smart_device.model})",
            "",
            f"{'ID':<4} {'Name':<28} {'Value':>6} {'Worst':>6} "
            f"{'Thresh':>7} {'Raw':>15} {'Type':<10} {'Severity':<10}",
            "-" * 95,
        ]
        for attr in smart_device.attributes:
            severity_icon = (
                "🔴"
                if attr.severity == "critical"
                else "🟡"
                if attr.severity == "warning"
                else "✅"
            )
            lines.append(
                f"{attr.attr_id:<4} {attr.name:<28} "
                f"{attr.value:>6} {attr.worst:>6} "
                f"{attr.thresh:>7} {attr.raw_value:>15} "
                f"{attr.attr_type:<10} {severity_icon} {attr.severity:<8}"
            )
        return "\n".join(lines)
    except (json.JSONDecodeError, KeyError, TypeError):
        return _enrich_error_output(result, device)


@mcp.tool()
async def get_nvme_health(device: str) -> str:
    """Get NVMe SMART health log for an NVMe device.

    Data source priority:
    1. InfluxDB (Telegraf smart_device table) - no root required
    2. Direct nvme-cli via SSH - requires sudo

    Args:
        device: NVMe device name (e.g., 'nvme0n1')

    Returns:
        NVMe SMART health data
    """
    if not security.validate_device_name(device):
        return f"❌ Invalid device name: {device}"

    # Normalize device name (nvme0n1 -> nvme0 for InfluxDB matching)
    influx_device = device
    if device.endswith("n1"):
        influx_device = device[:-2]

    # Priority 1: Try InfluxDB first
    influx_data = await _get_influxdb_latest_device(influx_device)
    if influx_data:
        return _format_influxdb_device_health(influx_data)

    # Priority 2: Fall back to nvme-cli
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = f"nvme smart-log /dev/{device} 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    result = await _run_ssh(cmd)
    return _enrich_error_output(result, device)


@mcp.tool()
async def run_smart_test(device: str, test_type: str = "short") -> str:
    """Run a SMART self-test on a disk.

    Self-tests are safe - they don't modify data on the drive.
    Results appear in the SMART self-test log after completion.

    Test types:
    - short: Quick test (~2 minutes). Checks electrical/mechanical + short scan.
    - long: Comprehensive test (hours). Full media scan.
    - conveyance: For drives transported after purchase (~5 minutes).

    Args:
        device: Block device name (e.g., 'sda', 'nvme0n1')
        test_type: Test type - short, long, or conveyance (default: short)

    Returns:
        Test initiation status
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    if not security.validate_device_name(device):
        return f"❌ Invalid device name: {device}"

    if not security.validate_smart_test_type(test_type):
        return f"❌ Invalid test type: {test_type}. Use: short, long, conveyance"

    cmd = f"smartctl -t {test_type} /dev/{device} 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    return await _run_ssh(cmd)


@mcp.tool()
async def get_zfs_status() -> str:
    """Get ZFS pool status, health, and capacity.

    Returns pool names, sizes, allocation, dedup ratio, and health status.
    Also reports scrub status if available.

    Returns:
        ZFS pool status and health information
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    cmd = (
        "zpool status -x 2>&1 && echo '---' && "
        "zpool list -o name,size,alloc,free,cap,dedup,health 2>&1"
    )
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    return await _run_ssh(cmd)


@mcp.tool()
async def get_raid_status() -> str:
    """Get mdadm software RAID status.

    Reports RAID level, array health, device state, and sync progress.
    Also reads /proc/mdstat for active arrays.

    Returns:
        RAID array status and health information
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    cmd = "cat /proc/mdstat 2>&1 && echo '---' && mdadm --detail --scan --verbose 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    return await _run_ssh(cmd)


@mcp.tool()
async def get_io_stats() -> str:
    """Get disk I/O statistics.

    Reports per-device I/O utilization, latency, throughput,
    and queue depth from iostat.

    Returns:
        Extended I/O statistics for all devices
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    cmd = "iostat -x 1 1 2>&1"
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    return await _run_ssh(cmd)


# ============================================================================
# HTTP-based tools (InfluxDB, Prometheus)
# ============================================================================


def _make_influxdb_client() -> InfluxDBClient:
    """Create InfluxDB client from config."""
    cfg = config.get("influxdb", {})
    return InfluxDBClient(
        host=cfg.get("host", "localhost"),
        port=cfg.get("port", 8181),
        use_https=cfg.get("use_https", False),
        database=cfg.get("database"),
        token=cfg.get("token"),
        query_limit=cfg.get("query_limit", 1000),
    )


def _make_prometheus_client() -> PrometheusClient:
    """Create Prometheus client from config."""
    cfg = config.get("prometheus", {})
    return PrometheusClient(
        host=cfg.get("host", "localhost"),
        port=cfg.get("port", 9090),
        use_https=cfg.get("use_https", False),
        token=cfg.get("token"),
    )


@mcp.tool()
async def query_prometheus_disk(query: str) -> str:
    """Query Prometheus for disk-related metrics.

    Useful for checking node_exporter smartmon and disk I/O metrics.

    Common queries:
    - smartmon_health_ok
    - smartmon_temperature_celsius
    - node_disk_io_time_seconds_total

    Args:
        query: PromQL expression for disk metrics

    Returns:
        Query results in JSON format
    """
    prom_config = config.get("prometheus", {})
    if not prom_config.get("enabled", False):
        return (
            "❌ Prometheus is not enabled.\n"
            "Set 'prometheus.enabled: true' in config.yaml."
        )

    validated = security.validate_prometheus_query(query)
    if validated is None:
        return "❌ Invalid PromQL query: contains forbidden characters"

    client = _make_prometheus_client()
    return await client.query(query)


@mcp.tool()
async def query_influxdb_disk(query: str, database: str | None = None) -> str:
    """Query InfluxDB for historical disk metrics.

    Useful for trend analysis: has SMART data been degrading over time?
    Telegraf's smart plugin collects SMART attributes as InfluxDB measurements.

    Args:
        query: SQL query (must start with SELECT)
        database: Database name (overrides config default)

    Returns:
        Query results in JSON format
    """
    influx_config = config.get("influxdb", {})
    if not influx_config.get("enabled", False):
        return (
            "❌ InfluxDB is not enabled.\nSet 'influxdb.enabled: true' in config.yaml."
        )

    validated = security.validate_influxdb_query(query)
    if validated is None:
        return (
            "❌ Invalid query. Queries must:\n"
            "- Start with SELECT (read-only only)\n"
            "- Not contain SQL injection characters (;, --, /*, etc.)\n"
            "- Not contain shell injection characters"
        )

    client = _make_influxdb_client()
    return await client.query(query, database)


# ============================================================================
# Composite tools
# ============================================================================


@mcp.tool()
async def get_full_disk_report(device: str | None = None) -> str:
    """Get a comprehensive disk health report combining multiple data sources.

    Data source priority:
    1. InfluxDB (Telegraf smart_device table) - no root required
    2. Direct smartctl via SSH - requires sudo

    If device is specified: detailed analysis of that device.
    If no device: overview of all disks with severity summary.

    This is the recommended tool for overall disk health assessment.

    Args:
        device: Optional specific device name (e.g., 'sda')

    Returns:
        Comprehensive disk health report
    """
    if device:
        if not security.validate_device_name(device):
            return f"❌ Invalid device name: {device}"
        return await get_disk_health(device)

    # Overview of all disks - try InfluxDB first
    lines = ["=== Disk Health Overview ===\n"]

    if await _is_influxdb_available():
        # Get all devices from InfluxDB
        client = _make_influxdb_client()
        query = (
            "SELECT DISTINCT device, model, health_ok, temp_c, "
            "power_on_hours, serial_no FROM smart_device "
            "WHERE time > now() - INTERVAL '10 minutes'"
        )
        try:
            result = await client.query(query)
            if result.startswith("✅ Query successful"):
                data = json.loads(result.split("\n\n", 1)[1])
                if isinstance(data, list) and len(data) > 0:
                    lines.append("Source: InfluxDB (Telegraf smart plugin)\n")
                    lines.append(f"Found {len(data)} devices:\n")
                    for row in data:
                        dev_name = row.get("device", "unknown")
                        model = row.get("model", "unknown")
                        health_ok = row.get("health_ok", None)
                        temp = row.get("temp_c", 0)
                        poh = row.get("power_on_hours", 0)

                        if health_ok is True:
                            emoji = "✅"
                        elif health_ok is False:
                            emoji = "🔴"
                        else:
                            emoji = "⚠️"

                        temp_flag = " 🔥" if temp > 55 else ""
                        lines.append(
                            f"  {emoji} /dev/{dev_name} - {model} | "
                            f"Temp: {temp}°C{temp_flag} | "
                            f"POH: {poh:,} | "
                            f"Health: {'PASSED' if health_ok else 'UNKNOWN'}"
                        )
                    lines.append(f"\n{'=' * 50}\n")
                else:
                    lines.append(
                        "⚠️  No recent data in InfluxDB, falling back to SSH...\n"
                    )
                    return await _get_full_report_via_ssh()
        except (json.JSONDecodeError, IndexError, KeyError):
            lines.append("⚠️  InfluxDB parse error, falling back to SSH...\n")
            return await _get_full_report_via_ssh()
    else:
        lines.append("⚠️  InfluxDB not enabled, using SSH fallback\n")
        return await _get_full_report_via_ssh()

    return "\n".join(lines)


async def _get_full_report_via_ssh() -> str:
    """Generate full disk health report via SSH (requires sudo)."""
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    lines = ["=== Disk Health Overview ===\n"]

    disk_list = await list_disks()
    if "❌" not in disk_list:
        try:
            data = json.loads(disk_list)
            blockdevs = data.get("blockdevices", [])
            lines.append(f"Found {len(blockdevs)} block devices:\n")
            for dev in blockdevs:
                name = dev.get("name", "")
                model = dev.get("model", "")
                size = dev.get("size", "")
                lines.append(f"  • /dev/{name} - {model} ({size})")
        except (json.JSONDecodeError, KeyError):
            lines.append(f"Disk list: {disk_list[:500]}")

    lines.append("\n=== Individual Health Checks ===\n")

    try:
        data = json.loads(disk_list)
        blockdevs = data.get("blockdevices", [])
        for dev in blockdevs:
            name = dev.get("name", "")
            lines.append(f"\n--- /dev/{name} ---")
            cmd = f"smartctl -j -a /dev/{name} 2>&1"
            if not security.is_command_safe(cmd):
                lines.append("  ❌ Command blocked by security")
                continue

            health = await _run_ssh(cmd)
            if "❌" in health:
                enriched = _enrich_error_output(health, name)
                lines.append(f"  {enriched.replace(chr(10), chr(10) + '  ')}")
                continue

            try:
                smart_data = json.loads(health)
                smart_device = parse_smart_json(smart_data)
                health_emoji = (
                    "🔴"
                    if smart_device.health_score < 50
                    else "🟡"
                    if smart_device.health_score < 80
                    else "✅"
                )
                lines.append(
                    f"  {health_emoji} Health: {smart_device.health_score}/100"
                )
                lines.append(f"  Model: {smart_device.model}")
                lines.append(f"  SMART: {smart_device.overall_health}")
                if smart_device.temperature > 0:
                    temp_warn = " 🔥" if smart_device.temperature > 55 else ""
                    lines.append(f"  Temp: {smart_device.temperature}°C{temp_warn}")
                if smart_device.warnings:
                    for w in smart_device.warnings[:3]:
                        lines.append(f"  ⚠️  {w}")
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                lines.append(f"  ⚠️  Parse error: {e}")
    except (json.JSONDecodeError, KeyError):
        lines.append("Could not parse disk list for health checks")

    return "\n".join(lines)


async def main(config_path: Path | None = None) -> None:
    """Run the MCP server."""
    configure_logging()

    try:
        resolved = apply_config(config_path)
    except ConfigNotFoundError as e:
        logger.error("%s", e)
        raise SystemExit(2) from e

    logger.info("Using configuration: %s", resolved)
    logger.info("Starting Disk Health MCP...")
    logger.info(
        "Available tools: list_disks, get_disk_health, get_smart_attributes, "
        "get_nvme_health, run_smart_test, get_zfs_status, get_raid_status, "
        "get_io_stats, query_prometheus_disk, query_influxdb_disk, "
        "get_full_disk_report"
    )
    await mcp.run_stdio_async()


def cli() -> None:
    """Console entry point."""
    parser = argparse.ArgumentParser(description="Disk Health MCP server")
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
