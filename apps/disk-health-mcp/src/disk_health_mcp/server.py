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
import re
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from server_management_lib import (
    DEFAULT_MAX_OUTPUT_BYTES,
    ConfigNotFoundError,
    InfluxDBClient,
    PrometheusClient,
    SecurityValidator,
    ToolOutput,
    close_metric_tunnels,
    config_schema,
    create_audit_logger,
    create_executor,
    create_rate_limiter,
    load_config,
    make_structured_tool,
    open_metric_tunnels,
    parse_duration,
    resolve_config_path,
    run_streamable_http,
    sanitize_output,
)

from .operations import (
    CAT_MDSTAT,
    DF_REAL_FILESYSTEMS,
    FINDMNT_MERGERFS,
    FINDMNT_MOUNTS,
    IOSTAT,
    LIST_DISKS,
    MDADM_DETAIL,
    NVME_CLI_PATH,
    NVME_SMART_LOG,
    SMART_JSON,
    SMART_TEST,
    SMART_TEXT,
    SMART_VERSION,
    SMARTCTL_PATH,
    SNAPRAID_STATUS,
    ZPOOL_LIST,
    ZPOOL_STATUS,
)
from .smart_parser import (
    SmartDevice,
    format_smart_summary,
    has_usable_smart_data,
    parse_smart_json,
    parse_smart_text,
)

APP_NAME = "disk-health-mcp"
CONFIG_ENV_VAR = "DISK_HEALTH_MCP_CONFIG"

NVME_NAMESPACE_PATTERN = re.compile(r"^(nvme\d+)n\d+$")
EXIT_CODE_PATTERN = re.compile(r"⚠️ Exit code:\s*(-?\d+)")

# A sleeping disk is sampled by Telegraf with exit_status=2 and no health,
# temperature or wear fields. Those rows are not health data, so look back far
# enough to find the last successful sample instead of a 10-minute window that
# a 5-minute poll plus one sleep cycle can miss.
SMART_LOOKBACK = "24 hours"
INFLUX_SUCCESS_PREFIX = "✅ Query successful"


def _parse_influx_rows(result: str) -> list[dict]:
    """Parse an InfluxDB client response into row dictionaries."""
    if not result.startswith(INFLUX_SUCCESS_PREFIX):
        return []
    try:
        data = json.loads(result.split("\n\n", 1)[1])
    except (json.JSONDecodeError, IndexError):
        return []
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict)]


def _parse_influx_time(value: object) -> datetime | None:
    """Parse an InfluxDB timestamp, treating naive values as UTC."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_key_value_output(text: str) -> dict[str, str | int]:
    """Parse ``Key : value`` lines from human-readable tool output."""
    parsed: dict[str, str | int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        name = key.strip()
        raw = value.strip()
        if not name:
            continue
        try:
            parsed[name] = int(raw)
        except ValueError:
            parsed[name] = raw
    return parsed


def _format_sample_age(row: dict) -> str | None:
    """Describe how old an InfluxDB sample is, with its UTC timestamp."""
    timestamp = _parse_influx_time(row.get("time"))
    if timestamp is None:
        return None

    seconds = max(0, int((datetime.now(UTC) - timestamp).total_seconds()))
    if seconds < 60:
        age = f"{seconds} seconds"
    elif seconds < 3600:
        age = f"{seconds // 60} minutes"
    elif seconds < 86400:
        age = f"{seconds // 3600} hours"
    else:
        age = f"{seconds // 86400} days"
    return f"{age} ago ({timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')})"


logger = logging.getLogger(__name__)

# Best-effort load so the module stays importable (tests, tooling). The server
# itself refuses to start without a real configuration file (see main()).
config = load_config(env_var=CONFIG_ENV_VAR, app_name=APP_NAME, log_missing=False)
security = SecurityValidator(config)
executor = create_executor(config, security)
rate_limiter = create_rate_limiter(config)

mcp = MCPServer("disk-health-mcp")

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


def configure_logging() -> None:
    """Configure logging from MCP_LOG_LEVEL (called at startup, not on import)."""
    level_name = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level)


def _max_output_bytes() -> int:
    output_config = config.get("output", {}) or {}
    return int(output_config.get("max_bytes", DEFAULT_MAX_OUTPUT_BYTES))


def _cap_composite(text: str) -> str:
    """Apply the response cap to a tool response built from several sources."""
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


def apply_config(config_path: Path | None = None) -> Path:
    """(Re)load configuration and rebuild the dependent objects in place."""
    global security, executor, rate_limiter

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
    rate_limiter = create_rate_limiter(config)
    return resolved


# ============================================================================
# SSH-based tools
# ============================================================================


async def _run_command(cmd: str) -> str:
    """Execute a command through the configured executor."""
    try:
        return await executor.execute_safe_command(cmd)
    except Exception as e:
        return f"❌ SSH error: {e}"


def _command_failed(output: str) -> bool:
    """Return True when executor output represents a failed command.

    The SSH executor appends ``⚠️ Exit code: N`` for non-zero exits instead of
    raising, and some shells report command-not-found on stderr. Both must be
    treated as failures before attempting to parse smartctl output.
    """
    if "❌" in output:
        return True

    match = EXIT_CODE_PATTERN.search(output)
    if match:
        return int(match.group(1)) != 0

    return "command not found" in output.lower()


def _disk_devices(blockdevices: object) -> list[dict]:
    """Filter lsblk rows to whole disks with a valid device name.

    ``lsblk`` also reports loop devices, optical drives, zram and partitions.
    Passing those names to smartctl is both noisy and unsafe, so only rows with
    ``type == "disk"`` whose name passes :meth:`SecurityValidator.validate_device_name`
    are used for health checks.
    """
    if not isinstance(blockdevices, list):
        return []
    devices: list[dict] = []
    for device in blockdevices:
        if not isinstance(device, dict) or device.get("type") != "disk":
            continue
        name = device.get("name")
        if not isinstance(name, str) or not security.validate_device_name(name):
            continue
        devices.append(device)
    return devices


def _influxdb_device_name(device: str) -> str:
    """Map a kernel NVMe namespace name to the Telegraf tag value.

    Telegraf's smart plugin stores ``nvme0``/``nvme1`` (namespace-less) while
    Linux exposes ``nvme0n1``/``nvme1n1``. Other device names are unchanged.
    """
    match = NVME_NAMESPACE_PATTERN.match(device)
    return match.group(1) if match else device


def _no_smart_data_message(device: str, detail: str = "") -> str:
    """Build an explicit no-data error instead of a fabricated health report."""
    message = (
        f"❌ No SMART data available for /dev/{device}.\n"
        "InfluxDB returned no recent valid sample (or is disabled). Only rows "
        f"with exit_status = 0 from the last {SMART_LOOKBACK} are used, so "
        "standby rows for a sleeping disk are ignored. The smartctl fallback "
        "did not produce data either. No health status is being inferred."
    )
    if detail.strip():
        message += f"\n\n{detail.strip()}"
    return message


def _enrich_error_output(raw_output: str, device: str = "") -> str:
    """Add helpful hints when smartctl/nvme-cli fail due to environment issues.

    The MCP does not run commands through sudo. Direct SMART access therefore
    requires the executor user to be able to open the block device.
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
    # Detect missing tool paths, not arbitrary smartctl messages.
    not_found_patterns = [
        "command not found",
        "no such file or directory",
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
    # Detect devices that do not exist or do not support SMART
    device_detection_patterns = [
        "unable to detect device type",
        "no such device",
    ]

    has_privilege_error = any(p in lower for p in privilege_patterns)
    has_not_found_error = any(p in lower for p in not_found_patterns)
    has_device_fail = any(p in lower for p in device_fail_patterns)
    has_device_detection_error = any(p in lower for p in device_detection_patterns)

    if has_privilege_error or has_device_fail:
        hints.append(
            "💡 Hint: the executor user needs read access to the block device "
            "(usually membership in the 'disk' group). This MCP does not run "
            "sudo; InfluxDB is the preferred source for read-only SMART data."
        )
    if has_not_found_error:
        hints.append(
            "💡 Hint: check that smartmontools/nvme-cli are installed and that "
            f"{SMARTCTL_PATH} and {NVME_CLI_PATH} are executable by the executor "
            "user. InfluxDB remains the preferred source for read-only SMART data."
        )
    if has_device_detection_error:
        hints.append(
            "💡 Hint: the device may not exist or may not support SMART. "
            "Verify the name with list_disks."
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
    """Get the latest *valid* smart_device row for a device from InfluxDB.

    Telegraf keeps writing rows while a disk sleeps, but those rows carry
    ``exit_status=2`` and no health, temperature or wear fields. Only successful
    samples (``exit_status = 0``) are health data, so they are the only rows
    considered. The lookback covers a full sleep cycle plus the poll interval.

    Returns a dict of the latest valid reading, or None if unavailable.
    """
    if not await _is_influxdb_available():
        return None

    influx_device = _influxdb_device_name(device)
    client = _get_influxdb_client()
    query = (
        f"SELECT * FROM smart_device WHERE device = '{influx_device}' "
        f"AND exit_status = 0 AND time > now() - INTERVAL '{SMART_LOOKBACK}' "
        f"ORDER BY time DESC LIMIT 1"
    )
    try:
        result = await client.query(query)
        rows = _parse_influx_rows(result)
        return rows[0] if rows else None
    except (json.JSONDecodeError, IndexError, KeyError):
        pass
    return None


async def _get_influxdb_latest_attributes(device: str) -> list[dict] | None:
    """Get the latest smart_attribute rows for a device from InfluxDB.

    Only rows from successful samples are returned; standby rows carry no
    attributes and must not be rendered as wear data.

    Returns a list of attribute dicts, or None if unavailable.
    """
    if not await _is_influxdb_available():
        return None

    influx_device = _influxdb_device_name(device)
    client = _get_influxdb_client()
    query = (
        f"SELECT name, raw_value, device FROM smart_attribute "
        f"WHERE device = '{influx_device}' AND exit_status = 0 "
        f"AND time > now() - INTERVAL '{SMART_LOOKBACK}' "
        f"ORDER BY time DESC LIMIT 100"
    )
    try:
        result = await client.query(query)
        rows = _parse_influx_rows(result)
        if rows:
            # Deduplicate by name (take the latest for each attribute)
            seen: dict[str, dict] = {}
            for row in rows:
                name = row.get("name", "")
                if name not in seen:
                    seen[name] = row
            return list(seen.values())
    except (json.JSONDecodeError, IndexError, KeyError):
        pass
    return None


def _format_influxdb_device_health(row: dict, device: str | None = None) -> str:
    """Format an InfluxDB smart_device row into a human-readable health report.

    ``device`` lets callers display the kernel name (for example ``nvme0n1``)
    while the InfluxDB row uses the Telegraf tag (``nvme0``).
    """
    device = device or row.get("device", "unknown")
    model = row.get("model", "unknown")
    serial = row.get("serial_no", "unknown")
    health_ok = row.get("health_ok", None)
    temp = row.get("temp_c")
    power_on_hours = row.get("power_on_hours")
    power_cycles = row.get("power_cycle_count")

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
    ]
    age = _format_sample_age(row)
    if age:
        lines.append(f"  Sample: {age}")
    lines.extend(
        [
            f"  Model: {model}",
            f"  Serial: {serial}",
            f"  Health: {health_text}",
        ]
    )
    if temp is not None:
        lines.append(f"  Temperature: {temp}°C{' 🔥' if temp > 55 else ''}")
    if power_on_hours is not None:
        lines.append(
            f"  Power-On Hours: {power_on_hours:,} ({power_on_hours / 8760:.1f} years)"
        )
    if power_cycles is not None:
        lines.append(f"  Power Cycles: {power_cycles}")

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


@structured_tool(READ_ONLY)
async def list_disks() -> str | ToolOutput:
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

    cmd = LIST_DISKS.render()
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    output = _cap_composite(await _run_command(cmd))
    devices: list = []
    if not _command_failed(output):
        try:
            payload = json.loads(output)
            if isinstance(payload, dict):
                devices = payload.get("blockdevices", []) or []
        except (json.JSONDecodeError, TypeError):
            devices = []
    return ToolOutput(
        output,
        ok=not _command_failed(output),
        data={"devices": devices, "count": len(devices)},
    )


@structured_tool(READ_ONLY)
async def get_disk_health(device: str) -> str | ToolOutput:
    """Get a comprehensive health analysis for a specific disk.

    Data source priority:
    1. InfluxDB (Telegraf smart plugin) - no root required
    2. Direct smartctl via SSH - requires device access

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
        return ToolOutput(
            _cap_composite(_format_influxdb_device_health(influx_data, device)),
            data={"device": device, "source": "influxdb", "sample": influx_data},
        )

    # Priority 2: Fall back to smartctl via SSH
    if not config.get("host", {}).get("enabled", False):
        if await _is_influxdb_available():
            return _no_smart_data_message(device)
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = SMART_JSON.render(device=device)
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"

    raw_output = await _run_command(cmd)
    if _command_failed(raw_output):
        return _enrich_error_output(_no_smart_data_message(device, raw_output), device)

    try:
        data = json.loads(raw_output)
        smart_device: SmartDevice = parse_smart_json(data)
        if not has_usable_smart_data(smart_device):
            return _enrich_error_output(
                _no_smart_data_message(device, raw_output), device
            )
        return ToolOutput(
            _cap_composite(format_smart_summary(smart_device)),
            data={
                "device": device,
                "source": "smartctl",
                "model": smart_device.model,
                "health": smart_device.overall_health,
                "health_score": smart_device.health_score,
                "warnings": list(smart_device.warnings),
            },
        )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning(f"JSON parse failed, falling back to text: {e}")
        text_cmd = SMART_TEXT.render(device=device)
        raw_text = await _run_command(text_cmd)
        if _command_failed(raw_text):
            return _enrich_error_output(
                _no_smart_data_message(device, raw_text), device
            )

        text_device = parse_smart_text(raw_text)
        if text_device is None:
            return _enrich_error_output(
                _no_smart_data_message(device, raw_text), device
            )
        return ToolOutput(
            _cap_composite(format_smart_summary(text_device)),
            data={
                "device": device,
                "source": "smartctl-text",
                "model": text_device.model,
                "health": text_device.overall_health,
                "health_score": text_device.health_score,
            },
        )


@structured_tool(READ_ONLY)
async def get_smart_attributes(device: str) -> str | ToolOutput:
    """Get raw SMART attributes for a specific disk.

    Data source priority:
    1. InfluxDB (Telegraf smart_attribute table) - no root required
    2. Direct smartctl via SSH - requires device access

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
        return ToolOutput(
            _cap_composite("\n".join(lines)),
            data={
                "device": device,
                "source": "influxdb",
                "attributes": influx_attrs,
                "device_summary": influx_device or {},
            },
        )

    # Priority 2: Fall back to smartctl via SSH
    if not config.get("host", {}).get("enabled", False):
        if await _is_influxdb_available():
            return _no_smart_data_message(device)
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = SMART_JSON.render(device=device)
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"

    result = await _run_command(cmd)
    if _command_failed(result):
        return _enrich_error_output(_no_smart_data_message(device, result), device)

    try:
        data = json.loads(result)
        smart_device = parse_smart_json(data)
        if not has_usable_smart_data(smart_device):
            return _enrich_error_output(_no_smart_data_message(device, result), device)
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
        return ToolOutput(
            _cap_composite("\n".join(lines)),
            data={
                "device": device,
                "source": "smartctl",
                "model": smart_device.model,
                "attributes": [asdict(attr) for attr in smart_device.attributes],
            },
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        return _enrich_error_output(_no_smart_data_message(device, result), device)


@structured_tool(READ_ONLY)
async def get_nvme_health(device: str) -> str | ToolOutput:
    """Get NVMe SMART health log for an NVMe device.

    Data source priority:
    1. InfluxDB (Telegraf smart_device table) - no root required
    2. Direct nvme-cli via SSH - requires device access

    Args:
        device: NVMe device name (e.g., 'nvme0n1')

    Returns:
        NVMe SMART health data
    """
    if not security.validate_device_name(device):
        return f"❌ Invalid device name: {device}"

    # Priority 1: Try InfluxDB first. The lookup normalizes nvme0n1 -> nvme0.
    influx_data = await _get_influxdb_latest_device(device)
    if influx_data:
        return ToolOutput(
            _cap_composite(_format_influxdb_device_health(influx_data, device)),
            data={"device": device, "source": "influxdb", "sample": influx_data},
        )

    # Priority 2: Fall back to nvme-cli
    if not config.get("host", {}).get("enabled", False):
        if await _is_influxdb_available():
            return _no_smart_data_message(device)
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = NVME_SMART_LOG.render(device=device)
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    result = await _run_command(cmd)
    if _command_failed(result):
        return _enrich_error_output(result, device)
    return ToolOutput(
        _cap_composite(result),
        data={
            "device": device,
            "source": "nvme-cli",
            "fields": _parse_key_value_output(result),
            "raw": result,
        },
    )


@structured_tool(WRITE_ACTION)
async def run_smart_test(device: str, test_type: str = "short") -> str | ToolOutput:
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

    limited = _rate_limited("run_smart_test")
    if limited is not None:
        return limited

    # Pre-flight only asks smartctl for its version, so it never opens the
    # device and never spins up a sleeping disk. A missing or non-executable
    # smartctl must be reported before the write operation is attempted.
    preflight = await _run_command(SMART_VERSION.render())
    if _command_failed(preflight):
        return ToolOutput(
            _enrich_error_output(
                "❌ SMART self-tests unavailable: "
                f"{SMARTCTL_PATH} is missing or not executable by the executor "
                "user. No test was started.\n\n" + preflight,
                device,
            ),
            ok=False,
            data={
                "device": device,
                "test_type": test_type.lower(),
                "started": False,
            },
        )

    cmd = SMART_TEST.render(device=device, test_type=test_type.lower())
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"

    result = await _run_command(cmd)
    exit_match = EXIT_CODE_PATTERN.search(result)
    if exit_match and int(exit_match.group(1)) == 2:
        return ToolOutput(
            f"⚠️ No self-test started: /dev/{device} is in standby mode.\n"
            "The test command uses smartctl's `-n standby`, so it will not spin "
            "the disk up. Wake the disk explicitly (for example by reading from "
            "it) and call run_smart_test again.",
            data={
                "device": device,
                "test_type": test_type.lower(),
                "started": False,
                "reason": "standby",
            },
        )
    if _command_failed(result):
        return ToolOutput(
            _enrich_error_output(result, device),
            ok=False,
            data={
                "device": device,
                "test_type": test_type.lower(),
                "started": False,
            },
        )
    return ToolOutput(
        _cap_composite(result),
        data={
            "device": device,
            "test_type": test_type.lower(),
            "started": True,
            "output": result,
        },
    )


@structured_tool(READ_ONLY)
async def get_zfs_status() -> str | ToolOutput:
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

    parts = [
        ("ZFS Pool Status", ZPOOL_STATUS.render()),
        ("ZFS Pool List", ZPOOL_LIST.render()),
    ]
    for _, cmd in parts:
        if not security.is_command_safe(cmd):
            return "❌ Command not in safe whitelist"

    results = []
    outputs: dict[str, str] = {}
    for title, cmd in parts:
        output = await _run_command(cmd)
        outputs[title] = output
        results.append(f"=== {title} ===\n{output}")
    return ToolOutput(
        _cap_composite("\n\n".join(results)),
        data={
            "pool_status": outputs.get("ZFS Pool Status", ""),
            "pool_list": outputs.get("ZFS Pool List", ""),
        },
    )


@structured_tool(READ_ONLY)
async def get_raid_status() -> str | ToolOutput:
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

    parts = [
        ("MDSTAT", CAT_MDSTAT.render()),
        ("MDADM Detail", MDADM_DETAIL.render()),
    ]
    for _, cmd in parts:
        if not security.is_command_safe(cmd):
            return "❌ Command not in safe whitelist"

    results = []
    outputs: dict[str, str] = {}
    for title, cmd in parts:
        output = await _run_command(cmd)
        outputs[title] = output
        results.append(f"=== {title} ===\n{output}")
    return ToolOutput(
        _cap_composite("\n\n".join(results)),
        data={
            "mdstat": outputs.get("MDSTAT", ""),
            "mdadm_detail": outputs.get("MDADM Detail", ""),
        },
    )


@structured_tool(READ_ONLY)
async def get_snapraid_status() -> str | ToolOutput:
    """Get SnapRAID parity and sync status.

    SnapRAID is a snapshot/parity tool for collections of disks. Unlike ZFS or
    mdadm it does not provide a single block device, so this is the storage
    stack check for mergerFS + SnapRAID deployments.

    Returns:
        SnapRAID status (parity age, sync state, disk errors)
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    cmd = SNAPRAID_STATUS.render()
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    output = await _run_command(cmd)
    return ToolOutput(
        _cap_composite(output),
        data={"status": output, "fields": _parse_key_value_output(output)},
    )


@structured_tool(READ_ONLY)
async def get_mount_status() -> str | ToolOutput:
    """Get mounted filesystems and mergerFS pool state.

    mergerFS pools several disks behind one mount point and does not appear in
    ZFS or mdadm output. This tool reports the real mounts (`findmnt`), the
    mergerFS branches (when a pool is mounted) and filesystem usage (`df`).

    Returns:
        Mount, mergerFS and usage summary
    """
    if not config.get("host", {}).get("enabled", False):
        return (
            "❌ Host data source is not enabled.\n"
            "Set 'host.enabled: true' in config.yaml."
        )

    parts = [
        ("Mounted Filesystems", FINDMNT_MOUNTS.render()),
        ("mergerFS Pools", FINDMNT_MERGERFS.render()),
        ("Filesystem Usage", DF_REAL_FILESYSTEMS.render()),
    ]
    for _, cmd in parts:
        if not security.is_command_safe(cmd):
            return "❌ Command not in safe whitelist"

    results = []
    outputs: dict[str, str] = {}
    for title, cmd in parts:
        output = await _run_command(cmd)
        outputs[title] = output
        results.append(f"=== {title} ===\n{output}")
    return ToolOutput(
        _cap_composite("\n\n".join(results)),
        data={
            "mounts": outputs.get("Mounted Filesystems", ""),
            "mergerfs": outputs.get("mergerFS Pools", ""),
            "usage": outputs.get("Filesystem Usage", ""),
        },
    )


@structured_tool(READ_ONLY)
async def get_io_stats() -> str | ToolOutput:
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

    cmd = IOSTAT.render()
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"
    output = await _run_command(cmd)
    return ToolOutput(_cap_composite(output), data={"iostat": output})


# ============================================================================
# HTTP-based tools (InfluxDB, Prometheus)
# ============================================================================


_metric_clients: dict[tuple[str, int], InfluxDBClient | PrometheusClient] = {}


def _cached_client(name, cfg, factory):
    """Return one long-lived client per config object and service."""
    key = (name, id(cfg))
    client = _metric_clients.get(key)
    if client is None:
        client = factory()
        _metric_clients[key] = client
    return client


def _get_influxdb_client() -> InfluxDBClient:
    cfg = config.get("influxdb", {})
    return _cached_client("influxdb", cfg, _make_influxdb_client)  # type: ignore[return-value]


def _get_prometheus_client() -> PrometheusClient:
    cfg = config.get("prometheus", {})
    return _cached_client("prometheus", cfg, _make_prometheus_client)  # type: ignore[return-value]


QUERY_SUCCESS_PREFIX = "✅ Query successful"


def _query_data(result: str) -> dict:
    """Extract the JSON payload from a successful query response."""
    if not result.startswith(QUERY_SUCCESS_PREFIX):
        return {}
    try:
        payload = json.loads(result.split("\n\n", 1)[1])
    except (json.JSONDecodeError, IndexError):
        return {}
    if isinstance(payload, list):
        return {"rows": payload, "row_count": len(payload)}
    return {"result": payload}


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
    """Create InfluxDB client from config."""
    cfg = config.get("influxdb", {})
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
    """Create Prometheus client from config."""
    cfg = config.get("prometheus", {})
    return PrometheusClient(
        host=cfg.get("host", "localhost"),
        port=cfg.get("port", 9090),
        use_https=cfg.get("use_https", False),
        token=cfg.get("token"),
        max_output_bytes=_max_output_bytes(),
        timeout=parse_duration(cfg.get("query_timeout", "30s")),
        audit=create_audit_logger(config),
    )


@structured_tool(READ_ONLY)
async def query_prometheus_disk(query: str) -> str | ToolOutput:
    """Query Prometheus for disk-related metrics.

    Prometheus is optional. The smartmon_* metric family exists only when
    node_exporter runs with its smartmon collector; node_disk_* metrics come
    from node_exporter's disk collector. Without node_exporter, use
    query_influxdb_disk and the Telegraf smart_device/smart_attribute tables.

    Common queries:
    - node_disk_io_time_seconds_total
    - node_filesystem_avail_bytes
    - smartmon_health_ok          (requires node_exporter smartmon)
    - smartmon_temperature_celsius (requires node_exporter smartmon)

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
        _audit("query_blocked", kind="prometheus", query_length=len(query))
        return (
            "❌ Invalid query. Queries must:\n"
            "- Not contain null bytes or control characters other than newline/tab\n"
            "- Be at most 5000 characters\n"
            "- Be a single PromQL expression"
        )

    client = _get_prometheus_client()
    result = await client.query(validated)
    return ToolOutput(result, data=_query_data(result))


@structured_tool(READ_ONLY)
async def query_influxdb_disk(
    query: str, database: str | None = None
) -> str | ToolOutput:
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
        _audit("query_blocked", kind="influxdb", query_length=len(query))
        return (
            "❌ Invalid query. Queries must:\n"
            "- Start with SELECT (read-only only)\n"
            "- Not contain SQL comments (-- or /* */)\n"
            "- Not contain shell injection characters"
        )

    db = database or influx_config.get("database")
    if not db:
        return (
            "❌ No database specified. Provide 'database' parameter or set "
            "'influxdb.database' in config.yaml."
        )

    client = _get_influxdb_client()
    result = await client.query(validated, database=db)
    return ToolOutput(
        result,
        data={"database": db, **_query_data(result)},
    )


# ============================================================================
# Composite tools
# ============================================================================


async def _influxdb_latest_device_rows() -> list[dict]:
    """Return the latest valid smart_device row per device in one query.

    The previous overview issued ``1 + N`` sequential queries (one per
    device). A window function ranks the rows per device so the whole report
    costs one round trip regardless of how many disks are installed.
    """
    client = _get_influxdb_client()
    query = (
        "SELECT * FROM ("
        "SELECT *, ROW_NUMBER() OVER (PARTITION BY device ORDER BY time DESC) "
        "AS sample_rank FROM smart_device "
        f"WHERE exit_status = 0 AND time > now() - INTERVAL '{SMART_LOOKBACK}'"
        ") AS latest WHERE sample_rank = 1 ORDER BY device"
    )
    try:
        result = await client.query(query)
    except (json.JSONDecodeError, IndexError, KeyError):
        return []

    rows: list[dict] = []
    seen: set[str] = set()
    for row in _parse_influx_rows(result):
        device = row.get("device")
        if isinstance(device, str) and device and device not in seen:
            seen.add(device)
            rows.append(row)
    return rows


@structured_tool(READ_ONLY)
async def get_full_disk_report(device: str | None = None) -> str | ToolOutput:
    """Get a comprehensive disk health report combining multiple data sources.

    Data source priority:
    1. InfluxDB (Telegraf smart_device table) - no root required
    2. Direct smartctl via SSH - requires device access

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
    overview_devices: list[str] = []

    if await _is_influxdb_available():
        rows = await _influxdb_latest_device_rows()
        if not rows:
            note = (
                "⚠️  No valid SMART sample in InfluxDB "
                f"(last {SMART_LOOKBACK}; standby rows are ignored), "
                "falling back to SSH..."
            )
            return _cap_composite(f"{note}\n\n{await _get_full_report_via_ssh()}")

        overview_devices = [row["device"] for row in rows]
        lines.append("Source: InfluxDB (Telegraf smart plugin)\n")
        lines.append(
            f"Found {len(rows)} devices with a valid sample in the last "
            f"{SMART_LOOKBACK}:\n"
        )
        for row in rows:
            dev_name = row["device"]

            model = row.get("model", "unknown")
            health_ok = row.get("health_ok")
            temp = row.get("temp_c")
            poh = row.get("power_on_hours")
            age = _format_sample_age(row)

            if health_ok is True:
                emoji = "✅"
                health_text = "PASSED"
            elif health_ok is False:
                emoji = "🔴"
                health_text = "FAILED"
            else:
                emoji = "⚠️"
                health_text = "UNKNOWN"

            temp_flag = " 🔥" if isinstance(temp, int | float) and temp > 55 else ""
            parts = [
                f"  {emoji} /dev/{dev_name} - {model}",
                f"Health: {health_text}",
            ]
            if temp is not None:
                parts.append(f"Temp: {temp}°C{temp_flag}")
            if poh is not None:
                parts.append(f"POH: {poh:,}")
            if age:
                parts.append(f"Sample: {age}")
            lines.append(" | ".join(parts))
        lines.append(f"\n{'=' * 50}\n")
    else:
        lines.append("⚠️  InfluxDB not enabled, using SSH fallback\n")
        return await _get_full_report_via_ssh()

    return ToolOutput(
        _cap_composite("\n".join(lines)),
        data={"source": "influxdb", "devices": overview_devices},
    )


async def _get_full_report_via_ssh() -> str:
    """Generate full disk health report via SSH (requires device access)."""
    if not config.get("host", {}).get("enabled", False):
        if await _is_influxdb_available():
            return (
                "❌ No recent valid SMART sample available.\n"
                "InfluxDB has no sample with exit_status = 0 in the last "
                f"{SMART_LOOKBACK}, and host.enabled is false so there is no "
                "smartctl fallback. Standby rows (exit_status != 0) are not "
                "health data."
            )
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    lines = ["=== Disk Health Overview ===\n"]

    disk_list = await list_disks()
    if _command_failed(disk_list):
        lines.append(f"Disk list unavailable:\n{disk_list[:500]}")
        return _cap_composite("\n".join(lines))

    try:
        data = json.loads(disk_list)
        blockdevs = _disk_devices(data.get("blockdevices", []))
        lines.append(f"Found {len(blockdevs)} whole disks:\n")
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
        blockdevs = _disk_devices(data.get("blockdevices", []))
        for dev in blockdevs:
            name = dev.get("name", "")
            lines.append(f"\n--- /dev/{name} ---")
            cmd = SMART_JSON.render(device=name)
            if not security.is_command_safe(cmd):
                lines.append("  ❌ Command blocked by security")
                continue

            health = await _run_command(cmd)
            if _command_failed(health):
                enriched = _enrich_error_output(health, name)
                lines.append(f"  {enriched.replace(chr(10), chr(10) + '  ')}")
                continue

            try:
                smart_data = json.loads(health)
                smart_device = parse_smart_json(smart_data)
                if not has_usable_smart_data(smart_device):
                    lines.append("  ❌ No usable SMART data in the response")
                    continue
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

    return _cap_composite("\n".join(lines))


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

    logger.info("Starting Disk Health MCP...")
    logger.info(
        "Available tools: list_disks, get_disk_health, get_smart_attributes, "
        "get_nvme_health, run_smart_test, get_zfs_status, get_raid_status, "
        "get_snapraid_status, get_mount_status, get_io_stats, "
        "query_prometheus_disk, query_influxdb_disk, get_full_disk_report"
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
    parser = argparse.ArgumentParser(description="Disk Health MCP server")
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
