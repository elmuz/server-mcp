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
from dataclasses import asdict, dataclass
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
# Telegraf's smart plugin polls every 5 minutes. Two missed polls mean the newest
# successful sample is no longer current health data.
SMART_POLL_INTERVAL_SECONDS = 5 * 60
SMART_STALE_AFTER_SECONDS = 2 * SMART_POLL_INTERVAL_SECONDS
SMART_FAILURE_LIMIT = 100
INFLUX_SUCCESS_PREFIX = "✅ Query successful"

# Serials and device tags are interpolated into single-quoted SQL literals and the
# InfluxDB client does not re-validate internally built queries, so a value is
# accepted only when it has the shape of a serial or a device tag. Everything else
# is dropped and the caller falls back to another selector.
SQL_LITERAL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:#/+_-]{0,63}$")

# A tag that still looks like a kernel name is legacy data (written before the
# tag became a static label), not a label: do not present it as one.
KERNEL_NAME_PATTERN = re.compile(
    r"^(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+(?:n\d+)?"
    r"|mmcblk\d+(?:p\d+)?|md\d+|dm-\d+)$"
)


class _InfluxSample(dict):
    """A smart_device row plus recent non-success polls for the same device.

    Subclassing ``dict`` keeps the row shape (and equality) used by callers while
    carrying failure evidence without adding a synthetic database column.
    """

    failed_polls: list[dict]

    def __init__(self, row: dict | None = None, failed_polls: list[dict] | None = None):
        super().__init__(row or {})
        self.failed_polls = list(failed_polls or [])


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


def _sample_age_seconds(row: dict) -> int | None:
    """Return the sample age in seconds, or None when its time is unusable."""
    timestamp = _parse_influx_time(row.get("time"))
    if timestamp is None:
        return None
    return max(0, int((datetime.now(UTC) - timestamp).total_seconds()))


def _identity_value(value: object) -> str:
    """Normalize a model/serial value, treating placeholders as missing."""
    if value is None:
        return ""
    text = str(value).strip()
    if text.casefold() in {"", "unknown", "n/a", "none", "null"}:
        return ""
    return text


def _same_serial(left: str, right: str) -> bool:
    return left.strip().casefold() == right.strip().casefold()


def _exit_status(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _format_failed_polls(failed_polls: list[dict] | None, *, prefix: str = "  ") -> str:
    """Describe recent non-success polls instead of hiding them."""
    failures = [row for row in (failed_polls or []) if isinstance(row, dict)]
    if not failures:
        return f"{prefix}Recent failed polls: none in the last {SMART_LOOKBACK}."

    def sort_key(row: dict) -> datetime:
        return _parse_influx_time(row.get("time")) or datetime.min.replace(tzinfo=UTC)

    latest = max(failures, key=sort_key)
    latest_status = _exit_status(latest.get("exit_status"))
    seen_statuses = sorted(
        status
        for row in failures
        if (status := _exit_status(row.get("exit_status"))) is not None
    )
    latest_age = _format_sample_age(latest) or "timestamp unavailable"
    count = len(failures)
    count_text = f"at least {count}" if count >= SMART_FAILURE_LIMIT else str(count)
    suffix = " (standby/skipped)" if latest_status == 2 else ""
    status_text = "unknown" if latest_status is None else str(latest_status)
    # Counted summary, not one token per row: the failure list can be long and
    # the output is returned to the model.
    counts: dict[int, int] = {}
    for status in seen_statuses:
        counts[status] = counts.get(status, 0) + 1
    statuses_text = (
        ", ".join(f"{status} x{amount}" for status, amount in sorted(counts.items()))
        or "unknown"
    )
    return (
        f"{prefix}⚠️ Recent failed polls: {count_text} non-success SMART poll(s) "
        f"in the last {SMART_LOOKBACK}; latest {latest_age} "
        f"(exit_status={status_text}{suffix}; seen: {statuses_text})."
    )


_UNSET = object()


def _assess_influxdb_sample(
    row: dict,
    device: str | None = None,
    *,
    failed_polls: list[dict] | None = None,
    live_device: object = _UNSET,
    require_live_identity: bool = False,
    retargeted: bool = False,
) -> dict:
    """Assess freshness, identity and poll failures for one InfluxDB sample.

    ``retargeted`` marks the case where the requested device name does not
    resolve on the host and the live device was found from the sample serial
    instead. The report then describes a disk the caller did not name, so it is
    never a verified match for the request.
    """
    requested = device or str(row.get("device") or "unknown")
    sample_serial = _identity_value(row.get("serial_no"))
    sample_model = _identity_value(row.get("model")) or "unknown"
    age_seconds = _sample_age_seconds(row)
    stale = age_seconds is None or age_seconds > SMART_STALE_AFTER_SECONDS
    failures = [item for item in (failed_polls or []) if isinstance(item, dict)]
    health_ok = row.get("health_ok")

    identity_checked = live_device is not _UNSET
    live = live_device if isinstance(live_device, dict) else None
    live_name = _identity_value(live.get("name")) if live else ""
    live_model = _identity_value(live.get("model")) if live else ""
    live_serial = _identity_value(live.get("serial")) if live else ""

    if not identity_checked:
        identity_state = "unchecked"
    elif live is None:
        identity_state = "unresolved"
    elif retargeted:
        identity_state = "retargeted"
    elif not sample_serial or not live_serial:
        identity_state = "unverified"
    elif _same_serial(sample_serial, live_serial):
        identity_state = "verified"
    else:
        identity_state = "mismatch"

    statuses = [_exit_status(item.get("exit_status")) for item in failures]
    non_standby_failure = any(status not in (None, 2) for status in statuses)

    if identity_state == "mismatch":
        status = "identity_mismatch"
        severity = "critical"
        emoji = "🔴"
        health_text = "UNKNOWN — sample belongs to a different disk"
    elif health_ok is False:
        status = "failed"
        severity = "critical"
        emoji = "🔴"
        health_text = "FAILED"
    elif stale:
        status = "stale"
        severity = "critical" if non_standby_failure else "warning"
        emoji = "🔴" if severity == "critical" else "🟡"
        health_text = (
            "STALE — last sample PASSED, not current"
            if health_ok is True
            else "STALE — last sample UNKNOWN, not current"
        )
    elif identity_state in {"unverified", "retargeted"} or (
        identity_state == "unresolved" and require_live_identity
    ):
        status = "identity_unverified"
        severity = "warning"
        emoji = "🟡"
        health_text = (
            "UNVERIFIED — requested device not found, sample belongs to another disk"
            if identity_state == "retargeted"
            else "UNVERIFIED — serial cannot be matched to the requested device"
        )
    elif health_ok is True:
        status = "ok"
        severity = "ok"
        emoji = "✅"
        health_text = "PASSED"
    else:
        status = "unknown"
        severity = "warning"
        emoji = "⚠️"
        health_text = "UNKNOWN"

    return {
        "device": requested,
        "sample_device": row.get("device", "unknown"),
        "sample_model": sample_model,
        "sample_serial": sample_serial,
        "sample_timestamp": row.get("time"),
        "age_seconds": age_seconds,
        "stale": stale,
        "failed_polls": failures,
        "identity_checked": identity_checked,
        "identity_state": identity_state,
        "live_device_name": live_name,
        "live_device_model": live_model,
        "live_device_serial": live_serial,
        "status": status,
        "severity": severity,
        "emoji": emoji,
        "health_text": health_text,
    }


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


def _describe_disk(
    label: object,
    live_name: object,
    requested: str = "",
    *,
    pair: bool = True,
) -> str:
    """Return a display name that carries both the role label and the live device.

    ``Data1 (/dev/sda)`` is what an operator needs: the label says which role
    the disk has, the kernel name says where it is right now. A legacy tag that
    still holds a kernel name is not a label, so it is not shown as one.

    ``pair=False`` suppresses the label/device pairing. Callers use it when the
    two are *not* known to describe the same disk (a sample whose serial does
    not match the requested device), because ``Data2 (/dev/sda)`` would assert
    an identity the report itself denies.
    """
    label_text = _identity_value(label)
    live_text = _identity_value(live_name)
    is_label = bool(label_text) and not KERNEL_NAME_PATTERN.match(label_text)
    if pair and is_label and live_text:
        return f"{label_text} (/dev/{live_text})"
    if live_text:
        return f"/dev/{live_text}"
    if requested:
        return f"/dev/{requested}"
    if label_text:
        return label_text
    return "unknown disk"


def _influxdb_device_name(device: str) -> str:
    """Map a kernel NVMe namespace name to the legacy Telegraf tag value.

    Telegraf's smart plugin stores ``nvme0``/``nvme1`` (namespace-less) while
    Linux exposes ``nvme0n1``/``nvme1n1``. Other device names are unchanged.
    Kept for the fallback path: the ``device`` tag is no longer an identity.
    """
    match = NVME_NAMESPACE_PATTERN.match(device)
    return match.group(1) if match else device


def _sql_literal(value: object) -> str:
    """Return ``value`` only when it may be quoted into an InfluxDB SQL literal.

    Serials and device tags come from the host (``lsblk``, Telegraf) and end up
    inside a query string, and the InfluxDB client does not run
    :meth:`SecurityValidator.validate_influxdb_query` on internally built
    queries. An allowlist is therefore the only line of defence: a value that
    does not look like a serial or a device tag is dropped (``""``) instead of
    being escaped by hand, and the caller falls back to another selector.
    """
    text = _identity_value(value)
    if not text:
        return ""
    if not SQL_LITERAL_PATTERN.match(text):
        logger.warning("Refusing unsafe InfluxDB identity value: %r", text)
        return ""
    return text


def _identity_selector(device: str, serial: str = "") -> str:
    """Build the SQL predicate that selects one physical disk.

    The serial is the only reboot-safe identity: kernel names are assigned by
    probe order and the ``device`` tag is now a static label (Data1, Parity1,
    ...). The ``device`` arm stays as a fallback for a host whose live serial
    cannot be resolved (SSH unavailable), or whose serial is not a value we are
    willing to put inside a query.
    """
    wanted = _sql_literal(serial)
    if wanted:
        return f"serial_no = '{wanted}'"
    return f"device = '{_sql_literal(_influxdb_device_name(device))}'"


def _failed_poll_selector(label: str, serial: str = "") -> str | None:
    """Build the predicate for the failed polls of one disk.

    Failed polls (``exit_status != 0``) may carry no serial on a host whose
    Telegraf does not stamp one, and their health fields are absent. They are
    then matched through ``device`` tags, and the only tag known to belong to
    this disk is the ``label`` its newest valid sample reported.

    A kernel name is *not* a safe handle: the same name is reused after a
    reboot and can still be a tag of another disk, so including it would attach
    that disk's failures to this one. Rows that do carry a serial are matched on
    it exactly, which also covers pollers that report the serial on failure
    rows.
    """
    tag = _sql_literal(_influxdb_device_name(label)) if label else ""
    wanted_serial = _sql_literal(serial)
    if wanted_serial and tag:
        return (
            f"(serial_no = '{wanted_serial}' OR "
            f"(device = '{tag}' AND (serial_no IS NULL OR serial_no = '')))"
        )
    if wanted_serial:
        return f"serial_no = '{wanted_serial}'"
    if tag:
        return f"device = '{tag}'"
    return None


def _live_serial(device: str, live_devices: dict[str, dict] | None) -> str:
    """Resolve a kernel device name to its live serial ('' when unavailable)."""
    live = _resolve_live_device(device, live_devices)
    if not live:
        return ""
    return _identity_value(live.get("serial"))


def _no_smart_data_message(
    device: str,
    detail: str = "",
    *,
    failed_polls: list[dict] | None = None,
) -> str:
    """Build an explicit no-data error instead of a fabricated health report."""
    message = (
        f"❌ No SMART data available for /dev/{device}.\n"
        "InfluxDB returned no recent valid sample (or is disabled). Only rows "
        f"with exit_status = 0 from the last {SMART_LOOKBACK} are used, so "
        "standby rows for a sleeping disk are ignored. The smartctl fallback "
        "did not produce data either. No health status is being inferred."
    )
    if failed_polls:
        message += f"\n\n{_format_failed_polls(failed_polls, prefix='')}"
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


async def _get_live_devices() -> dict[str, dict] | None:
    """Return live ``lsblk`` identities keyed by kernel device name.

    This is best-effort: host commands may be disabled or unavailable, in which
    case the caller can only report the stored sample identity and must not
    pretend that it was verified against the live device.
    """
    if not config.get("host", {}).get("enabled", False):
        return None

    cmd = LIST_DISKS.render()
    if not security.is_command_safe(cmd):
        return None
    try:
        output = await executor.execute_safe_command(cmd)
    except Exception as exc:  # pragma: no cover - defensive around executors
        logger.debug("Live device lookup failed: %s", exc)
        return None
    if _command_failed(output):
        return None
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    devices: dict[str, dict] = {}
    for dev in _disk_devices(payload.get("blockdevices", [])):
        name = dev.get("name")
        if isinstance(name, str) and name:
            devices[name] = dev
    return devices


def _resolve_live_device(
    device: str,
    live_devices: dict[str, dict] | None,
    *,
    serial: str = "",
    allow_serial_match: bool = True,
) -> dict | None:
    """Find the live row for a kernel name, label or InfluxDB device tag.

    The serial wins when the caller has one: a name or label can be ambiguous
    across time (``sdd`` was a kernel name before the tag became a label, and
    it now names a different disk), while the serial always identifies exactly
    one physical disk. Without a usable serial, an exact name, then an NVMe
    namespace match (``nvme0`` -> ``nvme0n1``) is used.
    """
    if not live_devices:
        return None

    wanted = _identity_value(serial)
    if allow_serial_match and wanted:
        for dev in live_devices.values():
            if _same_serial(wanted, _identity_value(dev.get("serial"))):
                return dev

    exact = live_devices.get(device)
    if exact is not None:
        return exact

    match = NVME_NAMESPACE_PATTERN.match(device)
    prefix = (
        f"{match.group(1)}n"
        if match
        else (f"{device}n" if device.startswith("nvme") else "")
    )
    if prefix:
        for name, dev in live_devices.items():
            if name.startswith(prefix):
                return dev
    return None


async def _get_influxdb_recent_failed_polls(label: str, serial: str = "") -> list[dict]:
    """Return recent non-success smart_device rows for one disk (newest first).

    ``label`` is the tag of the newest valid sample and ``serial`` is the disk
    identity when the caller resolved it. See :func:`_failed_poll_selector` for
    why a requested kernel name is not used as a handle.
    """
    selector = _failed_poll_selector(label, serial)
    if selector is None or not await _is_influxdb_available():
        return []

    client = _get_influxdb_client()
    query = (
        f"SELECT device, exit_status, time FROM smart_device "
        f"WHERE {selector} AND exit_status != 0 "
        f"AND time > now() - INTERVAL '{SMART_LOOKBACK}' "
        f"ORDER BY time DESC LIMIT {SMART_FAILURE_LIMIT}"
    )
    try:
        result = await client.query(query)
    except (json.JSONDecodeError, IndexError, KeyError):
        return []
    return [
        row
        for row in _parse_influx_rows(result)
        if _exit_status(row.get("exit_status")) not in (None, 0)
    ]


async def _is_influxdb_available() -> bool:
    """Check if InfluxDB is enabled and reachable."""
    influx_config = config.get("influxdb", {})
    if not influx_config.get("enabled", False):
        return False
    return True


async def _get_influxdb_latest_device(device: str, serial: str = "") -> dict | None:
    """Get the latest *valid* smart_device row for a disk from InfluxDB.

    Telegraf keeps writing rows while a disk sleeps, but those rows carry
    ``exit_status=2`` and no health, temperature or wear fields. Only successful
    samples (``exit_status = 0``) are health data, so they are the only rows
    considered. The lookback covers a full sleep cycle plus the poll interval.

    The disk is selected by ``serial`` whenever the caller could resolve the
    live serial; the ``device`` label is only a fallback. This is what keeps a
    report attached to the same physical disk after a reboot re-enumerates the
    controller or the tag is re-written by a deployment.

    The returned row carries recent non-success polls in its ``failed_polls``
    attribute. When InfluxDB is available but has no valid sample, an empty
    (falsy) row is returned so callers can still explain why the disk is not
    healthy. ``None`` means InfluxDB is disabled or the query failed.
    """
    if not await _is_influxdb_available():
        return None

    selector = _identity_selector(device, serial)
    client = _get_influxdb_client()
    query = (
        f"SELECT * FROM smart_device WHERE {selector} "
        f"AND exit_status = 0 AND time > now() - INTERVAL '{SMART_LOOKBACK}' "
        f"ORDER BY time DESC LIMIT 1"
    )
    try:
        result = await client.query(query)
        rows = _parse_influx_rows(result)
    except (json.JSONDecodeError, IndexError, KeyError):
        return None
    row = rows[0] if rows else None
    label = _identity_value(row.get("device")) if row else ""
    # With a sample, the label it reported is the only safe tag handle: kernel
    # names are reused across disks. Without a sample there is nothing to
    # disambiguate, so the requested name is used so the caller can still
    # explain *why* no valid sample exists (standby checklist rows).
    failed_polls = await _get_influxdb_recent_failed_polls(label or device, serial)
    return _InfluxSample(row, failed_polls)


async def _get_influxdb_latest_attributes(
    device: str, serial: str = ""
) -> list[dict] | None:
    """Get the latest smart_attribute rows for a disk from InfluxDB.

    Only rows from successful samples are returned; standby rows carry no
    attributes and must not be rendered as wear data. Identity comes from the
    serial, exactly like :func:`_get_influxdb_latest_device`.

    Returns a list of attribute dicts, or None if unavailable.
    """
    if not await _is_influxdb_available():
        return None

    selector = _identity_selector(device, serial)
    client = _get_influxdb_client()
    # No ``exit_status`` filter here: Telegraf writes that field on SATA
    # smartctl output only, never on the NVMe rows, so filtering on it silently
    # dropped every NVMe attribute and sent the tool to the unprivileged
    # smartctl fallback. Standby rows need no filter either - a sleeping disk
    # produces a smart_device row but no smart_attribute rows at all.
    query = (
        f"SELECT name, raw_value, device, serial_no FROM smart_attribute "
        f"WHERE {selector} "
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


def _render_influxdb_health(
    row: dict,
    device: str | None = None,
    *,
    failed_polls: list[dict] | object | None = _UNSET,
    live_device: object = _UNSET,
    require_live_identity: bool = False,
    retargeted: bool = False,
) -> tuple[str, dict, bool]:
    """Render an InfluxDB sample with freshness, identity and poll-failure checks."""
    if failed_polls is _UNSET:
        failed_polls = getattr(row, "failed_polls", [])
    if not isinstance(failed_polls, list):
        failed_polls = []

    assessment = _assess_influxdb_sample(
        row,
        device,
        failed_polls=failed_polls,
        live_device=live_device,
        require_live_identity=require_live_identity,
        retargeted=retargeted,
    )
    requested = assessment["device"]
    model = assessment["sample_model"]
    serial = assessment["sample_serial"]
    temp = row.get("temp_c")
    power_on_hours = row.get("power_on_hours")
    power_cycles = row.get("power_cycle_count")
    age = _format_sample_age(row)
    stale_after_minutes = SMART_STALE_AFTER_SECONDS // 60
    poll_minutes = SMART_POLL_INTERVAL_SECONDS // 60

    # Only a verified or retargeted sample is known to belong to the live
    # device that was resolved; on a mismatch the label belongs to another disk.
    title = _describe_disk(
        assessment["sample_device"],
        assessment["live_device_name"],
        requested,
        pair=assessment["identity_state"] in {"verified", "retargeted"},
    )
    lines = [
        f"{assessment['emoji']} Device Health Report: {title}",
        f"{'=' * 50}",
        "  Source: InfluxDB (Telegraf smart plugin)",
    ]
    lines.append(f"  Sample: {age}" if age else "  Sample: timestamp unavailable")
    lines.append(f"  Sample Device Tag: {assessment['sample_device']}")
    lines.append(f"  Model: {model}")
    lines.append(f"  Serial: {serial or 'unknown'}")

    if assessment["identity_checked"]:
        live_name = assessment["live_device_name"]
        live_model = assessment["live_device_model"]
        live_serial = assessment["live_device_serial"]
        if live_name:
            lines.append(
                f"  Live Device: /dev/{live_name} "
                f"(model {live_model or 'unknown'}, "
                f"serial {live_serial or 'unknown'})"
            )
        else:
            lines.append(
                "  Live Device: unavailable (host data source disabled or lsblk failed)"
            )

        state = assessment["identity_state"]
        if state == "verified":
            lines.append(
                f"  Identity: verified — sample serial {serial} matches live "
                f"/dev/{live_name}."
            )
        elif state == "mismatch":
            lines.append(
                f"  Identity: 🔴 MISMATCH — requested /dev/{requested} resolves "
                f"to live serial {live_serial or 'unknown'} "
                f"({live_model or 'unknown'}), but the sample serial is "
                f"{serial or 'unknown'} ({model})."
            )
        elif state == "retargeted":
            lines.append(
                f"  Identity: ⚠️ UNVERIFIED for /dev/{requested} — that name does "
                f"not resolve on the host; the sample serial "
                f"{serial or 'unknown'} belongs to live /dev/{live_name}. "
                "The report describes that disk, not the requested name."
            )
        elif state == "unverified":
            lines.append(
                "  Identity: ⚠️ UNVERIFIED — serial is missing from the sample "
                "or the live device, so it cannot be matched."
            )
        else:
            lines.append(
                f"  Identity: ⚠️ UNVERIFIED — live /dev/{requested} could not be "
                f"resolved; sample serial {serial or 'unknown'} cannot be matched."
            )

    if assessment["age_seconds"] is None:
        lines.append(
            "  Freshness: ⚠️ UNVERIFIED — sample timestamp is missing; current "
            f"health cannot be established (threshold {stale_after_minutes} min)."
        )
    elif assessment["stale"]:
        lines.append(
            f"  Freshness: ⚠️ STALE — no successful sample within "
            f"{stale_after_minutes} minutes "
            f"(2 x {poll_minutes}-minute poll interval); this is not current health."
        )
    else:
        lines.append(
            f"  Freshness: current — sample is within {stale_after_minutes} "
            f"minutes (2 x {poll_minutes}-minute poll interval)."
        )

    lines.append(f"  Health: {assessment['health_text']}")
    lines.append(_format_failed_polls(failed_polls))

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

    data = {
        "device": requested,
        "source": "influxdb",
        "sample": dict(row),
        "sample_device": assessment["sample_device"],
        "sample_model": model,
        "sample_serial": serial,
        "sample_timestamp": assessment["sample_timestamp"],
        "age_seconds": assessment["age_seconds"],
        "stale": assessment["stale"],
        "freshness": (
            "unknown"
            if assessment["age_seconds"] is None
            else "stale"
            if assessment["stale"]
            else "current"
        ),
        "failed_poll_count": len(failed_polls),
        "recent_failed_polls": failed_polls,
        "identity": {
            "state": assessment["identity_state"],
            "live_device": assessment["live_device_name"],
            "live_model": assessment["live_device_model"],
            "live_serial": assessment["live_device_serial"],
        },
        "status": assessment["status"],
        "severity": assessment["severity"],
    }
    return "\n".join(lines), data, assessment["severity"] == "ok"


def _format_influxdb_device_health(
    row: dict,
    device: str | None = None,
    *,
    failed_polls: list[dict] | object | None = _UNSET,
    live_device: object = _UNSET,
    require_live_identity: bool = False,
) -> str:
    """Format an InfluxDB smart_device row into a human-readable health report.

    ``device`` lets callers display the kernel name (for example ``nvme0n1``)
    while the InfluxDB row uses the Telegraf tag (``nvme0``). Callers that can
    resolve the live device pass it so serial mismatches are not hidden.
    """
    text, _, _ = _render_influxdb_health(
        row,
        device,
        failed_polls=failed_polls,
        live_device=live_device,
        require_live_identity=require_live_identity,
    )
    return text


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


async def _influxdb_health_tool_output(
    row: dict,
    device: str,
    *,
    require_live_identity: bool = True,
    live_devices: dict[str, dict] | None = None,
) -> ToolOutput:
    """Resolve the live identity and render one InfluxDB-backed health report.

    The requested name stays the reference for the identity check: the live
    device is resolved from ``device`` and the sample serial is compared with
    *that* disk. Only when the requested name no longer resolves is the sample
    serial used to find the disk it belongs to, and the report says so instead
    of calling the request verified.

    ``live_devices`` lets a caller that already ran ``lsblk`` reuse the result
    instead of paying for a second round trip.
    """
    if live_devices is None:
        live_devices = await _get_live_devices()
    live_device = _resolve_live_device(device, live_devices)
    retargeted = live_device is None
    if retargeted:
        live_device = _resolve_live_device(
            device,
            live_devices,
            serial=_identity_value(row.get("serial_no")),
        )
    text, data, ok = _render_influxdb_health(
        row,
        device,
        failed_polls=getattr(row, "failed_polls", None),
        live_device=live_device,
        require_live_identity=require_live_identity,
        retargeted=retargeted,
    )
    return ToolOutput(_cap_composite(text), ok=ok, data=data)


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

    # Priority 1: Try InfluxDB (no root needed). Resolve the live serial first
    # so the sample is selected by identity, not by a tag that a previous
    # deployment may have pointed at another physical disk. The ``lsblk``
    # result is reused below instead of running it twice.
    live_devices = await _get_live_devices()
    serial = _live_serial(device, live_devices)
    influx_data = await _get_influxdb_latest_device(device, serial=serial)
    failed_polls = getattr(influx_data, "failed_polls", None)
    if influx_data:
        return await _influxdb_health_tool_output(
            influx_data, device, live_devices=live_devices
        )

    # Priority 2: Fall back to smartctl via SSH
    if not config.get("host", {}).get("enabled", False):
        if await _is_influxdb_available():
            return _no_smart_data_message(device, failed_polls=failed_polls)
        return (
            "❌ No data sources available.\n"
            "Enable at least one: host.enabled or influxdb.enabled in config.yaml."
        )

    cmd = SMART_JSON.render(device=device)
    if not security.is_command_safe(cmd):
        return "❌ Command not in safe whitelist"

    raw_output = await _run_command(cmd)
    if _command_failed(raw_output):
        return _enrich_error_output(
            _no_smart_data_message(device, raw_output, failed_polls=failed_polls),
            device,
        )

    try:
        data = json.loads(raw_output)
        smart_device: SmartDevice = parse_smart_json(data)
        if not has_usable_smart_data(smart_device):
            return _enrich_error_output(
                _no_smart_data_message(device, raw_output, failed_polls=failed_polls),
                device,
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
                _no_smart_data_message(device, raw_text, failed_polls=failed_polls),
                device,
            )

        text_device = parse_smart_text(raw_text)
        if text_device is None:
            return _enrich_error_output(
                _no_smart_data_message(device, raw_text, failed_polls=failed_polls),
                device,
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

    # Priority 1: Try InfluxDB (no root needed). Select the rows by serial so
    # a re-enumerated (or re-tagged) disk keeps reporting its own attributes.
    live_devices = await _get_live_devices()
    serial = _live_serial(device, live_devices)
    influx_attrs = await _get_influxdb_latest_attributes(device, serial=serial)
    if influx_attrs:
        # Fetch device summary for SSD wear cross-reference
        influx_device = await _get_influxdb_latest_device(device, serial=serial)

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

    # Priority 1: try InfluxDB first, selecting the disk by its live serial.
    live_devices = await _get_live_devices()
    serial = _live_serial(device, live_devices)
    influx_data = await _get_influxdb_latest_device(device, serial=serial)
    failed_polls = getattr(influx_data, "failed_polls", None)
    if influx_data:
        return await _influxdb_health_tool_output(
            influx_data, device, live_devices=live_devices
        )

    # Priority 2: Fall back to nvme-cli
    if not config.get("host", {}).get("enabled", False):
        if await _is_influxdb_available():
            return _no_smart_data_message(device, failed_polls=failed_polls)
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


_metric_clients: dict[tuple[object, ...], InfluxDBClient | PrometheusClient] = {}


def _cached_client(name, cfg, factory):
    """Return one long-lived client per service endpoint.

    The key is the endpoint, not the ``id()`` of the config dict: an address can
    be reused once a dict is freed, which would hand back a client built for a
    different endpoint. ``apply_config()`` clears the cache, so a changed token
    or database is picked up on reload.
    """
    key = (name, cfg.get("host"), cfg.get("port"), cfg.get("scheme"))
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


@dataclass
class _FailedPolls:
    """Recent non-success SMART rows, indexed by physical disk.

    The current Telegraf deployment stamps ``serial_no`` on every poll,
    including a standby row, so the serial is the primary key. A row from a
    poller that recorded no serial is kept under the ``device`` label that
    wrote it; the label is only a fallback because it is mutable across a
    redeploy.
    """

    by_serial: dict[str, list[dict]]
    by_label: dict[str, list[dict]]

    def for_disk(self, serial: str, label: str = "") -> list[dict]:
        """Return the failures that belong to one physical disk."""
        rows = list(self.by_serial.get(_identity_value(serial), []))
        wanted_label = _identity_value(label)
        if wanted_label:
            rows.extend(self.by_label.get(wanted_label, []))
        return rows

    def groups(self) -> dict[str, list[dict]]:
        """Group failures by the label they carry, for the no-sample report."""
        grouped: dict[str, list[dict]] = {}
        for rows in self.by_serial.values():
            key = _identity_value(rows[0].get("device")) if rows else ""
            grouped.setdefault(key or "unknown", []).extend(rows)
        for label, rows in self.by_label.items():
            grouped.setdefault(label, []).extend(rows)
        return grouped


async def _influxdb_recent_failures_by_disk() -> _FailedPolls:
    """Return recent non-success smart_device rows indexed by physical disk.

    Grouping by ``serial_no`` is what keeps failure evidence attached to the
    right disk after a label change: Telegraf now tags every poll, including a
    standby row, with the disk serial. Rows without a serial still fall back to
    the ``device`` label for hosts that have not been redeployed yet.
    """
    empty = _FailedPolls({}, {})
    if not await _is_influxdb_available():
        return empty

    client = _get_influxdb_client()
    query = (
        "SELECT device, serial_no, exit_status, time FROM smart_device "
        f"WHERE exit_status != 0 AND time > now() - INTERVAL '{SMART_LOOKBACK}' "
        f"ORDER BY time DESC LIMIT {SMART_FAILURE_LIMIT * 10}"
    )
    try:
        result = await client.query(query)
    except (json.JSONDecodeError, IndexError, KeyError):
        return empty

    by_serial: dict[str, list[dict]] = {}
    by_label: dict[str, list[dict]] = {}
    for row in _parse_influx_rows(result):
        status = _exit_status(row.get("exit_status"))
        if status in (None, 0):
            continue
        serial = _identity_value(row.get("serial_no"))
        if serial:
            by_serial.setdefault(serial, []).append(row)
            continue
        label = _identity_value(row.get("device"))
        if label:
            by_label.setdefault(label, []).append(row)
    return _FailedPolls(by_serial, by_label)


async def _influxdb_latest_device_rows() -> list[dict]:
    """Return the latest valid smart_device row per *physical disk*.

    The previous overview issued ``1 + N`` sequential queries (one per
    device). A window function ranks the rows per disk so the whole report
    costs one round trip regardless of how many disks are installed.

    Ranking is partitioned by ``serial_no``, not by the ``device`` tag: the
    tag is only a label, and grouping on it would split one disk into two
    series whenever the label changes. Recent non-success polls are attached
    by serial (label only as a fallback for rows without one) so staleness has
    an explanation even after the label is rewritten.
    """
    failures = await _influxdb_recent_failures_by_disk()
    client = _get_influxdb_client()
    query = (
        "SELECT * FROM ("
        "SELECT *, ROW_NUMBER() OVER (PARTITION BY serial_no ORDER BY time DESC) "
        "AS sample_rank FROM smart_device "
        f"WHERE exit_status = 0 AND time > now() - INTERVAL '{SMART_LOOKBACK}' "
        "AND serial_no IS NOT NULL AND serial_no != ''"
        ") AS latest WHERE sample_rank = 1 ORDER BY serial_no"
    )
    try:
        result = await client.query(query)
    except (json.JSONDecodeError, IndexError, KeyError):
        return []

    rows: list[dict] = []
    seen: set[str] = set()
    for row in _parse_influx_rows(result):
        serial = _identity_value(row.get("serial_no"))
        if not serial or serial in seen:
            continue
        seen.add(serial)
        label = _identity_value(row.get("device"))
        rows.append(_InfluxSample(row, failures.for_disk(serial, label)))
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
    # Parallel lists: a kernel name ``get_disk_health()`` accepts (or "" when the
    # disk could not be matched to a live device), the static role label ("" for
    # a legacy tag that still holds a kernel name) and the serial.
    overview_devices: list[str] = []
    overview_labels: list[str] = []
    overview_serials: list[str] = []

    if await _is_influxdb_available():
        rows = await _influxdb_latest_device_rows()
        if not rows:
            failures = await _influxdb_recent_failures_by_disk()
            note = (
                "⚠️  No valid SMART sample in InfluxDB "
                f"(last {SMART_LOOKBACK}; standby rows are ignored), "
                "falling back to SSH..."
            )
            failure_groups = failures.groups()
            if failure_groups:
                failure_lines = [
                    f"  {label}: {_format_failed_polls(polls, prefix='')}"
                    for label, polls in sorted(failure_groups.items())
                ]
                note += (
                    "\n\nRecent non-success SMART polls explain the missing sample:"
                    "\n" + "\n".join(failure_lines)
                )
            return _cap_composite(f"{note}\n\n{await _get_full_report_via_ssh()}")

        live_devices = await _get_live_devices()
        lines.append("Source: InfluxDB (Telegraf smart plugin)\n")
        lines.append(
            f"Found {len(rows)} devices with a valid sample in the last "
            f"{SMART_LOOKBACK}:\n"
        )
        for row in rows:
            dev_name = row["device"]
            serial = _identity_value(row.get("serial_no"))
            failed_polls = getattr(row, "failed_polls", [])
            live_device = _resolve_live_device(
                dev_name,
                live_devices,
                serial=serial,
            )
            assessment = _assess_influxdb_sample(
                row,
                dev_name,
                failed_polls=failed_polls,
                live_device=live_device,
                require_live_identity=True,
            )

            label = _identity_value(dev_name)
            is_label = bool(label) and not KERNEL_NAME_PATTERN.match(label)
            live_name = _identity_value(assessment["live_device_name"])
            overview_devices.append(live_name or ("" if is_label else label))
            overview_labels.append(label if is_label else "")
            overview_serials.append(serial)

            temp = row.get("temp_c")
            poh = row.get("power_on_hours")
            age = _format_sample_age(row)
            temp_flag = " 🔥" if isinstance(temp, int | float) and temp > 55 else ""
            parts = [
                f"  {assessment['emoji']} "
                f"{_describe_disk(dev_name, assessment['live_device_name'])} - "
                f"{assessment['sample_model']}",
                f"Health: {assessment['health_text']}",
                f"Serial: {serial or 'unknown'}",
            ]
            if not assessment["live_device_name"]:
                parts.append("Live: unavailable")
            if temp is not None:
                parts.append(f"Temp: {temp}°C{temp_flag}")
            if poh is not None:
                parts.append(f"POH: {poh:,}")
            if age:
                parts.append(f"Sample: {age}")
            else:
                parts.append("Sample: timestamp unavailable")
            if assessment["stale"]:
                parts.append(
                    f"Freshness: STALE (>{SMART_STALE_AFTER_SECONDS // 60} min)"
                )
            if assessment["identity_state"] == "mismatch":
                parts.append(
                    f"Identity: MISMATCH sample serial {serial or 'unknown'} != "
                    f"live serial {assessment['live_device_serial'] or 'unknown'}"
                )
            elif assessment["identity_state"] == "unverified":
                parts.append("Identity: UNVERIFIED (serial missing)")
            elif assessment["identity_state"] == "unresolved":
                parts.append("Identity: UNVERIFIED (live device not resolved)")
            elif assessment["identity_state"] == "verified":
                parts.append("Identity: verified")

            line = " | ".join(parts)
            if failed_polls:
                line += "\n    " + _format_failed_polls(failed_polls, prefix="")
            lines.append(line)
        lines.append(f"\n{'=' * 50}\n")
    else:
        lines.append("⚠️  InfluxDB not enabled, using SSH fallback\n")
        return await _get_full_report_via_ssh()

    return ToolOutput(
        _cap_composite("\n".join(lines)),
        data={
            "source": "influxdb",
            "devices": overview_devices,
            "labels": overview_labels,
            "serials": overview_serials,
        },
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
