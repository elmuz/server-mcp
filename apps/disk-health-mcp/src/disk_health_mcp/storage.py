"""Storage-stack diagnostics for the disk-health MCP.

ZFS, mdadm, SnapRAID, mounts and iostat are one domain: each reads a host tool
through the allowlisted executor and reports the raw sections next to parsed
data. Keeping them out of the server module keeps the tool registration layer
small and lets this area gain focused tests without importing the whole app.

The server passes the live config, security validator, command runner and output
cap in explicitly, so module-level state (and the tests that patch it) stays in
one place.
"""

from collections.abc import Awaitable, Callable
from typing import Any

from server_management_lib import SecurityValidator, ToolOutput

from .operations import (
    CAT_MDSTAT,
    DF_REAL_FILESYSTEMS,
    FINDMNT_MERGERFS,
    FINDMNT_MOUNTS,
    IOSTAT,
    MDADM_DETAIL,
    SNAPRAID_STATUS,
    ZPOOL_LIST,
    ZPOOL_STATUS,
)

Config = dict[str, Any]
Runner = Callable[[str], Awaitable[str]]
Cap = Callable[[str], str]
CommandFailed = Callable[[str], bool]


def _host_disabled() -> str:
    return (
        "❌ Host data source is not enabled.\nSet 'host.enabled: true' in config.yaml."
    )


def _host_enabled(config: Config) -> bool:
    return bool(config.get("host", {}).get("enabled", False))


async def _run_parts(
    parts: list[tuple[str, str]],
    *,
    security: SecurityValidator,
    run_command: Runner,
    cap: Cap,
) -> tuple[str, dict[str, str]] | None:
    """Run a list of titled operations, or return None when one is not allowed."""
    for _, command in parts:
        if not security.is_command_safe(command):
            return None

    results: list[str] = []
    outputs: dict[str, str] = {}
    for title, command in parts:
        output = await run_command(command)
        outputs[title] = output
        results.append(f"=== {title} ===\n{output}")
    return cap("\n\n".join(results)), outputs


async def get_zfs_status(
    *,
    config: Config,
    security: SecurityValidator,
    run_command: Runner,
    cap: Cap,
) -> str | ToolOutput:
    if not _host_enabled(config):
        return _host_disabled()

    parts = [
        ("ZFS Pool Status", ZPOOL_STATUS.render()),
        ("ZFS Pool List", ZPOOL_LIST.render()),
    ]
    rendered = await _run_parts(
        parts, security=security, run_command=run_command, cap=cap
    )
    if rendered is None:
        return "❌ Command not in safe whitelist"

    text, outputs = rendered
    return ToolOutput(
        text,
        data={
            "pool_status": outputs.get("ZFS Pool Status", ""),
            "pool_list": outputs.get("ZFS Pool List", ""),
        },
    )


async def get_raid_status(
    *,
    config: Config,
    security: SecurityValidator,
    run_command: Runner,
    cap: Cap,
) -> str | ToolOutput:
    if not _host_enabled(config):
        return _host_disabled()

    parts = [
        ("MDSTAT", CAT_MDSTAT.render()),
        ("MDADM Detail", MDADM_DETAIL.render()),
    ]
    rendered = await _run_parts(
        parts, security=security, run_command=run_command, cap=cap
    )
    if rendered is None:
        return "❌ Command not in safe whitelist"

    text, outputs = rendered
    return ToolOutput(
        text,
        data={
            "mdstat": outputs.get("MDSTAT", ""),
            "mdadm_detail": outputs.get("MDADM Detail", ""),
        },
    )


async def get_snapraid_status(
    *,
    config: Config,
    security: SecurityValidator,
    run_command: Runner,
    cap: Cap,
    command_failed: CommandFailed,
    parse_status: Callable[[str], dict[str, object]],
) -> str | ToolOutput:
    if not _host_enabled(config):
        return _host_disabled()

    command = SNAPRAID_STATUS.render()
    if not security.is_command_safe(command):
        return "❌ Command not in safe whitelist"
    output = await run_command(command)
    return ToolOutput(
        cap(output),
        ok=not command_failed(output),
        data={
            "status": output,
            "parsed": parse_status(output),
        },
    )


async def get_mount_status(
    *,
    config: Config,
    security: SecurityValidator,
    run_command: Runner,
    cap: Cap,
) -> str | ToolOutput:
    if not _host_enabled(config):
        return _host_disabled()

    parts = [
        ("Mounted Filesystems", FINDMNT_MOUNTS.render()),
        ("mergerFS Pools", FINDMNT_MERGERFS.render()),
        ("Filesystem Usage", DF_REAL_FILESYSTEMS.render()),
    ]
    rendered = await _run_parts(
        parts, security=security, run_command=run_command, cap=cap
    )
    if rendered is None:
        return "❌ Command not in safe whitelist"

    text, outputs = rendered
    return ToolOutput(
        text,
        data={
            "mounts": outputs.get("Mounted Filesystems", ""),
            "mergerfs": outputs.get("mergerFS Pools", ""),
            "usage": outputs.get("Filesystem Usage", ""),
        },
    )


async def get_io_stats(
    *,
    config: Config,
    security: SecurityValidator,
    run_command: Runner,
    cap: Cap,
) -> str | ToolOutput:
    if not _host_enabled(config):
        return _host_disabled()

    command = IOSTAT.render()
    if not security.is_command_safe(command):
        return "❌ Command not in safe whitelist"
    output = await run_command(command)
    return ToolOutput(cap(output), data={"iostat": output})
