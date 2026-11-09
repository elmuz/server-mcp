"""Focused tests for the extracted storage-stack domain handlers."""

from unittest.mock import AsyncMock

import pytest

from disk_health_mcp import storage
from server_management_lib import SecurityValidator, ToolOutput


def _security() -> SecurityValidator:
    return SecurityValidator({})


def _deps(*, enabled: bool = True, safe: bool = True, failed: bool = False):
    config = {"host": {"enabled": enabled}}
    runner = AsyncMock(return_value="host output")
    command_failed = lambda output: failed  # noqa: E731
    if not safe:
        security = type("Unsafe", (), {"is_command_safe": lambda self, cmd: False})()
    else:
        security = _security()
    return config, security, runner, command_failed


async def test_zfs_and_raid_report_sections_and_parsed_data():
    config, security, runner, _ = _deps()

    zfs = await storage.get_zfs_status(
        config=config, security=security, run_command=runner, cap=lambda text: text
    )
    assert isinstance(zfs, ToolOutput)
    assert zfs.data == {
        "pool_status": "host output",
        "pool_list": "host output",
    }
    assert "=== ZFS Pool Status ===" in zfs.text

    raid = await storage.get_raid_status(
        config=config, security=security, run_command=runner, cap=lambda text: text
    )
    assert isinstance(raid, ToolOutput)
    assert raid.data == {"mdstat": "host output", "mdadm_detail": "host output"}


async def test_snapraid_honours_command_failure_and_parses_status():
    config, security, runner, command_failed = _deps(failed=True)
    parsed: list[str] = []
    result = await storage.get_snapraid_status(
        config=config,
        security=security,
        run_command=runner,
        cap=lambda text: text,
        command_failed=command_failed,
        parse_status=lambda output: parsed.append(output) or {"ok": False},
    )

    assert isinstance(result, ToolOutput)
    assert result.ok is False
    assert result.data == {"status": "host output", "parsed": {"ok": False}}
    assert parsed == ["host output"]


async def test_mount_and_io_report_expected_data():
    config, security, runner, _ = _deps()

    mounts = await storage.get_mount_status(
        config=config, security=security, run_command=runner, cap=lambda text: text
    )
    assert isinstance(mounts, ToolOutput)
    assert set(mounts.data) == {"mounts", "mergerfs", "usage"}

    io = await storage.get_io_stats(
        config=config, security=security, run_command=runner, cap=lambda text: text
    )
    assert isinstance(io, ToolOutput)
    assert io.data == {"iostat": "host output"}


@pytest.mark.parametrize(
    "handler",
    [
        storage.get_zfs_status,
        storage.get_raid_status,
        storage.get_mount_status,
        storage.get_io_stats,
    ],
)
async def test_host_disabled_is_reported_without_running_commands(handler):
    config, security, runner, _ = _deps(enabled=False)

    result = await handler(
        config=config, security=security, run_command=runner, cap=lambda text: text
    )

    assert "Host data source is not enabled" in result
    runner.assert_not_awaited()


async def test_unsafe_command_is_rejected_before_execution():
    config, security, runner, _ = _deps(safe=False)

    result = await storage.get_mount_status(
        config=config, security=security, run_command=runner, cap=lambda text: text
    )

    assert result == "❌ Command not in safe whitelist"
    runner.assert_not_awaited()
