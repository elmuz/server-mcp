"""
Tests for disk-health command construction.

The executor is mocked; these tests assert the argv vectors produced by the
operation catalog and that the catalog is accepted by the shared command policy.
"""

import asyncio

import pytest

from disk_health_mcp import operations, server
from server_management_lib import Operation, SecurityValidator


def _commands(executor) -> list[str]:
    return [call.args[0] for call in executor.execute_safe_command.await_args_list]


class TestOperationCatalog:
    def test_every_operation_passes_the_command_policy(self):
        security = SecurityValidator({})
        for name, operation in vars(operations).items():
            if not isinstance(operation, Operation):
                continue
            command = operation.render(device="sda", test_type="short")
            assert security.is_command_safe(command) is True, (name, command)

    def test_operations_do_not_use_shell_syntax(self):
        for name, operation in vars(operations).items():
            if not isinstance(operation, Operation):
                continue
            command = operation.render(device="sda", test_type="short")
            assert "2>&1" not in command, name
            assert "&&" not in command, name


class TestHostCommands:
    async def test_list_disks_uses_lsblk_json(self, patched_server):
        await server.list_disks()

        assert _commands(patched_server["executor"]) == [
            "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json"
        ]

    async def test_zfs_status_runs_both_operations(self, patched_server):
        result = await server.get_zfs_status()

        assert "=== ZFS Pool Status ===" in result
        assert "=== ZFS Pool List ===" in result
        assert _commands(patched_server["executor"]) == [
            "zpool status -x",
            "zpool list -o name,size,alloc,free,cap,dedup,health",
        ]

    async def test_raid_status_runs_both_operations(self, patched_server):
        result = await server.get_raid_status()

        assert "=== MDSTAT ===" in result
        assert "=== MDADM Detail ===" in result
        assert _commands(patched_server["executor"]) == [
            "cat /proc/mdstat",
            "mdadm --detail --scan --verbose",
        ]

    async def test_io_stats_uses_iostat(self, patched_server):
        await server.get_io_stats()

        assert _commands(patched_server["executor"]) == ["iostat -x 1 1"]

    async def test_snapraid_status_runs_through_sudo(self, patched_server):
        """SnapRAID content and lock files are root:root 0600, so status needs root."""
        await server.get_snapraid_status()

        assert _commands(patched_server["executor"]) == [
            "sudo -n /usr/local/bin/snapraid status"
        ]

    async def test_mount_status_reports_mounts_and_mergerfs(self, patched_server):
        result = await server.get_mount_status()

        assert "=== Mounted Filesystems ===" in result
        assert "=== mergerFS Pools ===" in result
        assert "=== Filesystem Usage ===" in result
        assert _commands(patched_server["executor"]) == [
            "findmnt --real -o TARGET,SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%",
            "findmnt -t fuse.mergerfs -o TARGET,SOURCE,FSTYPE,OPTIONS",
            "df -h -x tmpfs -x devtmpfs -x overlay -x squashfs",
        ]

    async def test_host_tools_require_host_enabled(self, mock_config, mock_security):
        from unittest.mock import AsyncMock, patch

        config = dict(mock_config)
        config["host"] = {"enabled": False}
        executor = AsyncMock()

        with (
            patch("disk_health_mcp.server.config", config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
        ):
            assert "Host data source is not enabled" in (
                await server.get_snapraid_status()
            )
            assert "Host data source is not enabled" in (
                await server.get_mount_status()
            )

        executor.execute_safe_command.assert_not_awaited()


class TestToolAnnotations:
    def test_host_command_tools_are_read_only(self):
        tools = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}
        for name in (
            "list_disks",
            "get_zfs_status",
            "get_raid_status",
            "get_snapraid_status",
            "get_mount_status",
            "get_io_stats",
        ):
            assert tools[name].annotations.read_only_hint is True

    def test_run_smart_test_is_a_write_action(self):
        tools = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}
        assert tools["run_smart_test"].annotations.read_only_hint is False


class TestCompositeOutputCap:
    async def test_composite_output_is_capped_once(self, patched_server, monkeypatch):
        monkeypatch.setitem(server.config, "output", {"max_bytes": 200})

        async def fake_command(command: str) -> str:
            return "x" * 2000

        patched_server["executor"].execute_safe_command.side_effect = fake_command

        result = await server.get_zfs_status()

        assert result.count("truncated to 200 bytes") == 1
        assert "tool output truncated to 200 bytes" in result


class TestSmartTestPreflight:
    async def test_missing_smartctl_is_reported_without_running_test(
        self, patched_server
    ):
        executor = patched_server["executor"]

        async def fake_command(command: str) -> str:
            if "smartctl" in command:
                return "❌ Command not found: /usr/sbin/smartctl"
            return "{}"

        executor.execute_safe_command.side_effect = fake_command

        result = await server.run_smart_test("sda")

        assert "pre-flight failed" in result
        assert "No test was started" in result
        commands = _commands(executor)
        assert not any(" -t " in command for command in commands)

    async def test_standby_disk_does_not_start_a_test(self, patched_server):
        executor = patched_server["executor"]

        async def fake_command(command: str) -> str:
            if "lsblk" in command:
                return "{}"
            return "Device is in STANDBY mode\n\n⚠️ Exit code: 2"

        executor.execute_safe_command.side_effect = fake_command

        result = await server.run_smart_test("sda")

        assert "No self-test started" in result
        assert "standby" in result.lower()
        assert any("-n standby" in command for command in _commands(executor))
        assert not any(" -t " in command for command in _commands(executor))


@pytest.mark.parametrize("test_type", ["short", "long", "conveyance"])
async def test_smart_test_uses_catalog(patched_server, test_type):
    await server.run_smart_test("sda", test_type)

    assert _commands(patched_server["executor"]) == [
        "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json",
        "/usr/sbin/smartctl -n standby -i /dev/sda",
        f"/usr/sbin/smartctl -n standby -t {test_type} /dev/sda",
    ]


SNAPRAID_SAMPLE = """Loading state from /var/local/snapraid/snapraid.content...
Loaded state in 1 seconds
Using 923 MiB of memory for the file-system.
SnapRAID status report:

   Files Fragmented Excess  Wasted  Used    Free  Use Name
            Files  Fragments  GB      GB      GB
  195156    1721   11216    65.3    4903   12983  27% d1
  198870     804    7188    82.4    4915   12970  27% d2
 --------------------------------------------------------------------------
  394026    2525   18404   147.7    9819   25954  27%


 12%|                         o     o     o      o                        o
    |      o     o            *     *     *      *                        *
  0%|*_____*_____*_____*______*_____*_____*______*_____o_____o______o_____*
    79                    days ago of the last scrub/sync                 2

The oldest block was scrubbed 79 days ago, the median 44, the newest 2.

No sync is in progress.
11% of the array is not scrubbed.
You have 47513 files with a zero sub-second timestamp.
Run 'snapraid touch' to set their sub-second timestamps to a non-zero value.
No rehash is in progress or needed.
No error detected.
"""


def test_snapraid_status_parses_the_report():
    sample = SNAPRAID_SAMPLE

    async def run():
        from unittest.mock import AsyncMock, patch

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(return_value=sample)
        tool = server.mcp._tool_manager.get_tool("get_snapraid_status")
        with patch("disk_health_mcp.server.executor", executor):
            return await tool.fn()

    response = asyncio.run(run())
    parsed = response.data["parsed"]

    assert parsed["disks"][0] == {
        "files": 195156,
        "fragmented_files": 1721,
        "excess_fragments": 11216,
        "wasted_gb": 65.3,
        "used_gb": 4903,
        "free_gb": 12983,
        "use_pct": 27,
        "name": "d1",
    }
    assert parsed["totals"]["files"] == 394026
    assert parsed["sync_in_progress"] is False
    assert parsed["scrub"] == {
        "oldest_days": 79,
        "median_days": 44,
        "newest_days": 2,
        "not_scrubbed_pct": 11,
    }
    assert parsed["errors"] == "none"
    assert parsed["zero_timestamp_files"] == 47513


def test_smart_test_permission_failure_is_not_reported_as_standby(
    patched_server,
):
    executor = patched_server["executor"]

    async def fake_command(command: str) -> str:
        if "lsblk" in command:
            return "{}"
        return "/dev/sda: Permission denied\n\n⚠️ Exit code: 2"

    executor.execute_safe_command.side_effect = fake_command

    result = asyncio.run(server.run_smart_test("sda"))

    assert "standby" not in result.lower()
    assert "permission" in result.lower()
    assert "No test was started" in result
    assert not any(" -t " in command for command in _commands(executor))
