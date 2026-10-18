"""
Tests for disk-health command construction.

The executor is mocked; these tests assert the argv vectors produced by the
operation catalog and that the catalog is accepted by the shared command policy.
"""

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

    async def test_snapraid_status_uses_snapraid(self, patched_server):
        await server.get_snapraid_status()

        assert _commands(patched_server["executor"]) == ["snapraid status"]

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
            if command.endswith("--version"):
                return "❌ Command not found: /usr/sbin/smartctl"
            return "test should not run"

        executor.execute_safe_command.side_effect = fake_command

        result = await server.run_smart_test("sda")

        assert "SMART self-tests unavailable" in result
        assert "No test was started" in result
        commands = _commands(executor)
        assert commands == ["/usr/sbin/smartctl --version"]
        assert not any(" -t " in command for command in commands)

    async def test_standby_disk_does_not_start_a_test(self, patched_server):
        executor = patched_server["executor"]

        async def fake_command(command: str) -> str:
            if command.endswith("--version"):
                return "smartctl 7.4 2023-08-01"
            return "Device is in STANDBY mode\n\n⚠️ Exit code: 2"

        executor.execute_safe_command.side_effect = fake_command

        result = await server.run_smart_test("sda")

        assert "No self-test started" in result
        assert "standby" in result.lower()
        assert any("-n standby" in command for command in _commands(executor))


@pytest.mark.parametrize("test_type", ["short", "long", "conveyance"])
async def test_smart_test_uses_catalog(patched_server, test_type):
    await server.run_smart_test("sda", test_type)

    assert _commands(patched_server["executor"]) == [
        "/usr/sbin/smartctl --version",
        f"/usr/sbin/smartctl -n standby -t {test_type} /dev/sda",
    ]
