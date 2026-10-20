"""Tests for structured outputs and MCP resources in disk-health-mcp."""

import asyncio
import json
from typing import Any, cast

import pytest

from disk_health_mcp import server
from server_management_lib import ToolResponse


class TestStructuredOutput:
    def test_every_tool_publishes_an_output_schema(self):
        tools = server.mcp._tool_manager.list_tools()

        assert len(tools) == 13
        for tool in tools:
            assert tool.output_schema is not None, tool.name
            assert tool.output_schema["title"] == "ToolResponse"

    def test_list_disks_returns_structured_devices(self, patched_server):
        tool = server.mcp._tool_manager.get_tool("list_disks")

        response = asyncio.run(tool.fn())

        assert isinstance(response, ToolResponse)
        assert response.tool == "list_disks"
        assert response.ok is True
        assert response.data["count"] == 1
        assert response.data["devices"][0]["name"] == "sda"

    def test_error_response_is_not_ok(self, patched_server):
        patched_server["config"]["host"]["enabled"] = False
        patched_server["config"]["influxdb"]["enabled"] = False
        tool = server.mcp._tool_manager.get_tool("get_disk_health")

        response = asyncio.run(tool.fn(device="sda"))

        assert response.ok is False
        assert "No data sources available" in response.text

    def test_smartctl_health_includes_source(self, patched_server):
        patched_server["config"]["influxdb"]["enabled"] = False
        tool = server.mcp._tool_manager.get_tool("get_disk_health")

        response = asyncio.run(tool.fn(device="sda"))

        assert response.ok is True
        assert response.data["source"] in {"smartctl", "smartctl-text"}
        assert response.data["device"] == "sda"


def _resource_json(uri: str) -> dict:
    """Read an MCP resource and decode its JSON payload."""
    result = asyncio.run(server.mcp.read_resource(uri))
    items = cast(Any, result)
    return json.loads(items[0].content)


class TestResources:
    def test_static_resources_are_registered(self):
        resources = {
            str(resource.uri)
            for resource in server.mcp._resource_manager.list_resources()
        }

        assert "server-mcp://config/schema" in resources
        assert "server-mcp://tools/catalog" in resources

    def test_config_schema_masks_secrets(self):
        payload = _resource_json("server-mcp://config/schema")

        assert payload["app"] == "disk-health-mcp"
        assert payload["defaults"]["influxdb"]["token"] == "***"

    def test_tool_catalog_lists_disk_tools(self):
        payload = _resource_json("server-mcp://tools/catalog")

        names = {tool["name"] for tool in payload["tools"]}
        assert "get_disk_health" in names
        assert "run_smart_test" in names

    def test_tool_template_returns_details(self):
        payload = _resource_json("server-mcp://tools/run_smart_test")

        assert payload["name"] == "run_smart_test"
        assert payload["read_only"] is False

    def test_unknown_tool_template_fails(self):
        with pytest.raises(Exception, match="Error creating resource from template"):
            asyncio.run(server.mcp.read_resource("server-mcp://tools/nope"))


def _commands(executor) -> list[str]:
    return [call.args[0] for call in executor.execute_safe_command.await_args_list]


class TestOperationalHardening:
    """P1-12/P1-14/P1-15/P1-16 regressions."""

    def test_run_smart_test_is_rate_limited(self, patched_server, monkeypatch):
        from server_management_lib import RateLimiter

        monkeypatch.setattr(server, "rate_limiter", RateLimiter(1, 60))
        executor = patched_server["executor"]

        async def fake_command(command: str) -> str:
            if command.endswith("--version"):
                return "smartctl 7.4"
            return "SMART self-test started"

        executor.execute_safe_command.side_effect = fake_command

        first = asyncio.run(server.run_smart_test("sda"))
        second = asyncio.run(server.run_smart_test("sda"))

        assert "started" in first
        assert "Rate limit exceeded" in second
        commands = _commands(executor)
        assert len([c for c in commands if c.endswith("--version")]) == 1
        assert len([c for c in commands if " -t " in c]) == 1

    def test_influx_query_uses_the_validated_text(self, patched_server, monkeypatch):
        from unittest.mock import AsyncMock

        client = AsyncMock()
        client.query = AsyncMock(return_value="✅ Query successful\n\n[]")
        monkeypatch.setattr(server, "_make_influxdb_client", lambda: client)
        monkeypatch.setattr(
            server.security,
            "validate_influxdb_query",
            lambda query: "SELECT validated",
        )

        asyncio.run(server.query_influxdb_disk("SELECT original"))

        assert client.query.await_args.args[0] == "SELECT validated"

    def test_prometheus_query_uses_the_validated_text(
        self, patched_server, monkeypatch
    ):
        from unittest.mock import AsyncMock

        patched_server["config"]["prometheus"]["enabled"] = True
        client = AsyncMock()
        client.query = AsyncMock(return_value="✅ Query successful\n\n[]")
        monkeypatch.setattr(server, "_make_prometheus_client", lambda: client)
        monkeypatch.setattr(
            server.security,
            "validate_prometheus_query",
            lambda query: "up == 1",
        )

        asyncio.run(server.query_prometheus_disk("up"))

        assert client.query.await_args.args[0] == "up == 1"

    def test_blocked_query_is_audited(self, patched_server, monkeypatch, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        patched_server["config"]["audit"] = {
            "enabled": True,
            "path": str(log_path),
        }
        monkeypatch.setattr(
            server.security,
            "validate_influxdb_query",
            lambda query: None,
        )

        result = asyncio.run(server.query_influxdb_disk("SELECT * FROM cpu -- note"))

        assert "Invalid query" in result
        record = json.loads(log_path.read_text().splitlines()[-1])
        assert record["event"] == "query_blocked"
        assert record["kind"] == "influxdb"

    def test_disk_devices_filter_lsblk_rows(self):
        devices = server._disk_devices(
            [
                {"name": "loop0", "type": "loop"},
                {"name": "sr0", "type": "rom"},
                {"name": "sdaa", "type": "disk"},
                {"name": "zram0", "type": "disk"},
                {"name": "sdb", "type": "part"},
                {"name": "../etc", "type": "disk"},
            ]
        )

        assert [device["name"] for device in devices] == ["sdaa"]

    def test_full_report_never_calls_smartctl_for_non_disks(
        self, patched_server, monkeypatch
    ):
        from unittest.mock import AsyncMock

        from server_management_lib.security import SecurityValidator

        monkeypatch.setattr(server, "security", SecurityValidator({}))
        patched_server["config"]["influxdb"]["enabled"] = False
        executor = AsyncMock()
        lsblk = json.dumps(
            {
                "blockdevices": [
                    {"name": "loop0", "type": "loop"},
                    {"name": "sr0", "type": "rom"},
                    {"name": "sdaa", "type": "disk", "model": "wide", "size": "16T"},
                    {"name": "zram0", "type": "disk"},
                ]
            }
        )
        executor.execute_safe_command.side_effect = [lsblk, "{}"]
        monkeypatch.setattr(server, "executor", executor)

        result = asyncio.run(server.get_full_disk_report())

        assert "/dev/sdaa" in result
        assert "loop0" not in result
        assert "zram0" not in result
        smart_commands = [
            c
            for c in _commands(executor)
            if "/usr/sbin/smartctl" in c and " --version" not in c
        ]
        assert smart_commands == ["/usr/sbin/smartctl -j -a /dev/sdaa"]


class TestEveryToolHasStructuredData:
    """P2-13: every disk-health tool publishes machine-readable data."""

    @pytest.mark.parametrize(
        ("tool_name", "arguments", "expected_keys"),
        [
            ("get_smart_attributes", {"device": "sda"}, {"attributes", "source"}),
            ("get_nvme_health", {"device": "nvme0n1"}, {"raw", "source"}),
            (
                "run_smart_test",
                {"device": "sda", "test_type": "short"},
                {"device", "test_type", "started"},
            ),
            ("get_zfs_status", {}, {"pool_status", "pool_list"}),
            ("get_raid_status", {}, {"mdstat", "mdadm_detail"}),
            ("get_snapraid_status", {}, {"status", "fields"}),
            ("get_mount_status", {}, {"mounts", "mergerfs", "usage"}),
            ("get_io_stats", {}, {"iostat"}),
        ],
    )
    def test_host_tools_publish_data(
        self, patched_server, monkeypatch, tool_name, arguments, expected_keys
    ):
        patched_server["config"]["influxdb"]["enabled"] = False
        monkeypatch.setattr(server, "_metric_clients", {})
        tool = server.mcp._tool_manager.get_tool(tool_name)

        response = asyncio.run(tool.fn(**arguments))

        assert isinstance(response, ToolResponse)
        assert response.data
        assert expected_keys <= set(response.data)

    def test_query_prometheus_disk_publishes_result(self, patched_server, monkeypatch):
        from unittest.mock import AsyncMock

        patched_server["config"]["prometheus"]["enabled"] = True
        client = AsyncMock()
        client.query = AsyncMock(
            return_value='✅ Query successful\n\n{"resultType": "vector"}'
        )
        monkeypatch.setattr(server, "_metric_clients", {})
        monkeypatch.setattr(server, "_make_prometheus_client", lambda: client)
        tool = server.mcp._tool_manager.get_tool("query_prometheus_disk")

        response = asyncio.run(tool.fn(query="up"))

        assert response.ok is True
        assert response.data["result"] == {"resultType": "vector"}

    def test_query_influxdb_disk_publishes_rows(self, patched_server, monkeypatch):
        from unittest.mock import AsyncMock

        client = AsyncMock()
        client.query = AsyncMock(
            return_value='✅ Query successful\n\n[{"device": "sda"}]'
        )
        monkeypatch.setattr(server, "_metric_clients", {})
        monkeypatch.setattr(server, "_make_influxdb_client", lambda: client)
        tool = server.mcp._tool_manager.get_tool("query_influxdb_disk")

        response = asyncio.run(tool.fn(query="SELECT * FROM smart_device"))

        assert response.ok is True
        assert response.data["row_count"] == 1
        assert response.data["rows"] == [{"device": "sda"}]

    def test_full_report_queries_valid_sample_and_failed_polls(
        self, patched_server, monkeypatch
    ):
        from datetime import UTC, datetime
        from unittest.mock import AsyncMock

        sample = {
            "device": "sda",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "serial_no": "ZVTFE2SL",
            "time": datetime.now(UTC).isoformat(),
        }
        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(f"✅ Query successful\n\n{json.dumps([sample])}")
        )
        monkeypatch.setattr(server, "_metric_clients", {})
        monkeypatch.setattr(server, "_make_influxdb_client", lambda: client)
        tool = server.mcp._tool_manager.get_tool("get_full_disk_report")

        response = asyncio.run(tool.fn())

        assert response.ok is True
        assert client.query.await_count == 2
        queries = [call.args[0] for call in client.query.await_args_list]
        assert any("exit_status != 0" in query for query in queries)
        assert any(
            "ROW_NUMBER() OVER (PARTITION BY serial_no" in query for query in queries
        )
        assert response.data["devices"] == ["sda"]
        assert response.data["serials"] == ["ZVTFE2SL"]

    def test_full_report_payload_keeps_devices_usable(
        self, patched_server, monkeypatch
    ):
        """`devices` must stay an argument `get_disk_health` accepts.

        The role label is reported separately, and a tag that still holds a
        kernel name is not presented as a label, so a client can never feed a
        value back and land on a different physical disk.
        """
        from datetime import UTC, datetime
        from unittest.mock import AsyncMock

        from server_management_lib import SecurityValidator

        rows = [
            {
                "device": "Data1",
                "exit_status": 0,
                "health_ok": True,
                "model": "ST18000NT001",
                "serial_no": "ZVTFF270",
                "time": datetime.now(UTC).isoformat(),
            },
            {
                "device": "sdd",
                "exit_status": 0,
                "health_ok": True,
                "model": "ST18000NT001",
                "serial_no": "ZVTFF3JB",
                "time": datetime.now(UTC).isoformat(),
            },
        ]
        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(f"✅ Query successful\n\n{json.dumps(rows)}")
        )
        monkeypatch.setattr(server, "_metric_clients", {})
        monkeypatch.setattr(server, "_make_influxdb_client", lambda: client)
        monkeypatch.setattr(
            server,
            "_get_live_devices",
            AsyncMock(
                return_value={
                    "sda": {"name": "sda", "model": "m", "serial": "ZVTFF270"},
                    "sdc": {"name": "sdc", "model": "m", "serial": "ZVTFF3JB"},
                }
            ),
        )
        tool = server.mcp._tool_manager.get_tool("get_full_disk_report")

        response = asyncio.run(tool.fn())

        assert response.data["devices"] == ["sda", "sdc"]
        assert response.data["labels"] == ["Data1", ""]
        assert response.data["serials"] == ["ZVTFF270", "ZVTFF3JB"]

        validator = SecurityValidator({})
        for device in response.data["devices"]:
            assert validator.validate_device_name(device) is True

    def test_unresolved_disk_is_not_returned_as_a_device(
        self, patched_server, monkeypatch
    ):
        """Without a live match, `devices` must not carry a role label."""
        from datetime import UTC, datetime
        from unittest.mock import AsyncMock

        rows = [
            {
                "device": "Data1",
                "exit_status": 0,
                "health_ok": True,
                "model": "ST18000NT001",
                "serial_no": "ZVTFF270",
                "time": datetime.now(UTC).isoformat(),
            }
        ]
        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(f"✅ Query successful\n\n{json.dumps(rows)}")
        )
        monkeypatch.setattr(server, "_metric_clients", {})
        monkeypatch.setattr(server, "_make_influxdb_client", lambda: client)
        monkeypatch.setattr(server, "_get_live_devices", AsyncMock(return_value=None))
        tool = server.mcp._tool_manager.get_tool("get_full_disk_report")

        response = asyncio.run(tool.fn())

        assert response.data["devices"] == [""]
        assert response.data["labels"] == ["Data1"]


class TestProxyErrorPages:
    """A proxy/gateway HTML page is surfaced as a failed disk-health tool."""

    def test_query_influxdb_disk_html_page_is_not_ok(self, patched_server, monkeypatch):
        from unittest.mock import AsyncMock

        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(
                "❌ Received an HTML page from "
                "https://influxdb.catafal.co:443/api/v3/query_sql (HTTP 502), "
                "not a InfluxDB response.\n"
                "This is usually a reverse proxy / gateway error, not a query "
                "error."
            )
        )
        monkeypatch.setattr(server, "_metric_clients", {})
        monkeypatch.setattr(server, "_make_influxdb_client", lambda: client)
        tool = server.mcp._tool_manager.get_tool("query_influxdb_disk")

        response = asyncio.run(tool.fn(query="SELECT * FROM smart_device"))

        assert response.ok is False
        assert "Received an HTML page" in response.text
        assert "reverse proxy" in response.text
        # The resolved default database is published, not null.
        assert response.data["database"] == "telegraf"
