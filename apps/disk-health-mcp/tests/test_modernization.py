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
