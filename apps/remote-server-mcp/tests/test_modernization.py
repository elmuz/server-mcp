"""Tests for the P2 modernization features of remote-server-mcp."""

import asyncio
import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from remote_server_mcp import operations, server
from server_management_lib import (
    RateLimiter,
    RemoteDirEntry,
    SecurityValidator,
    ToolResponse,
)
from server_management_lib.operations import Operation


@pytest.fixture(autouse=True)
def restore_server_state():
    original_config = dict(server.config)
    original_security = server.security
    original_executor = server.executor
    original_catalog = server.catalog
    original_limiter = server.rate_limiter
    # Keep one test's confirmed actions from consuming the global window.
    server.rate_limiter = None
    yield
    server.config.clear()
    server.config.update(original_config)
    server.security = original_security
    server.executor = original_executor
    server.catalog = original_catalog
    server.rate_limiter = original_limiter


@pytest.fixture
def patched(monkeypatch):
    executor = AsyncMock()
    executor.check_service_exists.return_value = True
    executor.execute_safe_command.return_value = "ok"
    executor.read_remote_file.return_value = "A=1\nB=2\n"
    executor.list_remote_dir.return_value = [
        RemoteDirEntry(name="compose.yml", longname="compose.yml", size=10)
    ]
    monkeypatch.setattr(server, "executor", executor)
    monkeypatch.setattr(
        server, "security", SecurityValidator({"security": {"services_path": "/srv"}})
    )
    monkeypatch.setattr(server, "catalog", operations.build_container_catalog("docker"))
    return executor


def _commands(executor) -> list[str]:
    return [call.args[0] for call in executor.execute_safe_command.await_args_list]


def _listing() -> str:
    return "app\tapp\tUp\n"


class TestContainerRuntimeAdapter:
    @pytest.mark.parametrize("runtime", ["docker", "podman", "nerdctl"])
    def test_every_runtime_operation_passes_the_policy(self, runtime):
        security = SecurityValidator({})
        catalog = operations.build_container_catalog(runtime)
        for name, operation in vars(catalog).items():
            if not isinstance(operation, Operation):
                continue
            rendered = operation.render(service="app", lines=10, directory="/srv/app")
            assert security.is_command_safe(rendered) is True, (runtime, name, rendered)
        for name in ("logs",):
            rendered = getattr(catalog, name)(since="1h").render(
                service="app", lines=10, since="1h", directory="/srv/app"
            )
            assert security.is_command_safe(rendered) is True, rendered

    def test_apply_config_selects_the_runtime(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "executor: local\ncontainer_runtime: podman\nsecurity:\n  services_path: /srv\n"
        )
        monkeypatch.setattr(server, "executor", AsyncMock())

        server.apply_config(config_file)

        assert server.catalog.runtime == "podman"
        assert server.security.container_runtime == "podman"

    def test_invalid_runtime_falls_back_to_docker(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("container_runtime: containerd\n")
        monkeypatch.setattr(server, "executor", AsyncMock())

        server.apply_config(config_file)

        assert server.catalog.runtime == "docker"


class TestComposeOperations:
    def test_compose_ps_uses_the_service_directory(self, patched):
        result = asyncio.run(server.compose_ps("app"))

        assert _commands(patched) == [
            "docker compose --project-directory /srv/app ps --format "
            "'{{.Name}} {{.Status}}'"
        ]
        assert "Compose Status: app" in result

    def test_compose_ps_rejects_unknown_directory(self, patched):
        patched.check_service_exists.return_value = False

        result = asyncio.run(server.compose_ps("missing"))

        assert "does not exist" in result
        assert _commands(patched) == []

    @pytest.mark.parametrize(
        ("tool", "subcommand"),
        [
            ("compose_pull", "pull"),
            ("compose_up", "up -d --remove-orphans"),
            ("compose_down", "down --remove-orphans"),
        ],
    )
    def test_mutating_compose_requires_confirmation(self, patched, tool, subcommand):
        result = asyncio.run(getattr(server, tool)("app"))

        assert "Confirmation required" in result
        assert f"compose --project-directory /srv/app {subcommand}" in result
        assert _commands(patched) == []

    @pytest.mark.parametrize(
        ("tool", "subcommand"),
        [
            ("compose_pull", "pull"),
            ("compose_up", "up -d --remove-orphans"),
            ("compose_down", "down --remove-orphans"),
        ],
    )
    def test_confirmed_compose_actions_execute(self, patched, tool, subcommand):
        result = asyncio.run(getattr(server, tool)("app", confirm=True))

        assert _commands(patched) == [
            f"docker compose --project-directory /srv/app {subcommand}"
        ]
        assert "✅" in result

    def test_compose_action_reports_failure(self, patched):
        patched.execute_safe_command.return_value = "boom\n\n⚠️ Exit code: 1"

        result = asyncio.run(server.compose_up("app", confirm=True))

        assert "⚠️" in result
        assert "boom" in result

    def test_compose_operations_pass_the_policy(self):
        security = SecurityValidator({})
        for operation in (
            operations.COMPOSE_PS,
            operations.COMPOSE_PULL,
            operations.COMPOSE_UP,
            operations.COMPOSE_DOWN,
        ):
            command = operation.render(directory="/srv/app")
            assert security.is_command_safe(command) is True, command


class TestDestructiveConfirmation:
    def test_restart_preview_does_not_execute(self, patched):
        result = asyncio.run(server.restart_service("app"))

        assert "Confirmation required" in result
        assert "docker restart -- app" in result
        assert not [c for c in _commands(patched) if c.startswith("docker restart")]

    def test_stop_preview_does_not_execute(self, patched):
        result = asyncio.run(server.stop_service("app"))

        assert "Confirmation required" in result
        assert not [c for c in _commands(patched) if c.startswith("docker stop")]

    def test_rate_limiter_blocks_repeated_actions(self, patched, monkeypatch):
        monkeypatch.setattr(server, "rate_limiter", RateLimiter(1, 60))

        first = asyncio.run(server.restart_service("app", confirm=True))
        second = asyncio.run(server.restart_service("app", confirm=True))

        assert "restarted" in first
        assert "Rate limit exceeded" in second
        # The second call never renders a restart command.
        assert (
            len([c for c in _commands(patched) if c.startswith("docker restart")]) == 1
        )

    def test_rate_limit_can_be_disabled(self, patched, monkeypatch):
        monkeypatch.setattr(server, "rate_limiter", None)

        asyncio.run(server.restart_service("app", confirm=True))
        asyncio.run(server.restart_service("app", confirm=True))

        assert (
            len([c for c in _commands(patched) if c.startswith("docker restart")]) == 2
        )


class TestStructuredOutput:
    def test_every_tool_publishes_an_output_schema(self):
        for tool in server.mcp._tool_manager.list_tools():
            assert tool.output_schema is not None, tool.name
            assert tool.output_schema["title"] == "ToolResponse"

    def test_list_containers_returns_structured_data(self, patched):
        patched.execute_safe_command.side_effect = lambda command: (
            _listing() if command.startswith("docker ps") else "ok"
        )
        tool = server.mcp._tool_manager.get_tool("list_containers")

        response = asyncio.run(tool.fn())

        assert isinstance(response, ToolResponse)
        assert response.tool == "list_containers"
        assert response.ok is True
        assert response.data["count"] == 1
        assert response.data["containers"][0]["name"] == "app"

    def test_error_response_is_not_ok(self, patched):
        patched.check_service_exists.return_value = False
        tool = server.mcp._tool_manager.get_tool("get_service_status")

        response = asyncio.run(tool.fn(service="missing"))

        assert response.ok is False
        assert response.data == {}


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

        assert payload["app"] == "remote-server-mcp"
        assert payload["defaults"]["influxdb"]["token"] == "***"

    def test_tool_catalog_lists_tools(self):
        payload = _resource_json("server-mcp://tools/catalog")

        names = {tool["name"] for tool in payload["tools"]}
        assert "list_containers" in names
        assert "compose_ps" in names

    def test_tool_template_returns_details(self):
        payload = _resource_json("server-mcp://tools/get_service_status")

        assert payload["name"] == "get_service_status"
        assert payload["read_only"] is True

    def test_unknown_tool_template_fails(self):
        with pytest.raises(Exception, match="Error creating resource from template"):
            asyncio.run(server.mcp.read_resource("server-mcp://tools/nope"))


class TestTransportSelection:
    def test_streamable_http_main_path(self, monkeypatch):
        captured = {}

        async def fake_http(*args, **kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(server, "run_streamable_http", fake_http)
        monkeypatch.setattr(server, "apply_config", lambda path: Path("/tmp/c.yaml"))
        monkeypatch.setattr(server, "open_metric_tunnels", AsyncMock(return_value=[]))
        monkeypatch.setattr(server, "close_metric_tunnels", AsyncMock())
        stub_executor = AsyncMock()
        stub_executor.execute_safe_command.return_value = "ok"
        monkeypatch.setattr(server, "executor", stub_executor)

        asyncio.run(
            server.main(
                transport="streamable-http",
                http_host="127.0.0.1",
                http_port=9999,
            )
        )

        assert captured["host"] == "127.0.0.1"
        assert captured["port"] == 9999

    def test_public_bind_without_token_exits(self, monkeypatch):
        monkeypatch.setattr(server, "apply_config", lambda path: Path("/tmp/c.yaml"))
        monkeypatch.setattr(server, "open_metric_tunnels", AsyncMock(return_value=[]))
        monkeypatch.setattr(server, "close_metric_tunnels", AsyncMock())
        stub_executor = AsyncMock()
        stub_executor.execute_safe_command.return_value = "ok"
        monkeypatch.setattr(server, "executor", stub_executor)
        monkeypatch.setattr(server, "config", {"transport": {}})

        with pytest.raises(SystemExit) as excinfo:
            asyncio.run(
                server.main(
                    transport="streamable-http",
                    http_host="0.0.0.0",
                )
            )

        assert excinfo.value.code == 2
