"""
Tests for RSM tool command construction.

No SSH connection is made: the SSH manager is replaced with an AsyncMock and
the exact command strings are asserted. This catches argument-order bugs such
as ``docker stats --no-stream -- <service> --format=...``.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from remote_server_mcp import server
from server_management_lib import (
    ConfigNotFoundError,
    LocalExecutor,
    RemoteDirEntry,
    SecurityValidator,
)


@pytest.fixture(autouse=True)
def restore_server_state():
    """Keep apply_config() from leaking into other tests."""
    original_config = dict(server.config)
    original_security = server.security
    original_executor = server.executor
    yield
    server.config.clear()
    server.config.update(original_config)
    server.security = original_security
    server.executor = original_executor


@pytest.fixture
def custom_security():
    return SecurityValidator({"security": {"services_path": "/opt/services"}})


@pytest.fixture
def patched(monkeypatch, custom_security):
    """Patch the module-level security/SSH objects used by the tools."""
    executor = AsyncMock()
    executor.check_service_exists.return_value = True
    executor.execute_safe_command.return_value = "ok"
    executor.read_remote_file.return_value = "file contents"
    executor.list_remote_dir.return_value = [
        RemoteDirEntry(
            name="config.yml",
            longname="-rw-r--r-- 1 app app 42 Jan  1 00:00 config.yml",
            size=42,
        )
    ]

    monkeypatch.setattr(server, "security", custom_security)
    monkeypatch.setattr(server, "executor", executor)
    return executor


def _commands(executor) -> list[str]:
    return [call.args[0] for call in executor.execute_safe_command.await_args_list]


class TestServicePathConsistency:
    def test_list_services_uses_configured_base_path(self, patched):
        asyncio.run(server.list_services())

        assert "/opt/services/" in _commands(patched)[0]
        assert "/srv/" not in _commands(patched)[0]

    def test_list_service_files_uses_configured_base_path(self, patched):
        asyncio.run(server.list_service_files("app"))

        call = patched.list_remote_dir.await_args
        assert call.args[0] == "/opt/services/app"
        assert call.kwargs["allowed_base"] == "/opt/services/app"

    def test_get_service_file_uses_configured_base_path(self, patched):
        result = asyncio.run(server.get_service_file("app", "config.yml"))

        call = patched.read_remote_file.await_args
        assert call.args[0] == "/opt/services/app/config.yml"
        assert call.kwargs["allowed_base"] == "/opt/services/app"
        assert result == "file contents"

    def test_server_health_uses_configured_base_path(self, patched):
        asyncio.run(server.get_server_health())

        commands = "\n".join(_commands(patched))
        assert "df -h /opt/services" in commands


class TestDockerCommandConstruction:
    def test_docker_stats_flags_come_before_terminator(self, patched):
        asyncio.run(server.get_service_status("app"))

        stats = [c for c in _commands(patched) if c.startswith("docker stats")]
        assert stats, "expected a docker stats command"
        command = stats[0]
        assert "--format" in command
        assert command.index("--format") < command.index(" -- app")
        assert command.endswith("-- app")

    def test_service_is_quoted(self, patched):
        asyncio.run(server.restart_service("app"))

        assert "docker restart -- app" in _commands(patched)[0]

    def test_negative_log_lines_are_clamped(self, patched):
        asyncio.run(server.get_service_logs("app", lines=-5))

        assert "--tail 1 " in _commands(patched)[0]

    def test_log_search_filters_without_a_shell_pipe(self, patched):
        patched.execute_safe_command.return_value = "line one\nits fine here\n"

        result = asyncio.run(server.search_service_logs("app", "it's fine"))

        assert result == "its fine here"
        assert "grep" not in _commands(patched)[0]


class TestToolAnnotations:
    def test_read_only_tools_are_annotated(self):
        tools = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}
        for name in ("list_services", "get_service_logs", "get_service_file"):
            assert tools[name].annotations.read_only_hint is True
            assert tools[name].annotations.destructive_hint is False

    def test_destructive_tools_are_annotated(self):
        tools = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}
        assert tools["restart_service"].annotations.read_only_hint is False
        assert tools["restart_service"].annotations.destructive_hint is True
        assert tools["stop_service"].annotations.destructive_hint is True
        assert tools["start_service"].annotations.destructive_hint is False


class TestConfigBootstrap:
    def test_apply_config_rebuilds_dependencies(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "ssh:\n"
            "  host: example.com\n"
            "security:\n"
            "  services_path: /data/srv\n"
            "influxdb:\n"
            "  enabled: false\n"
        )
        monkeypatch.setenv("REMOTE_SERVER_MCP_CONFIG", str(config_file))

        resolved = server.apply_config()

        assert resolved == config_file
        assert server.config["ssh"]["host"] == "example.com"
        assert server.executor.services_base_path == "/data/srv"

    def test_apply_config_missing_required_file_raises(self, tmp_path):
        with pytest.raises(ConfigNotFoundError):
            server.apply_config(tmp_path / "missing.yaml")

    def test_apply_config_can_select_local_executor(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("executor: local\nsecurity:\n  services_path: /srv\n")

        server.apply_config(config_file)

        assert isinstance(server.executor, LocalExecutor)
