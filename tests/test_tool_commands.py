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
from server_management_lib import ConfigNotFoundError, SecurityValidator


@pytest.fixture(autouse=True)
def restore_server_state():
    """Keep apply_config() from leaking into other tests."""
    original_config = dict(server.config)
    original_security = server.security
    original_ssh = server.ssh_manager
    yield
    server.config.clear()
    server.config.update(original_config)
    server.security = original_security
    server.ssh_manager = original_ssh


@pytest.fixture
def custom_security():
    return SecurityValidator({"security": {"services_path": "/opt/services"}})


@pytest.fixture
def patched(monkeypatch, custom_security):
    """Patch the module-level security/SSH objects used by the tools."""
    ssh = AsyncMock()
    ssh.check_service_exists.return_value = True
    ssh.execute_safe_command.return_value = "ok"

    monkeypatch.setattr(server, "security", custom_security)
    monkeypatch.setattr(server, "ssh_manager", ssh)
    return ssh


def _commands(ssh) -> list[str]:
    return [call.args[0] for call in ssh.execute_safe_command.await_args_list]


class TestServicePathConsistency:
    def test_list_services_uses_configured_base_path(self, patched):
        asyncio.run(server.list_services())

        assert "/opt/services/" in _commands(patched)[0]
        assert "/srv/" not in _commands(patched)[0]

    def test_list_service_files_uses_configured_base_path(self, patched):
        asyncio.run(server.list_service_files("app"))

        assert "/opt/services/app" in _commands(patched)[0]

    def test_get_service_file_uses_configured_base_path(self, patched):
        asyncio.run(server.get_service_file("app", "config.yml"))

        command = _commands(patched)[0]
        assert "cat /opt/services/app/config.yml" in command

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
        assert "--format=" in command
        assert command.index("--format=") < command.index(" -- app")
        assert command.endswith("-- app 2>&1")

    def test_service_is_quoted(self, patched):
        asyncio.run(server.restart_service("app"))

        assert "docker restart -- app" in _commands(patched)[0]

    def test_negative_log_lines_are_clamped(self, patched):
        asyncio.run(server.get_service_logs("app", lines=-5))

        assert "--tail 1 " in _commands(patched)[0]

    def test_log_search_is_quoted(self, patched):
        asyncio.run(server.search_service_logs("app", "it's fine"))

        command = _commands(patched)[0]
        assert "grep -F 'its fine'" in command


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
        assert server.ssh_manager.services_base_path == "/data/srv"

    def test_apply_config_missing_required_file_raises(self, tmp_path):
        with pytest.raises(ConfigNotFoundError):
            server.apply_config(tmp_path / "missing.yaml")
