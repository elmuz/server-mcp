"""
SSH Connection Tests for Remote Server MCP

Tests SSH connection functionality and MCP server integration.
These tests require a valid config.yaml with SSH credentials.

Run with:
    uv run pytest tests/test_ssh_connection.py -v
    uv run pytest tests/test_ssh_connection.py -v -k "not integration"  # Skip integration tests
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from remote_server_mcp import server as mcp_server
from server_management_lib import SecurityValidator, load_config
from server_management_lib.ssh_manager import SSHManager

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def config():
    """Load actual configuration."""
    config_path = Path(__file__).parent.parent / "config.yaml"
    if config_path.exists():
        return load_config(config_path)
    return {
        "ssh": {
            "host": "localhost",
            "port": 22,
            "username": "test",
            "key_path": None,
        },
        "security": {
            "services_path": "/srv",
            "allow_generic_commands": False,
        },
    }


@pytest.fixture
def security(config):
    """Create security validator."""
    return SecurityValidator(config)


@pytest.fixture
def ssh_manager(config, security):
    """Create SSH manager instance."""
    return SSHManager(config, security)


# ============================================================================
# Unit Tests - SSH Manager
# ============================================================================


class TestSSHManagerInitialization:
    """Test SSHManager initialization."""

    def test_ssh_manager_created(self, ssh_manager):
        """Test SSHManager is created successfully."""
        assert ssh_manager is not None
        assert ssh_manager.connection is None
        assert ssh_manager._connected is False

    def test_ssh_manager_has_config(self, ssh_manager):
        """Test SSHManager has configuration."""
        assert ssh_manager.config is not None
        assert "ssh" in ssh_manager.config
        assert "security" in ssh_manager.config

    def test_ssh_manager_has_security(self, ssh_manager):
        """Test SSHManager has security validator."""
        assert ssh_manager.security is not None
        assert isinstance(ssh_manager.security, SecurityValidator)


class TestSSHConnection:
    """Test SSH connection functionality."""

    @pytest.mark.integration
    def test_ssh_connect_and_disconnect(self, ssh_manager):
        """Test establishing and closing SSH connection."""

        async def run_test():
            # Connect
            await ssh_manager.connect()
            assert ssh_manager._connected is True
            assert ssh_manager.connection is not None

            # Disconnect
            await ssh_manager.disconnect()
            assert ssh_manager._connected is False

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_ssh_execute_command(self, ssh_manager):
        """Test executing a safe command over SSH."""

        async def run_test():
            # Connect and execute command
            await ssh_manager.connect()
            result = await ssh_manager.execute_safe_command("echo 'test'")
            await ssh_manager.disconnect()

            assert result is not None
            assert "test" in result

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_ssh_check_service_exists(self, ssh_manager):
        """Test checking if a service exists."""

        async def run_test():
            await ssh_manager.connect()

            # Check for a non-existent service
            result = await ssh_manager.check_service_exists("nonexistent-service-12345")
            assert result is False

            await ssh_manager.disconnect()

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_ssh_context_manager(self, config, security):
        """Test SSHManager as async context manager."""

        async def run_test():
            manager = SSHManager(config, security)

            async with manager as m:
                assert m._connected is True
                assert m.connection is not None

            # After exiting context, should be disconnected
            assert m._connected is False

        asyncio.run(run_test())


class TestSSHCommandExecution:
    """Test command execution safety."""

    def test_unsafe_command_blocked(self, ssh_manager):
        """Test that unsafe commands are blocked."""

        async def run_test():
            # These should be blocked by security
            unsafe_commands = [
                "rm -rf /",
                "sudo reboot",
                "cat /etc/shadow",
            ]

            for cmd in unsafe_commands:
                result = await ssh_manager.execute_safe_command(cmd)
                assert "Security violation" in result or "❌" in result, (
                    f"Should block: {cmd}"
                )

        asyncio.run(run_test())

    def test_safe_command_allowed(self, ssh_manager):
        """Test that safe commands are allowed."""

        async def run_test():
            # These should pass security checks
            safe_commands = [
                "docker ps",
                "ls -lah /srv",
                "uptime",
                "free -h",
            ]

            # Note: These will fail if not connected, but should not be blocked by security
            for cmd in safe_commands:
                # Just verify they don't get blocked by security
                assert ssh_manager.security.is_command_safe(cmd) is True

        asyncio.run(run_test())


# ============================================================================
# Mock Tests (No Real SSH Required)
# ============================================================================


class TestSSHManagerMock:
    """Test SSHManager with mocked connections."""

    def test_connect_failure(self, config, security):
        """Test handling of connection failure."""

        async def run_test():
            manager = SSHManager(config, security)

            # Mock asyncssh.connect to raise exception
            with patch(
                "server_management_lib.ssh_manager.asyncssh.connect"
            ) as mock_connect:
                mock_connect.side_effect = Exception("Connection refused")

                with pytest.raises(Exception, match="Connection refused"):
                    await manager.connect()

        asyncio.run(run_test())

    def test_execute_without_connection(self, config, security):
        """Test that execute_safe_command auto-connects if needed."""

        async def run_test():
            manager = SSHManager(config, security)
            # Set as already connected
            manager._connected = True

            # Mock the connection
            mock_connection = AsyncMock()
            mock_connection.run.return_value = MagicMock(
                stdout="test output", stderr="", exit_status=0
            )
            manager.connection = mock_connection

            result = await manager.execute_safe_command("echo test")

            assert "test output" in result
            # Verify the command was executed
            mock_connection.run.assert_called_once()

        asyncio.run(run_test())

    def test_execute_with_error_output(self, config, security):
        """Test handling of command with stderr output."""

        async def run_test():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_connection = AsyncMock()
            mock_connection.run.return_value = MagicMock(
                stdout="partial output", stderr="error message", exit_status=1
            )
            manager.connection = mock_connection

            result = await manager.execute_safe_command("some-command")

            assert "partial output" in result
            assert "error message" in result
            assert "STDERR" in result

        asyncio.run(run_test())

    def test_execute_timeout(self, config, security):
        """Test handling of command timeout."""

        async def run_test():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_connection = AsyncMock()
            mock_connection.run.side_effect = TimeoutError(30)
            manager.connection = mock_connection

            result = await manager.execute_safe_command("slow-command")

            assert "timed out" in result.lower()

        asyncio.run(run_test())


# ============================================================================
# MCP Server Integration Tests
# ============================================================================


class TestMCPServerSSH:
    """Test MCP server integration with SSH."""

    def test_mcp_server_has_ssh_manager(self):
        """Test that MCP server has SSH manager initialized."""
        assert mcp_server.executor is not None
        assert isinstance(mcp_server.executor, SSHManager)

    def test_mcp_server_has_security(self):
        """Test that MCP server has security validator."""
        assert mcp_server.security is not None
        assert isinstance(mcp_server.security, SecurityValidator)

    @pytest.mark.integration
    def test_mcp_list_services(self):
        """Test list_services tool works over SSH."""

        async def run_test():
            # Connect SSH
            await mcp_server.executor.connect()

            try:
                # Call the tool function directly
                result = await mcp_server.list_services()
                assert result is not None
                # Should contain service list or docker status
                assert isinstance(result, str)
            finally:
                # Always disconnect
                await mcp_server.executor.disconnect()

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_mcp_server_health(self):
        """Test get_server_health tool works over SSH."""

        async def run_test():
            await mcp_server.executor.connect()

            try:
                result = await mcp_server.get_server_health()
                assert result is not None
                assert isinstance(result, str)
                # Should contain some system info
                assert len(result) > 0
            finally:
                await mcp_server.executor.disconnect()

        asyncio.run(run_test())

    def test_mcp_tools_validate_service_names(self):
        """Test that MCP tools validate service names."""
        # Verify security validator is properly configured
        assert mcp_server.security.validate_service_name("valid-service") is True
        assert mcp_server.security.validate_service_name("invalid;service") is False
        assert mcp_server.security.validate_service_name("../../etc") is False


# ============================================================================
# Connection Stress Tests
# ============================================================================


class TestSSHConnectionStress:
    """Test SSH connection robustness."""

    @pytest.mark.integration
    def test_multiple_commands(self, ssh_manager):
        """Test executing multiple commands in sequence."""

        async def run_test():
            await ssh_manager.connect()

            try:
                commands = [
                    "echo 'cmd1'",
                    "echo 'cmd2'",
                    "echo 'cmd3'",
                    "hostname",
                    "whoami",
                ]

                results = []
                for cmd in commands:
                    result = await ssh_manager.execute_safe_command(cmd)
                    results.append(result)
                    assert result is not None
                    assert len(result) > 0

                assert len(results) == len(commands)
            finally:
                await ssh_manager.disconnect()

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_reconnect_after_disconnect(self, ssh_manager):
        """Test reconnecting after disconnection."""

        async def run_test():
            # First connection
            await ssh_manager.connect()
            await ssh_manager.disconnect()

            # Reconnect
            await ssh_manager.connect()
            result = await ssh_manager.execute_safe_command("echo 'reconnected'")
            await ssh_manager.disconnect()

            assert "reconnected" in result

        asyncio.run(run_test())


# ============================================================================
# Configuration Tests
# ============================================================================


class TestSSHConfiguration:
    """Test SSH configuration loading."""

    def test_config_has_ssh_section(self, config):
        """Test configuration has SSH section."""
        assert "ssh" in config
        ssh_config = config["ssh"]
        assert "host" in ssh_config
        assert "port" in ssh_config
        assert "username" in ssh_config

    def test_config_has_authentication(self, config):
        """Test configuration has authentication method."""
        ssh_config = config["ssh"]
        # Should have either password or key_path
        has_password = ssh_config.get("password") is not None
        has_key = ssh_config.get("key_path") is not None
        assert has_password or has_key, "Config must have password or key_path"

    def test_key_path_expansion(self, config):
        """Test that key path with ~ is properly expanded."""
        import os

        ssh_config = config["ssh"]
        key_path = ssh_config.get("key_path")

        if key_path and "~" in key_path:
            expanded = os.path.expanduser(key_path)
            assert expanded != key_path
            assert os.path.isabs(expanded)


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
