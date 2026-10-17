"""
Tests for server_management_lib.ssh_manager module.

Covers:
- SSHManager initialization
- Connection handling (success, failure, disconnect)
- Safe command execution (various scenarios)
- Service existence checking
- Async context manager
- Edge cases (key auth, password auth)

All SSH operations are mocked - no real connections.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

from server_management_lib.security import SecurityValidator
from server_management_lib.ssh_manager import SSHManager


class TestSSHManagerInit:
    """Test SSHManager initialization."""

    def test_manager_created(self, config, security):
        manager = SSHManager(config, security)
        assert manager.connection is None
        assert manager._connected is False

    def test_manager_with_key_path(self, config_with_key, security):
        """Test SSHManager with key path configuration."""
        manager = SSHManager(config_with_key, security)
        assert manager.config["ssh"]["key_path"] == "~/.ssh/id_rsa"

    def test_manager_with_password(self, config_with_password, security):
        """Test SSHManager with password configuration."""
        manager = SSHManager(config_with_password, security)
        assert manager.config["ssh"]["password"] == "secret"


class TestSSHManagerConnection:
    """Test SSHManager connection handling."""

    def test_connect_failure(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            with patch("server_management_lib.ssh_manager.asyncssh.connect") as mock:
                mock.side_effect = Exception("Connection refused")
                with pytest.raises(Exception, match="Connection refused"):
                    await manager.connect()

        asyncio.run(run())

    def test_disconnect_on_error(self, config, security):
        async def run():
            manager = SSHManager(config, security)

            with patch("server_management_lib.ssh_manager.asyncssh.connect") as mock:
                mock.side_effect = Exception("Connection failed")

                try:
                    await manager.connect()
                except Exception:
                    pass

                assert manager._connected is False

        asyncio.run(run())

    def test_disconnect(self, config, security):
        """Test explicit disconnect."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.close = MagicMock()
            manager.connection = mock_conn

            await manager.disconnect()
            assert manager._connected is False

        asyncio.run(run())


class TestSSHManagerCommandExecution:
    """Test SSHManager safe command execution."""

    def test_execute_safe_command(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="hello", stderr="", exit_status=0
            )
            manager.connection = mock_conn

            result = await manager.execute_safe_command("echo hello")
            assert "hello" in result

        asyncio.run(run())

    def test_unsafe_command_blocked(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = AsyncMock()

            result = await manager.execute_safe_command("rm -rf /")
            assert "Security violation" in result or "❌" in result

        asyncio.run(run())

    def test_command_not_connected(self, config, security):
        """Command execution when not connected should attempt to connect."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = False
            manager.connection = None

            # When connect() raises, it should propagate
            with patch.object(
                manager, "connect", side_effect=Exception("Connection failed")
            ):
                with pytest.raises(Exception, match="Connection failed"):
                    await manager.execute_safe_command("echo test")

        asyncio.run(run())

    def test_command_connection_none(self, config, security):
        """Command execution when connection is None after connect."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = None

            with patch.object(manager, "connect", return_value=None):
                result = await manager.execute_safe_command("echo test")
                assert "Connection failed" in result

        asyncio.run(run())

    def test_command_with_stderr(self, config, security):
        """Test that stderr is included in the output."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="stdout output", stderr="stderr output", exit_status=0
            )
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("echo test")
                assert "stdout output" in result
                assert "stderr output" in result

        asyncio.run(run())

    def test_command_nonzero_exit(self, config, security):
        """Test that non-zero exit codes are reported."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="output", stderr="", exit_status=1
            )
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("command")
                assert "output" in result
                assert "Exit code: 1" in result

        asyncio.run(run())

    def test_command_asyncssh_error(self, config, security):
        """Test that asyncssh errors are handled."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.side_effect = Exception("SSH connection lost")
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("command")
                assert (
                    "Error executing command" in result
                    or "SSH connection lost" in result
                )

        asyncio.run(run())

    def test_command_timeout(self, config, security):
        """Test that timeouts are handled."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.side_effect = TimeoutError()
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("command", timeout=10)
                assert "timed out" in result

        asyncio.run(run())


class TestSSHManagerServiceCheck:
    """Test SSHManager service existence checking."""

    def test_check_service_exists(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            # check_service_exists runs: test -d /srv/{service} && echo 'exists' || echo 'not_exists'
            mock_conn.run.return_value = MagicMock(
                stdout="exists", stderr="", exit_status=0
            )
            manager.connection = mock_conn

            result = await manager.check_service_exists("myapp")
            assert result is True

        asyncio.run(run())

    def test_check_service_exists_not_found(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="not_exists", stderr="", exit_status=0
            )
            manager.connection = mock_conn

            result = await manager.check_service_exists("nonexistent")
            assert result is False

        asyncio.run(run())

    def test_check_service_exists_exception(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = AsyncMock()
            manager.connection.run.side_effect = Exception("Command failed")

            result = await manager.check_service_exists("myapp")
            assert result is False

        asyncio.run(run())


class TestSSHManagerContextManager:
    """Test SSHManager async context manager."""

    def test_context_manager_usage(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="test", stderr="", exit_status=0
            )
            mock_conn.close = MagicMock()
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("echo test")
                assert "test" in result

            await manager.disconnect()
            assert manager._connected is False

        asyncio.run(run())


class TestConnectionSecurity:
    """Host key verification and connection option handling."""

    def test_known_hosts_is_verified_by_default(self, tmp_path, security):
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text("")
        config = {
            "ssh": {"host": "example.com", "known_hosts": str(known_hosts)},
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        kwargs = manager.build_connect_kwargs()
        assert kwargs["known_hosts"] == str(known_hosts)
        assert kwargs["port"] == 22

    def test_missing_known_hosts_raises(self, tmp_path, security):
        from server_management_lib import SSHConfigurationError

        config = {
            "ssh": {"host": "example.com", "known_hosts": str(tmp_path / "nope")},
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        with pytest.raises(SSHConfigurationError, match="known_hosts file not found"):
            manager.build_connect_kwargs()

    def test_known_hosts_skips_unparseable_entries(
        self, tmp_path, security, monkeypatch
    ):
        """A legacy entry must not disable verification for the whole file."""
        key = asyncssh.generate_private_key("ssh-ed25519")
        public_key = key.export_public_key().decode().strip()
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text(
            f"example.com {public_key}\nexample.com ssh-rsa !!!not-base64!!!\n"
        )
        # Simulate the real-world failure: one legacy line makes the
        # whole-file parser raise.
        monkeypatch.setattr(
            "server_management_lib.ssh_manager.asyncssh.read_known_hosts",
            MagicMock(side_effect=ValueError("p must be exactly 1024 bits")),
        )
        config = {
            "ssh": {"host": "example.com", "known_hosts": str(known_hosts)},
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        kwargs = manager.build_connect_kwargs()
        assert isinstance(kwargs["known_hosts"], bytes)
        known_hosts = asyncssh.import_known_hosts(kwargs["known_hosts"].decode())
        matched = known_hosts.match("example.com", "127.0.0.1", 22)[0]
        assert matched, "the valid ed25519 entry must be kept"

    def test_known_hosts_with_no_usable_entries_raises(
        self, tmp_path, security, monkeypatch
    ):
        from server_management_lib import SSHConfigurationError

        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text("# only a comment\n")
        monkeypatch.setattr(
            "server_management_lib.ssh_manager.asyncssh.read_known_hosts",
            MagicMock(side_effect=ValueError("broken")),
        )
        config = {
            "ssh": {"host": "example.com", "known_hosts": str(known_hosts)},
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        with pytest.raises(SSHConfigurationError, match="No usable host keys"):
            manager.build_connect_kwargs()

    def test_known_hosts_is_loaded_once(self, tmp_path, security, monkeypatch):
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text("")
        loader = MagicMock(return_value=str(known_hosts))
        monkeypatch.setattr(
            "server_management_lib.ssh_manager._load_known_hosts", loader
        )
        config = {
            "ssh": {"host": "example.com", "known_hosts": str(known_hosts)},
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        assert manager._known_hosts_option() == str(known_hosts)
        assert manager._known_hosts_option() == str(known_hosts)
        loader.assert_called_once()

    def test_known_hosts_can_be_disabled_explicitly(self, security):
        config = {
            "ssh": {"host": "example.com", "known_hosts": "none"},
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        kwargs = manager.build_connect_kwargs()
        assert kwargs["known_hosts"] is None

    def test_no_username_lets_ssh_config_decide(self, security):
        config = {
            "ssh": {
                "host": "alias-in-ssh-config",
                "username": None,
                "known_hosts": "none",
            },
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        kwargs = manager.build_connect_kwargs()
        assert "username" not in kwargs
        assert kwargs["host"] == "alias-in-ssh-config"

    def test_key_path_is_expanded(self, security):
        config = {
            "ssh": {
                "host": "example.com",
                "key_path": "~/.ssh/id_ed25519",
                "known_hosts": "none",
            },
            "security": {"services_path": "/srv"},
        }
        manager = SSHManager(config, security)

        kwargs = manager.build_connect_kwargs()
        assert not kwargs["client_keys"][0].startswith("~")


class TestServicePathHandling:
    """The configured services_path must be used everywhere."""

    def test_check_service_exists_uses_configured_base_path(self, security):
        async def run():
            config = {
                "ssh": {"host": "example.com", "known_hosts": "none"},
                "security": {"services_path": "/opt/services/"},
            }
            manager = SSHManager(config, SecurityValidator(config))
            execute = AsyncMock(return_value="exists")

            with patch.object(manager, "execute_safe_command", new=execute):
                assert await manager.check_service_exists("myapp") is True

            command = execute.await_args.args[0]
            assert "/opt/services/myapp" in command
            assert "/srv/" not in command

        asyncio.run(run())


class TestConnectionLifecycle:
    """Connection loss should reset state so the next call reconnects."""

    def test_connection_lost_resets_state(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            mock_conn = AsyncMock()
            mock_conn.run.side_effect = asyncssh.ConnectionLost("gone")
            manager.connection = mock_conn

            result = await manager.execute_safe_command("echo test")
            assert "connection lost" in result.lower()
            assert manager._connected is False
            assert manager.connection is None

        asyncio.run(run())

    def test_disconnect_waits_closed(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            mock_conn = MagicMock()
            mock_conn.wait_closed = AsyncMock()
            manager.connection = mock_conn

            await manager.disconnect()
            mock_conn.close.assert_called_once()
            mock_conn.wait_closed.assert_awaited_once()
            assert manager.connection is None

        asyncio.run(run())
