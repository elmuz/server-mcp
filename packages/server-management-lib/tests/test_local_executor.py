"""Tests for the local executor (no shell, same confinement as SFTP)."""

import asyncio

import pytest

from server_management_lib import (
    LocalExecutor,
    RemotePathError,
    SecurityValidator,
    SSHManager,
    create_executor,
)


def _executor(tmp_path, **overrides):
    config = {
        "executor": "local",
        "security": {"services_path": str(tmp_path / "services")},
        **overrides,
    }
    return LocalExecutor(config, SecurityValidator(config))


class TestFactory:
    def test_default_is_ssh(self, security):
        assert isinstance(create_executor({}, security), SSHManager)

    def test_local_executor_selected(self, security):
        executor = create_executor({"executor": "local"}, security)
        assert isinstance(executor, LocalExecutor)

    def test_unknown_executor_raises(self, security):
        with pytest.raises(ValueError, match="Unknown executor"):
            create_executor({"executor": "kubernetes"}, security)


class TestLocalCommands:
    def test_echo(self, tmp_path):
        result = asyncio.run(_executor(tmp_path).execute_safe_command("echo hello"))
        assert result.strip() == "hello"

    def test_blocked_command(self, tmp_path):
        result = asyncio.run(_executor(tmp_path).execute_safe_command("rm -rf /"))
        assert "Security violation" in result

    def test_shell_operators_rejected(self, tmp_path):
        result = asyncio.run(
            _executor(tmp_path).execute_safe_command("echo hi && echo bye")
        )
        assert "Shell operators" in result

    def test_missing_command(self, tmp_path):
        result = asyncio.run(
            _executor(tmp_path).execute_safe_command(
                "definitely-not-a-real-command-xyz"
            )
        )
        assert "Command not found" in result

    def test_timeout(self, tmp_path):
        result = asyncio.run(
            _executor(tmp_path).execute_safe_command("sleep 5", timeout=0.05)
        )
        assert "timed out" in result

    def test_nonzero_exit_is_reported(self, tmp_path):
        result = asyncio.run(_executor(tmp_path).execute_safe_command("false"))
        assert "Exit code: 1" in result


class TestLocalServices:
    def test_check_service_exists(self, tmp_path):
        executor = _executor(tmp_path)
        (tmp_path / "services" / "app").mkdir(parents=True)

        assert asyncio.run(executor.check_service_exists("app")) is True
        assert asyncio.run(executor.check_service_exists("missing")) is False


class TestLocalFiles:
    def test_read_file(self, tmp_path):
        service = tmp_path / "services" / "app"
        service.mkdir(parents=True)
        (service / "config.yml").write_text("hello")

        result = asyncio.run(
            _executor(tmp_path).read_remote_file(
                str(service / "config.yml"), allowed_base=str(service)
            )
        )
        assert result == "hello"

    def test_read_file_truncated(self, tmp_path):
        service = tmp_path / "services" / "app"
        service.mkdir(parents=True)
        (service / "log.txt").write_text("abcdefghij")

        result = asyncio.run(
            _executor(tmp_path).read_remote_file(
                str(service / "log.txt"),
                allowed_base=str(service),
                max_bytes=5,
            )
        )
        assert result.startswith("abcde")
        assert "truncated to 5 bytes" in result

    def test_read_file_escape_blocked(self, tmp_path):
        service = tmp_path / "services" / "app"
        service.mkdir(parents=True)
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")

        with pytest.raises(RemotePathError, match="escapes the allowed"):
            asyncio.run(
                _executor(tmp_path).read_remote_file(
                    str(outside), allowed_base=str(service)
                )
            )

    def test_list_dir_sorted(self, tmp_path):
        service = tmp_path / "services" / "app"
        service.mkdir(parents=True)
        (service / "b.txt").write_text("b")
        (service / "a.txt").write_text("a")

        entries = asyncio.run(
            _executor(tmp_path).list_remote_dir(str(service), allowed_base=str(service))
        )
        assert [entry.name for entry in entries] == ["a.txt", "b.txt"]
        assert entries[0].size == 1

    def test_list_dir_escape_blocked(self, tmp_path):
        service = tmp_path / "services" / "app"
        service.mkdir(parents=True)

        with pytest.raises(RemotePathError):
            asyncio.run(
                _executor(tmp_path).list_remote_dir(
                    str(tmp_path), allowed_base=str(service)
                )
            )

    def test_read_missing_file(self, tmp_path):
        from server_management_lib import RemoteFileError

        service = tmp_path / "services" / "app"
        service.mkdir(parents=True)

        with pytest.raises(RemoteFileError):
            asyncio.run(
                _executor(tmp_path).read_remote_file(
                    str(service / "missing"), allowed_base=str(service)
                )
            )
