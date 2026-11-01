"""Tests for runtime configuration validation and token-file handling."""

import copy
from pathlib import Path

import pytest

from server_management_lib.config import DEFAULT_CONFIG
from server_management_lib.runtime import collect_runtime_check
from server_management_lib.transport import (
    TOKEN_FILE_MAX_BYTES,
    load_http_token_file,
    resolve_http_token,
)


def _config() -> dict:
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["executor"] = "local"
    return config


def _token(tmp_path: Path, content: str = "secret\n", mode: int = 0o600) -> Path:
    path = tmp_path / "token"
    path.write_text(content)
    path.chmod(mode)
    return path


class TestTokenFile:
    def test_reads_and_trims_a_token(self, tmp_path):
        path = _token(tmp_path, "  secret-token\n")

        assert load_http_token_file(path) == "secret-token"

    def test_missing_file_is_an_error(self, tmp_path):
        with pytest.raises(ValueError, match="Cannot read"):
            load_http_token_file(tmp_path / "missing")

    def test_directory_is_rejected(self, tmp_path):
        path = tmp_path / "token"
        path.mkdir()

        with pytest.raises(ValueError, match="not a regular file"):
            load_http_token_file(path)

    def test_empty_file_is_rejected(self, tmp_path):
        path = _token(tmp_path, " \n")

        with pytest.raises(ValueError, match="empty"):
            load_http_token_file(path)

    def test_group_or_other_permissions_are_rejected(self, tmp_path):
        path = _token(tmp_path, mode=0o644)

        with pytest.raises(ValueError, match="accessible by group/other"):
            load_http_token_file(path)

    def test_oversized_file_is_rejected(self, tmp_path):
        path = _token(tmp_path, "x" * (TOKEN_FILE_MAX_BYTES + 1))

        with pytest.raises(ValueError, match="larger than"):
            load_http_token_file(path)

    def test_control_characters_are_rejected(self, tmp_path):
        path = _token(tmp_path, "sec\nret")

        with pytest.raises(ValueError, match="control character"):
            load_http_token_file(path)

    def test_file_takes_precedence_over_inline_token(self, tmp_path, caplog):
        path = _token(tmp_path, "from-file")

        assert resolve_http_token("from-inline", path) == "from-file"
        assert "using the token file" in caplog.text

    def test_inline_token_is_used_without_a_file(self):
        assert resolve_http_token("inline", None) == "inline"

    def test_missing_token_resolves_to_none(self):
        assert resolve_http_token(None, None) is None
        assert resolve_http_token("", None) is None


class TestRuntimeCheck:
    def test_local_executor_is_allowed_outside_a_container(self):
        result = collect_runtime_check(_config())

        assert result.ok is True

    def test_local_executor_is_rejected_inside_a_container(self):
        result = collect_runtime_check(_config(), container=True)

        assert result.ok is False
        assert any("executor: local" in issue for issue in result.issues)

    def test_ssh_key_and_known_hosts_must_be_readable(self, tmp_path):
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["executor"] = "ssh"
        config["ssh"]["key_path"] = str(tmp_path / "missing-key")
        config["ssh"]["known_hosts"] = str(tmp_path / "missing-known-hosts")

        result = collect_runtime_check(config)

        assert sum("not found" in issue for issue in result.issues) == 2

    def test_disabled_host_verification_is_a_warning(self):
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["executor"] = "ssh"
        config["ssh"]["known_hosts"] = "none"

        result = collect_runtime_check(config)

        assert result.ok is True
        assert any("host key verification is disabled" in w for w in result.warnings)

    def test_public_http_bind_without_a_token_is_rejected(self):
        config = _config()
        config["transport"].update({"type": "streamable-http", "host": "0.0.0.0"})

        result = collect_runtime_check(config)

        assert result.ok is False
        assert any("without an access token" in issue for issue in result.issues)

    def test_public_bind_with_a_token_file_is_accepted(self, tmp_path):
        path = _token(tmp_path)
        config = _config()
        config["transport"].update(
            {
                "type": "streamable-http",
                "host": "0.0.0.0",
                "token_file": str(path),
            }
        )

        result = collect_runtime_check(config)

        assert result.ok is True
        assert result.token_source == "file"

    def test_insecure_token_file_is_reported(self, tmp_path):
        path = _token(tmp_path, mode=0o644)
        config = _config()
        config["transport"].update(
            {
                "type": "streamable-http",
                "host": "0.0.0.0",
                "token_file": str(path),
            }
        )

        result = collect_runtime_check(config)

        assert result.ok is False
        assert any("group/other" in issue for issue in result.issues)

    def test_audit_parent_must_exist_in_a_container(self, tmp_path):
        config = _config()
        config["audit"] = {
            "enabled": True,
            "path": str(tmp_path / "audit" / "audit.jsonl"),
        }

        result = collect_runtime_check(config, container=True)

        assert result.ok is False
        assert any("does not exist" in issue for issue in result.issues)

    def test_audit_parent_is_created_outside_a_container(self, tmp_path):
        config = _config()
        config["audit"] = {
            "enabled": True,
            "path": str(tmp_path / "audit" / "audit.jsonl"),
        }

        result = collect_runtime_check(config)

        assert result.ok is True
        assert any("will be created" in warning for warning in result.warnings)

    def test_unknown_transport_is_rejected(self):
        config = _config()
        config["transport"]["type"] = "bogus"

        result = collect_runtime_check(config)

        assert result.ok is False
        assert any("unknown transport" in issue for issue in result.issues)

    @pytest.mark.parametrize("port", [0, 70000])
    def test_http_port_is_validated(self, port):
        config = _config()
        config["transport"].update(
            {"type": "streamable-http", "host": "127.0.0.1", "port": port}
        )

        result = collect_runtime_check(config)

        assert result.ok is False
        assert any("outside 1..65535" in issue for issue in result.issues)

    def test_transport_path_must_be_absolute(self):
        config = _config()
        config["transport"].update(
            {"type": "streamable-http", "host": "127.0.0.1", "path": "mcp"}
        )

        result = collect_runtime_check(config)

        assert result.ok is False
        assert any("must start with '/'" in issue for issue in result.issues)
