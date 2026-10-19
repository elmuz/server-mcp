"""Tests for the JSONL audit logger."""

import json

from server_management_lib.audit import REDACTED, AuditLogger


class TestAuditLogger:
    def test_disabled_writes_nothing(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path, enabled=False)
        logger.log("command", command="echo hi")
        assert not path.exists()

    def test_writes_jsonl_records(self, tmp_path):
        path = tmp_path / "nested" / "audit.jsonl"
        logger = AuditLogger(path, enabled=True)

        logger.log("command", command="echo hi", exit_status=0)
        logger.log("file_read", path="/srv/app/config.yml", size=10)

        lines = path.read_text().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["event"] == "command"
        assert first["command"] == "echo hi"
        assert first["exit_status"] == 0
        assert "ts" in first
        assert json.loads(lines[1])["size"] == 10

    def test_sensitive_fields_are_redacted(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path, enabled=True)

        logger.log(
            "query",
            token="secret-token",
            password="hunter2",
            nested={"api_key": "abc", "safe": "visible"},
        )

        record = json.loads(path.read_text())
        assert record["token"] == REDACTED
        assert record["password"] == REDACTED
        assert record["nested"]["api_key"] == REDACTED
        assert record["nested"]["safe"] == "visible"

    def test_unwritable_path_does_not_raise(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        logger = AuditLogger(blocker / "audit.jsonl", enabled=True)

        logger.log("command", command="echo hi")  # must not raise


class TestAuditPermissions:
    """The audit file and its directory must not be world-readable (P1-16)."""

    def test_created_directory_and_file_are_private(self, tmp_path):
        import os
        import stat

        if os.name != "posix":
            import pytest

            pytest.skip("POSIX file modes are not available")

        path = tmp_path / "private" / "audit.jsonl"
        logger = AuditLogger(path, enabled=True)

        logger.log("command", command="echo hi")

        directory_mode = stat.S_IMODE(path.parent.stat().st_mode)
        file_mode = stat.S_IMODE(path.stat().st_mode)
        assert directory_mode == 0o700
        assert file_mode == 0o600

    def test_existing_file_mode_is_tightened(self, tmp_path):
        import os
        import stat

        if os.name != "posix":
            import pytest

            pytest.skip("POSIX file modes are not available")

        path = tmp_path / "audit.jsonl"
        path.write_text("")
        path.chmod(0o644)
        logger = AuditLogger(path, enabled=True)

        logger.log("command", command="echo hi")

        assert stat.S_IMODE(path.stat().st_mode) == 0o600
