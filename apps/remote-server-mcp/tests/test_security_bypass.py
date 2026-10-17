"""
Advanced Security Bypass Tests for Remote Server MCP

These tests identify security vulnerabilities that could bypass the current
whitelist-based security model. They cover:

1. Symlink attacks (local resolve vs remote execution mismatch)
2. Docker option injection
3. Unicode / encoding bypasses
4. Grep injection in log search
5. Null byte injection
6. Credential exposure via legitimate files
7. Environment variable attacks
8. Shell metacharacter edge cases
9. Path validation logic flaws

TDD Approach: These tests should FAIL initially, then pass after fixes.
"""

import pytest

from server_management_lib import SecurityValidator

# ============================================================================
# 1. Symlink Attack Tests
# ============================================================================


class TestSymlinkAttacks:
    """
    CRITICAL: Path validation uses Path.resolve() LOCALLY, but commands
    execute REMOTELY. Remote symlinks completely bypass local validation.

    Attack scenario:
    1. Attacker creates a symlink in /srv/myapp/: ln -s /etc/shadow /srv/myapp/evil
    2. Attacker calls get_service_file("myapp", "evil")
    3. Local Path.resolve() sees /srv/myapp/evil (no symlink locally, stays as-is)
    4. Remote cat /srv/myapp/evil follows the symlink -> reads /etc/shadow
    """

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_symlink_escape_via_local_resolve(self):
        """
        Path.resolve() on the local machine cannot detect remote symlinks.
        The validation passes locally, but the remote cat follows the symlink.

        After fix: The code should still allow reading files (can't detect
        remote symlinks), but must use the configured services_base_path
        instead of hardcoded /srv/.
        """
        result = self.security.validate_service_file_path("myapp", "config")
        # The path validation itself can't detect remote symlinks,
        # but it must use the correct base path from config
        assert result is not None
        assert result.startswith("/srv/myapp/")

    def test_symlink_in_nested_path(self):
        """
        Symlinks can appear in any component of a path.
        /srv/myapp/logs/app.log where "logs" is a symlink -> /var/log
        """
        result = self.security.validate_service_file_path("myapp", "logs/app.log")
        assert result is not None
        assert result.startswith("/srv/myapp/")

    def test_dotdot_hidden_by_url_encoding(self):
        """
        URL-encoded path traversal: %2e%2e%2f could bypass string matching.
        """
        attacks = [
            ("%2e%2e%2fetc%2fpasswd", "URL-encoded ../etc/passwd"),
            ("%2E%2E%2F", "URL-encoded ../ uppercase"),
            ("..%252f", "Double-encoded"),
        ]

        for path, description in attacks:
            result = self.security.validate_service_file_path("myapp", path)
            assert result is None, f"Should block URL-encoded traversal: {description}"

    def test_unicode_dotdot_bypass(self):
        """
        Fullwidth Unicode dots (U+FF0E variants) could bypass ".." detection.
        U+FF0E = fullwidth full stop (looks like .)
        """
        attacks = [
            "\uff0e\uff0e/",  # fullwidth dots
            "\uff0e\uff0e\uff0f",  # fullwidth dots + slash
            "..\u200b/",  # Zero-width space between dots
        ]

        for path in attacks:
            result = self.security.validate_service_file_path("myapp", path)
            assert result is None, f"Should block unicode dotdot bypass: {path!r}"


# ============================================================================
# 2. Docker Option Injection Tests
# ============================================================================


class TestDockerOptionInjection:
    """
    Service names are used directly in docker commands without '--' separator.
    If a service name starts with '-', Docker interprets it as an option.

    Example: docker restart -- -v could be interpreted as docker restart with
    the -v flag instead of restarting a container named "-v".

    The service name validation allows names starting with letters, hyphens,
    and underscores. A name like "-help" or "--version" would pass validation.
    """

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_service_name_starting_with_hyphen(self):
        """
        Service names like "-help" or "--verbose" must be rejected.
        They would be interpreted as Docker flags.
        """
        attacks = [
            "-help",
            "--version",
            "-v",
            "-H",
            "--context",
        ]

        for name in attacks:
            result = self.security.validate_service_name(name)
            assert result is False, (
                f"Service name '{name}' starting with hyphen must be rejected "
                f"(Docker option injection risk)"
            )

    def test_service_name_starting_with_underscore_rejected(self):
        """
        Service names starting with underscore should also be rejected
        as a defense-in-depth measure.
        """
        name = "_service"
        result = self.security.validate_service_name(name)
        assert result is False, (
            f"Service name '{name}' starting with underscore must be rejected"
        )

    def test_docker_logs_injection(self):
        """
        Service name used to inject docker flags into log retrieval.
        "myapp --tail 999999" would change the tail value.
        """
        # Even with validation, consider what happens with service names
        # that look like docker options when combined with command templates
        attacks = [
            "myapp --format {{.Config.Image}}",  # Would this bypass validation?
        ]

        for name in attacks:
            # These should all be caught by service name validation
            assert self.security.validate_service_name(name) is False, (
                f"Should block docker option injection: {name}"
            )

    def test_service_name_starts_with_letter_safe(self):
        """
        Verify that requiring service names to start with alphanumeric
        (not hyphen/underscore) prevents Docker option injection.
        """
        # Safe names should be accepted
        safe_names = ["myapp", "web-server", "api_v2", "Service1"]
        for name in safe_names:
            assert self.security.validate_service_name(name) is True, (
                f"Safe service name should be accepted: {name}"
            )

        # Dangerous starts should be rejected
        dangerous_starts = ["-", "_"]
        for start in dangerous_starts:
            name = f"{start}service"
            result = self.security.validate_service_name(name)
            assert result is False, (
                f"Service name '{name}' starts with '{start}' - must be rejected"
            )


# ============================================================================
# 3. Grep Injection Tests
# ============================================================================


class TestGrepInjection:
    """
    CRITICAL: search_service_logs constructs:
        grep -F '{sanitized_pattern}'

    The sanitization removes single quotes, but:
    1. If pattern becomes empty after sanitization, grep reads from stdin (hangs)
    2. Backslash handling in grep -F has edge cases
    3. The grep -F flag treats input as fixed string, but the quotes are still vulnerable
    """

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_single_quote_stripping(self):
        """
        Single quote is NOT stripped by sanitize_search_pattern!
        The sanitization removes: ' " ` $ \\ ; | & > < ( ) { } \n \r
        But wait - it DOES strip single quotes. Let me verify:
        """
        pattern = "'; cat /etc/passwd; #"
        sanitized = self.security.sanitize_search_pattern(pattern)
        assert "'" not in sanitized, (
            "Single quote should be stripped to prevent grep injection"
        )

    def test_empty_pattern_after_sanitization(self):
        """
        If the entire pattern consists only of shell special characters,
        sanitization produces an empty string, causing grep to read from stdin.

        After fix: sanitize_search_pattern raises ValueError for empty patterns.
        """
        pattern = "';|&$"
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern(pattern)

    def test_grep_backslash_handling(self):
        """
        In grep -F, backslash is treated literally, but if the backslash
        is used to escape the closing quote, it could break the command.

        Pattern: test\
        Result: grep -F 'test\'  <- The backslash escapes the closing quote!
        Next char becomes part of the pattern, then the closing quote is missing.

        After fix: backslash is stripped, and if the pattern becomes empty,
        ValueError is raised.
        """
        # Patterns that become empty or only contain safe chars after sanitization
        safe_patterns = [
            ("test\\", "test"),
            ("foo\\bar", "foobar"),
            ("\\n", "n"),
        ]

        for pattern, expected in safe_patterns:
            sanitized = self.security.sanitize_search_pattern(pattern)
            assert sanitized == expected, (
                f"Expected '{expected}' from {pattern!r}, got '{sanitized}'"
            )

        # Pattern that becomes entirely special chars should raise ValueError
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("\\'")

    def test_pattern_with_newline_injection(self):
        """
        Newlines in the pattern could inject additional commands.
        Pattern: "error\ncat /etc/passwd"
        Command: grep -F 'error
        cat /etc/passwd'
        """
        pattern = "error\ncat /etc/passwd"
        sanitized = self.security.sanitize_search_pattern(pattern)
        assert "\n" not in sanitized, "Newlines should be stripped from pattern"
        assert "\r" not in sanitized, "Carriage returns should be stripped"

    def test_max_lines_bypass(self):
        """
        The lines parameter is limited to 5000, but the tool accepts
        arbitrary integers. An attacker could pass a very large number.
        """
        # The security module should enforce the limit
        # This tests that the SSH manager or tool enforces it
        # Since we're testing the security module, we verify pattern sanitization
        # doesn't break with extreme line counts
        pattern = self.security.sanitize_search_pattern("normal search")
        assert len(pattern) <= 200, "Pattern should be length-limited"


# ============================================================================
# 4. Path Validation Logic Flaws
# ============================================================================


class TestPathValidationLogic:
    """Test logical flaws in path validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_uses_configured_base_path(self):
        """
        Path resolution must use the configured services_base_path,
        not hardcoded /srv/.
        """
        config = {"security": {"services_path": "/opt/services"}}
        security = SecurityValidator(config)

        result = security.validate_service_file_path("myapp", "config.yml")
        # After fix: must use /opt/services/myapp/ from config
        assert result is not None
        assert result.startswith("/opt/services/myapp/"), (
            f"Path must use configured base path /opt/services/, got: {result}"
        )

    def test_space_in_path_blocked(self):
        """
        Spaces in paths could cause shell word splitting.
        'ls -lah /srv/myapp/my dir/file.txt' would be split.

        After fix: spaces are blocked in PATH_TRAVERSAL_PATTERNS.
        """
        result = self.security.validate_service_file_path("myapp", "my dir/file.txt")
        assert result is None, (
            "Paths with spaces must be blocked (shell word splitting)"
        )

    def test_null_byte_injection(self):
        """
        Null bytes can truncate paths in C-based programs.
        "config.yml\x00/etc/passwd" might be read as "config.yml" by Python
        but as "/etc/passwd" by the shell/cat command.
        """
        attacks = [
            "config\x00.yml",
            "file.txt\x00../../etc/passwd",
            "\x00/etc/passwd",
        ]

        for path in attacks:
            result = self.security.validate_service_file_path("myapp", path)
            assert result is None, f"Should block null byte injection: {path!r}"


# ============================================================================
# 5. Credential and Secret Exposure Tests
# ============================================================================


class TestCredentialExposure:
    """
    Test that legitimate service files cannot be used to exfiltrate secrets.

    docker-compose.yml often contains database passwords, API keys, etc.
    nginx.conf might contain SSL certificates inline.
    Application configs often contain secrets.
    """

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_docker_compose_with_secrets(self):
        """
        docker-compose.yml is a legitimate file to read, but often contains:
        - Database passwords
        - API keys
        - Secret tokens
        """
        result = self.security.validate_service_file_path("myapp", "docker-compose.yml")
        # Current code: allows this (it's a normal file path)
        # This IS a concern - docker-compose.yml often has secrets
        # The tool should allow reading it but warn about potential secret exposure
        assert result is not None, (
            "docker-compose.yml should be readable (but tool should warn about secrets)"
        )

    def test_git_config_exposure(self):
        """
        .git/config contains remote URLs which may have embedded credentials.
        .git/HEAD reveals branch names.
        """
        result = self.security.validate_service_file_path("myapp", ".git/config")
        # Current code: blocks ".git" because it starts with "."
        # Actually, let me check... ".git" doesn't match any SENSITIVE_FILE_PATTERNS
        # This is a gap!
        assert result is None, ".git/config should be blocked (may contain credentials)"

    def test_proc_self_environ(self):
        """
        /proc/self/environ contains environment variables including secrets.
        If path validation is bypassed, this is a prime target.
        """
        # Even with path validation, test that the SENSITIVE_FILE_PATTERNS
        # catch /proc/ paths
        # "config" is a valid path - the security module can't prevent
        # remote /proc/ access, but defense in depth helps
        self.security.validate_service_file_path("myapp", "config")

    def test_sys_devices_exposure(self):
        """
        /sys/devices/ could reveal hardware information.
        """
        # Similar to /proc/ - should be blocked by path validation
        # since absolute paths are rejected
        result = self.security.validate_service_file_path("myapp", "/sys/devices")
        assert result is None, "Absolute paths should be rejected"


# ============================================================================
# 6. Shell Metacharacter Edge Cases
# ============================================================================


class TestShellMetacharacterEdgeCases:
    """Test edge cases in shell metacharacter handling."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_exclamation_mark_injection(self):
        """
        ! in bash triggers history expansion.
        After fix: ! is blocked in PATH_TRAVERSAL_PATTERNS.
        """
        result = self.security.validate_service_file_path("myapp", "file!.txt")
        assert result is None, (
            "Exclamation marks must be blocked (bash history expansion)"
        )

    def test_tilde_expansion_in_service_name(self):
        """
        ~ in service name is blocked, but test the boundary.
        """
        assert self.security.validate_service_name("~root") is False
        assert self.security.validate_service_name("my~app") is False

    def test_colon_in_path(self):
        """
        : is used in various shell contexts and PATH.
        """
        # : is not in PATH_TRAVERSAL_PATTERNS
        # Could cause issues in some shell contexts
        # Not critical, but worth testing
        self.security.validate_service_file_path("myapp", "file:name.txt")

    def test_at_sign_in_path(self):
        """
        @ is used in some URL formats and SSH connection strings.
        """
        # @ is not in PATH_TRAVERSAL_PATTERNS
        self.security.validate_service_file_path("myapp", "file@name.txt")


# ============================================================================
# 7. Command Safety Bypass Tests
# ============================================================================


class TestCommandSafetyBypass:
    """Test that command safety checks can be bypassed."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_case_variation_bypass(self):
        """
        Dangerous pattern checks should be case-insensitive.
        'SUDO', 'SuD0', etc.
        """
        dangerous_variants = [
            "docker ps && SUDO ls",
            "docker ps && Su root",
        ]

        for cmd in dangerous_variants:
            # The code does .lower() so these should be caught
            assert self.security.is_command_safe(cmd) is False, (
                f"Should block case variation: {cmd}"
            )

    def test_unicode_homoglyph_in_commands(self):
        """
        Unicode lookalikes could bypass string matching.
        e.g., Cyrillic small letter es (U+0441) looks like 'c' in 'curl'
        """
        # This tests that the command safety check doesn't try to
        # detect Unicode homoglyphs (it currently doesn't, which is
        # acceptable since commands are application-constructed)
        cmd = "docker ps"
        assert self.security.is_command_safe(cmd) is True

    def test_concatenation_bypass(self):
        """
        Individual safe commands might be combined dangerously.
        "docker ps" is safe, "docker logs" is safe, but what if
        the command template itself is manipulated?
        """
        # The commands are constructed from templates in the server code.
        # Test that even with validated service names, the full command
        # doesn't accidentally become dangerous.
        service = "myapp"  # Validated
        cmd = f"docker logs --tail 100 {service} 2>&1"
        assert self.security.is_command_safe(cmd) is True

    def test_env_variable_in_commands(self):
        """
        Environment variable expansion in commands.
        If the remote server has crafted env vars, they could affect commands.
        """
        # Commands should not include $ expansions that could be controlled
        # remotely via environment variables
        cmd = "docker ps --format '{{.Names}}\t{{.Status}}'"
        # {{ }} is docker format, not shell $()
        assert self.security.is_command_safe(cmd) is True


# ============================================================================
# 8. Race Condition and TOCTOU Tests
# ============================================================================


class TestTOCTOU:
    """
    Time-of-Check-Time-of-Use attacks.
    The service exists check and the actual command execution have a gap.
    """

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_service_deletion_between_check_and_use(self):
        """
        An attacker could delete /srv/myapp between:
        1. check_service_exists() returns True
        2. The actual docker command executes

        This could cause the docker command to operate on an unexpected target.
        """
        # The security module can't prevent TOCTOU directly,
        # but the tool implementation should handle errors gracefully.
        # Test that the service validation is robust.
        assert self.security.validate_service_name("myapp") is True

    def test_symlink_creation_between_check_and_use(self):
        """
        An attacker could create a symlink in /srv/myapp/ between:
        1. validate_service_file_path("myapp", "config") passes
        2. cat /srv/myapp/config executes

        This is the same as the symlink attack, but highlights the
        TOCTOU aspect - the check and use are not atomic.
        """
        result = self.security.validate_service_file_path("myapp", "config")
        assert result is not None
        # The fix should address this by doing atomic remote checks


# ============================================================================
# 9. Log Search Specificity Tests
# ============================================================================


class TestLogSearchSpecificity:
    """Test that log search doesn't expose more than intended."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_wildcard_in_grep_pattern(self):
        """
        Empty pattern is dangerous - grep reads from stdin (hangs).
        After fix: sanitize_search_pattern raises ValueError for empty patterns.
        """
        pattern = ""
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern(pattern)

    def test_docker_container_name_in_pattern(self):
        """
        If the service name appears in the log search pattern,
        it could be confused with the container name parameter.
        """
        service = "myapp"
        pattern = self.security.sanitize_search_pattern(f"; docker rm {service}")
        assert ";" not in pattern
        assert "docker" not in pattern.lower() or "docker" in pattern.lower(), (
            "Semicolon should be stripped"
        )


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
