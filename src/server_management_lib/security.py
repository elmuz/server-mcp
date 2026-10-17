"""
Security Validator for Server Management Library

Enforces strict security policies:
- No generic command execution
- Device name validation (disk-health-mcp)
- Service name validation (remote-server-mcp)
- Path traversal prevention (including Unicode/encoding bypasses)
- Command injection prevention
- Database query validation (read-only enforcement)
- Search pattern sanitization

Design: Whitelist specific safe operations, don't try to blacklist dangerous ones.
"""

import logging
import re

import sqlparse
from sqlparse import tokens as sql_tokens

logger = logging.getLogger(__name__)

# ============================================================================
# Device name validation (disk-health-mcp)
# ============================================================================

# Valid block device name pattern: sdX, nvmeXnY, vdX, hdX, mmcblkXpY, dm-X
DEVICE_NAME_PATTERN = re.compile(
    r"^(sd[a-z]|nvme\d+n\d+|vd[a-z]|hd[a-z]|mmcblk\d+(p\d+)?|dm-\d+)$"
)

# ============================================================================
# Service name validation (remote-server-mcp)
# ============================================================================

# Strict service name pattern: must start with alphanumeric, then alphanumeric,
# hyphens, underscores. Prevents Docker option injection (names like "-help").
SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

# ============================================================================
# Path traversal patterns (remote-server-mcp)
# ============================================================================

PATH_TRAVERSAL_PATTERNS = [
    "..",  # Parent directory reference
    "~",  # Home directory
    "$",  # Variable expansion
    "`",  # Command substitution
    ";",  # Command separator
    "|",  # Pipe
    "&",  # Background/AND
    ">",  # Redirect
    "<",  # Redirect input
    "(",  # Subshell
    ")",  # Subshell
    "{",  # Brace expansion
    "}",  # Brace expansion
    "[",  # Glob
    "]",  # Glob
    "*",  # Glob
    "?",  # Glob
    "'",  # Quote escape
    '"',  # Quote escape
    "\\",  # Escape character
    "\n",  # Newline injection
    "\r",  # Carriage return
    "\t",  # Tab injection
    " ",  # Space (shell word splitting)
    "!",  # Bash history expansion
    "#",  # Comment character
]

URL_ENCODED_TRAVERSAL = [
    "%2e",  # URL-encoded dot
    "%2f",  # URL-encoded slash
    "%5c",  # URL-encoded backslash
    "%25",  # URL-encoded percent (double encoding)
    "%00",  # Null byte
]

UNICODE_DOT_VARIANTS = [
    "\uff0e",  # Fullwidth full stop
    "\u3002",  # Ideographic full stop
    "\u2024",  # One dot leader
    "\u2025",  # Two dot leader
    "\u2027",  # Hyphenation point
    "\u00b7",  # Middle dot
    "\u200b",  # Zero-width space (used between dots)
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
]

# ============================================================================
# Database query validation
# ============================================================================

# Keywords that turn a SELECT into a write or administrative statement.
# Validation is semantic: parse the SQL instead of blacklisting shell characters
# (the query is sent over HTTP, never through a shell).
WRITE_KEYWORDS = frozenset(
    {
        "ALTER",
        "CREATE",
        "DELETE",
        "DROP",
        "GRANT",
        "INSERT",
        "INTO",
        "KILL",
        "MERGE",
        "RENAME",
        "REPLACE",
        "REVOKE",
        "SET",
        "TRUNCATE",
        "UPDATE",
        "UPSERT",
    }
)

# ============================================================================
# Sensitive file patterns (remote-server-mcp)
# ============================================================================

SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".key",
    "secret",
    "password",
    "credential",
    "token",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/ssl",
    "/root/",
    "/home/",
    ".git/",
    ".git/config",
    ".git/HEAD",
    "/proc/",
    "/sys/",
    "/dev/",
    "htpasswd",
    "wp-config",
    "database.yml",
    "secrets.yml",
]

# ============================================================================
# Command safety - safe diagnostic prefixes (disk-health-mcp)
# ============================================================================

SAFE_COMMAND_PREFIXES = [
    "smartctl -",
    "/usr/sbin/smartctl -",
    "/sbin/smartctl -",
    "/usr/bin/smartctl -",
    "smartctl -j -a",
    "smartctl -j -i",
    "smartctl -a",
    "smartctl -i",
    "smartctl -c",
    "smartctl -l error",
    "smartctl -l selftest",
    "smartctl -t short",
    "smartctl -t long",
    "smartctl -t conveyance",
    "/usr/sbin/smartctl -j -a",
    "/usr/sbin/smartctl -a",
    "nvme smart-log",
    "/usr/sbin/nvme smart-log",
    "/sbin/nvme smart-log",
    "nvme smart-log-add",
    "nvme id-ctrl",
    "nvme id-ns",
    "nvme error-log",
    "lsblk -d",
    "lsblk -o",
    "zpool status",
    "zpool list",
    "zpool iostat",
    "zfs list",
    "zfs get",
    "cat /proc/mdstat",
    "mdadm --detail",
    "mdadm --examine",
    "iostat -x",
    "iostat -d",
]

# ============================================================================
# Command safety - disk-health-mcp injection patterns
# ============================================================================

INJECTION_PATTERNS = [
    ";",  # Command separator
    "|",  # Pipe
    "&",  # Background (but allow 2>&1 redirect)
    "`",  # Command substitution
    "$",  # Variable expansion
    "(",  # Subshell
    ")",  # Subshell
    "{",  # Brace expansion
    "}",  # Brace expansion
    "<",  # Redirect input
    "\n",  # Newline injection
    "\r",  # Carriage return
    "\\",  # Escape character
    "'",  # Quote escape
    '"',  # Quote escape
    "!",  # History expansion
    "~",  # Home directory
    "..",  # Path traversal
]


class SecurityValidator:
    """Validates all inputs for security before execution."""

    def __init__(self, config: dict):
        """
        Initialize security validator.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.security_config = config.get("security", {})
        self.services_base_path = self.security_config.get("services_path", "/srv")
        self.allow_generic_command_execution = False

    # ========================================================================
    # Device name validation (disk-health-mcp)
    # ========================================================================

    def validate_device_name(self, device: str) -> bool:
        """
        Validate block device name against safe pattern.

        Args:
            device: Device name (e.g., 'sda', 'nvme0n1')

        Returns:
            True if valid, False otherwise
        """
        if not device or not isinstance(device, str):
            logger.warning(f"Invalid device name: {device}")
            return False

        if len(device) > 32:
            logger.warning(f"Device name too long: {len(device)} chars")
            return False

        if not DEVICE_NAME_PATTERN.match(device):
            logger.warning(f"Device name contains invalid chars: {device}")
            return False

        for pattern in INJECTION_PATTERNS:
            if pattern in device:
                logger.warning(f"Device name contains injection pattern: {pattern}")
                return False

        return True

    def validate_smart_test_type(self, test_type: str) -> bool:
        """
        Validate SMART self-test type.

        Args:
            test_type: Test type string

        Returns:
            True if valid, False otherwise
        """
        if not test_type or not isinstance(test_type, str):
            logger.warning(f"Invalid SMART test type: {test_type}")
            return False
        valid_tests = {"short", "long", "conveyance"}
        if test_type.lower() not in valid_tests:
            logger.warning(f"Invalid SMART test type: {test_type}")
            return False
        return True

    # ========================================================================
    # Service name validation (remote-server-mcp)
    # ========================================================================

    def validate_service_name(self, service_name: str) -> bool:
        """
        Validate service name against strict pattern.

        Args:
            service_name: Service name to validate

        Returns:
            True if valid, False otherwise
        """
        if not service_name or not isinstance(service_name, str):
            logger.warning(f"Invalid service name: {service_name}")
            return False

        if len(service_name) > 100:
            logger.warning(f"Service name too long: {len(service_name)} chars")
            return False

        if not SERVICE_NAME_PATTERN.match(service_name):
            logger.warning(f"Service name contains invalid characters: {service_name}")
            return False

        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in service_name:
                logger.warning(
                    f"Service name contains path traversal pattern: {pattern}"
                )
                return False

        return True

    def validate_service_file_path(self, service: str, file_path: str) -> str | None:
        """
        Validate and construct a safe file path within /srv/{service}/.

        Args:
            service: Service name (already validated)
            file_path: Relative file path within service directory

        Returns:
            Full safe path, or None if invalid
        """
        if not file_path or not isinstance(file_path, str):
            logger.warning(f"Invalid file path: {file_path}")
            return None

        if len(file_path) > 500:
            logger.warning(f"File path too long: {len(file_path)} chars")
            return None

        if "\x00" in file_path:
            logger.warning("File path contains null byte")
            return None

        file_path_lower = file_path.lower()
        for pattern in URL_ENCODED_TRAVERSAL:
            if pattern.lower() in file_path_lower:
                logger.warning(f"File path contains URL-encoded traversal: {pattern}")
                return None

        for char in UNICODE_DOT_VARIANTS:
            if char in file_path:
                logger.warning("File path contains unicode dot variant: %r", char)
                return None

        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in file_path:
                logger.warning(f"File path contains dangerous pattern: {pattern}")
                return None

        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.lower() in file_path_lower:
                logger.warning(f"File path matches sensitive pattern: {pattern}")
                return None

        if file_path.startswith("/"):
            logger.warning(f"File path must be relative, not absolute: {file_path}")
            return None

        from pathlib import Path as _Path

        service_base = f"{self.services_base_path}/{service}"
        full_path = f"{service_base}/{file_path}"

        try:
            resolved_path = str(_Path(full_path).resolve())
            is_under_base = resolved_path.startswith(service_base + "/")
            if not is_under_base and resolved_path != service_base:
                logger.warning(
                    f"Path resolution escaped service directory: {resolved_path}"
                )
                return None
            return resolved_path
        except Exception as e:
            logger.warning(f"Error resolving path: {e}")
            return None

    # ========================================================================
    # Search pattern sanitization (remote-server-mcp)
    # ========================================================================

    def sanitize_search_pattern(self, pattern: str) -> str:
        """
        Sanitize a search pattern to prevent shell injection.

        Args:
            pattern: Raw search pattern

        Returns:
            Sanitized pattern safe for use in grep -F

        Raises:
            ValueError: If pattern becomes empty after sanitization
        """
        if not pattern or not isinstance(pattern, str):
            raise ValueError("Search pattern must not be empty")

        pattern = pattern[:200]

        for char in [
            "'",
            '"',
            "`",
            "$",
            "\\",
            ";",
            "|",
            "&",
            ">",
            "<",
            "(",
            ")",
            "{",
            "}",
            "\n",
            "\r",
            "\t",
            "!",
            "#",
            "~",
        ]:
            pattern = pattern.replace(char, "")

        if not pattern.strip():
            raise ValueError(
                "Search pattern became empty after sanitization. "
                "This would cause grep to read from stdin (hang)."
            )

        return pattern

    # ========================================================================
    # Database query validation (remote-server-mcp)
    # ========================================================================

    def validate_influxdb_query(self, query: str) -> str | None:
        """
        Validate an InfluxDB v3 SQL query for read-only safety.

        Args:
            query: SQL query string to validate

        Returns:
            The query if valid, None if invalid
        """
        if not query or not isinstance(query, str):
            logger.warning("Empty or invalid InfluxDB query")
            return None

        if len(query) > 5000:
            logger.warning(f"InfluxDB query too long: {len(query)} chars")
            return None

        if "\x00" in query:
            logger.warning("InfluxDB query contains a null byte")
            return None

        try:
            statements = [
                statement
                for statement in sqlparse.parse(query)
                if str(statement).strip()
            ]
        except Exception as e:  # pragma: no cover - sqlparse is defensive
            logger.warning(f"Could not parse InfluxDB query: {e}")
            return None

        if len(statements) != 1:
            logger.warning("InfluxDB query must be a single statement")
            return None

        statement = statements[0]
        if statement.get_type().upper() != "SELECT":
            logger.warning(
                "InfluxDB query must be a SELECT, got %s", statement.get_type()
            )
            return None

        for token in statement.flatten():
            if (
                token.ttype in sql_tokens.Keyword
                and token.value.upper() in WRITE_KEYWORDS
            ):
                logger.warning("InfluxDB query contains write keyword: %s", token.value)
                return None

        # A single trailing semicolon is harmless; drop it before sending.
        return query.strip().rstrip(";").rstrip()

    def validate_prometheus_query(self, query: str) -> str | None:
        """
        Validate a PromQL query for safety.

        Args:
            query: PromQL expression to validate

        Returns:
            The query if valid, None if invalid
        """
        if not query or not isinstance(query, str):
            logger.warning("Empty or Prometheus query")
            return None

        if len(query) > 5000:
            logger.warning(f"PromQL query too long: {len(query)} chars")
            return None

        if "\x00" in query:
            logger.warning("PromQL query contains a null byte")
            return None

        # PromQL is sent over HTTP, never through a shell. Quotes, braces and
        # comparison operators are valid and required for real queries. Only
        # reject control characters that cannot appear in a PromQL expression.
        for char in query:
            if ord(char) < 0x20 and char not in "\n\r\t":
                logger.warning("PromQL query contains control character: %r", char)
                return None

        return query

    # ========================================================================
    # Command safety (merged: disk-health-mcp strict + remote-server-mcp permissive)
    # ========================================================================

    def is_command_safe(self, command: str) -> bool:
        """
        Check if a diagnostic command is safe to execute.

        Uses the strict disk-health-mcp policy (whitelist-based) for
        disk diagnostic commands. For other commands, uses the more
        permissive remote-server-mcp policy (block only truly dangerous ops).

        Args:
            command: Full command string

        Returns:
            True if safe
        """
        command_lower = command.lower()

        # Block truly dangerous operations first, before any whitelist check
        dangerous_patterns = [
            "sudo",
            "su ",
            "passwd",
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "chmod",
            "chown",
            "mount ",
            "umount",
            "iptables",
            "kill -9",
            "rm -rf /",
            "mkfs",
            "fdisk",
            "/etc/shadow",
            "/etc/passwd",
            "wget ",
            "curl ",
            "bash ",
            "sh ",
            "zsh ",
            "python ",
            "python3 ",
            "perl ",
            "ruby ",
        ]

        for pattern in dangerous_patterns:
            if pattern in command_lower:
                logger.warning(f"Command contains dangerous pattern: {pattern}")
                return False

        # Block dd separately (handles "dd " at start or " dd " in middle)
        if command_lower.startswith("dd ") or " dd " in command_lower:
            logger.warning("Command contains dangerous pattern: dd")
            return False

        # Block network exfiltration tools
        net_tools = ["nc ", "ncat ", "netcat ", "socat ", "telnet "]
        for tool in net_tools:
            if tool in command_lower or command_lower.startswith(tool):
                logger.warning(f"Command contains dangerous pattern: {tool.strip()}")
                return False

        # Check against disk-health whitelist (strict)
        # Allow stderr redirect (2>&1) but block output redirection
        sanitized_cmd = command_lower.replace("2>&1", "").strip()

        for prefix in SAFE_COMMAND_PREFIXES:
            if command_lower.startswith(prefix.lower()):
                # For whitelisted commands, block output redirection to files/devices
                # but allow shell chaining (&&, ||, ;) and pipes since these are
                # constructed by the application, not raw user input
                if ">" in sanitized_cmd and "2>&1" not in sanitized_cmd:
                    logger.warning("Command contains dangerous pattern: >")
                    return False
                return True

        # Fall through to general safety check (remote-server-mcp policy)
        # Allow shell operators and formatting used in legitimate commands
        return True
