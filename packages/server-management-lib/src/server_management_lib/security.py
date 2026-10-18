"""
Security Validator for Server Management Library

Enforces strict security policies:
- No generic command execution
- Device name validation (disk-health-mcp)
- Service name validation (remote-server-mcp)
- Path traversal prevention (including Unicode/encoding bypasses)
- Command injection prevention
- Database query validation (read-only enforcement)
- Log search pattern and time-filter validation

Design: Whitelist specific safe operations, don't try to blacklist dangerous ones.
"""

import logging
import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath

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
# Host service unit validation (remote-server-mcp)
# ============================================================================

# Systemd unit names may contain dots, @, colons, hyphens and underscores. The
# allowlist below is the real control; this pattern only rejects names that
# cannot be a plain systemd unit (paths, spaces, shell syntax).
HOST_UNIT_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,99}$")

# Default units that may be inspected with systemctl/journalctl. Host
# infrastructure services are not Docker containers, so they need their own
# explicit allowlist. Override with security.host_units in config.yaml.
DEFAULT_HOST_UNITS: tuple[str, ...] = (
    "telegraf",
    "smartd",
    "docker",
    "snapraid",
    "mergerfs",
    "smbd",
)

# Absolute filesystem paths reported by get_server_health when
# health.disk_paths is unset or contains no valid entry. NAS pools are separate
# mount points, so they must be configured explicitly instead of assuming that
# services_path is representative.
DEFAULT_HEALTH_DISK_PATHS: tuple[str, ...] = ("/",)

# ============================================================================
# Log search and time-filter validation (remote-server-mcp)
# ============================================================================

# Log search matches lines locally in Python, never in a shell. Shell syntax in
# the pattern is therefore harmless and must be preserved verbatim; only the
# length and control characters are bounded.
MAX_SEARCH_PATTERN_LENGTH = 200
SEARCH_CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# ``docker logs --since/--until`` accept an RFC3339 timestamp (with an optional
# fractional part and offset), a date, or a Go-style relative duration such as
# ``42m`` or ``1h30m``. Keeping this strict prevents a value from being parsed
# as a Docker option.
LOG_TIME_PATTERN = re.compile(
    r"^(?:"
    r"\d{4}-\d{2}-\d{2}"
    r"(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?"
    r"|(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)){1,4}"
    r")$"
)
LOG_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}")
MAX_LOG_TIME_LENGTH = 64

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
# Sensitive file policy (remote-server-mcp)
# ============================================================================
#
# Matching is per path component (or its stem) and per extension, never as a
# substring of the whole path. That removes false positives such as
# ``monkey.txt`` matching ``.key`` or ``tokenizer.json`` matching ``token``.

# Components that are always refused: private keys, credential stores and
# version-control metadata that commonly embeds tokens in remote URLs.
BLOCKED_PATH_COMPONENTS: frozenset[str] = frozenset(
    {
        ".git",
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        ".docker",
        ".netrc",
        ".pgpass",
        ".npmrc",
        ".pypirc",
        ".htpasswd",
        "credentials",
        "credential",
        "secrets",
        "secret",
        "password",
        "passwords",
        "passwd",
        "token",
        "tokens",
        "api_key",
        "apikey",
        "private_key",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "shadow",
        "gshadow",
        "sudoers",
        "htpasswd",
        "wp-config",
        "wp-config.php",
        "database.yml",
        "database.yaml",
        "secrets.yml",
        "secrets.yaml",
    }
)

# Extensions that identify key material or an encrypted secret store.
BLOCKED_PATH_SUFFIXES: frozenset[str] = frozenset(
    {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"}
)

# ``.env`` files are readable because they are the primary way to debug a
# compose stack whose compose.yml only contains ``${VARS}``. Their values are
# masked before the contents are returned to the model.
REDACTED_PATH_NAMES: frozenset[str] = frozenset({".env", ".envrc"})
REDACTED_PATH_SUFFIXES: frozenset[str] = frozenset({".env"})


class FileAccess(Enum):
    """Access decision for a file inside a service directory."""

    ALLOW = "allow"
    REDACT = "redact"
    BLOCKED_INVALID = "blocked_invalid"
    BLOCKED_SENSITIVE = "blocked_sensitive"


@dataclass(frozen=True)
class ServiceFilePath:
    """Result of checking a requested service file path.

    ``path`` is the resolved absolute path when the file may be read, else
    ``None``. ``access`` tells callers whether the contents need redaction and
    why a path was refused; ``reason`` is a short human-readable explanation.
    """

    path: str | None
    access: FileAccess = FileAccess.ALLOW
    reason: str | None = None


def _relative_file_access(file_path: str) -> tuple[FileAccess, str | None]:
    """Classify a relative path against the sensitive-file policy."""
    access = FileAccess.ALLOW
    for component in PurePosixPath(file_path).parts:
        name = component.lower()
        pure = PurePosixPath(name)
        stem = pure.stem

        if name in BLOCKED_PATH_COMPONENTS or stem in BLOCKED_PATH_COMPONENTS:
            return (
                FileAccess.BLOCKED_SENSITIVE,
                f"path component {component!r} is sensitive",
            )

        if pure.suffix in BLOCKED_PATH_SUFFIXES:
            return (
                FileAccess.BLOCKED_SENSITIVE,
                f"file extension {pure.suffix!r} may contain key material",
            )

        if (
            name in REDACTED_PATH_NAMES
            or name.startswith(".env.")
            or pure.suffix in REDACTED_PATH_SUFFIXES
        ):
            access = FileAccess.REDACT

    return access, None


# ============================================================================
# Command safety - argv allowlist
# ============================================================================
#
# Every command must be an argv vector produced by the operation catalog and
# match one of these prefixes. The string is parsed with shlex and must render
# back to the exact same canonical form, so hand-built shell syntax (chaining,
# redirection, command substitution) is rejected before the allowlist lookup.

ALLOWED_ARGV_PREFIXES: tuple[tuple[str, ...], ...] = (
    # remote-server-mcp catalog
    ("echo",),
    ("uptime",),
    ("free", "-h"),
    ("df", "-h"),
    ("ls", "-1"),
    ("test", "-d"),
    ("docker", "ps"),
    ("docker", "logs"),
    ("docker", "inspect"),
    ("docker", "stats"),
    ("docker", "port"),
    ("docker", "restart"),
    ("docker", "start"),
    ("docker", "stop"),
    # host infrastructure services (remote-server-mcp)
    ("systemctl", "status"),
    ("journalctl", "-u"),
    # disk-health-mcp catalog
    ("lsblk", "-d"),
    ("iostat", "-x"),
    ("iostat", "-d"),
    ("zpool", "status"),
    ("zpool", "list"),
    ("zpool", "iostat"),
    ("zfs", "list"),
    ("zfs", "get"),
    ("cat", "/proc/mdstat"),
    ("mdadm", "--detail"),
    ("mdadm", "--examine"),
    ("snapraid", "status"),
    ("findmnt", "--real"),
    ("findmnt", "-t"),
)

for _smartctl in (
    "smartctl",
    "/usr/sbin/smartctl",
    "/sbin/smartctl",
    "/usr/bin/smartctl",
):
    ALLOWED_ARGV_PREFIXES += (
        (_smartctl, "--version"),
        (_smartctl, "-n", "standby"),
        (_smartctl, "-j", "-a"),
        (_smartctl, "-j", "-i"),
        (_smartctl, "-a"),
        (_smartctl, "-i"),
        (_smartctl, "-c"),
        (_smartctl, "-l", "error"),
        (_smartctl, "-l", "selftest"),
        (_smartctl, "-t"),
    )

for _nvme in ("nvme", "/usr/sbin/nvme", "/sbin/nvme"):
    for _subcommand in (
        "smart-log",
        "smart-log-add",
        "id-ctrl",
        "id-ns",
        "error-log",
    ):
        ALLOWED_ARGV_PREFIXES += ((_nvme, _subcommand),)

del _smartctl, _nvme, _subcommand

# Bare shell syntax in an argument can only come from a hand-built command.
SHELL_METACHARACTERS = frozenset(";&|<>`$")

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
        # Kept for configuration compatibility only. It deliberately has no
        # effect: there is no path that enables arbitrary command execution.
        self.allow_generic_command_execution = False

    @property
    def allowed_host_units(self) -> frozenset[str]:
        """Systemd units that may be inspected with systemctl/journalctl.

        ``security.host_units`` defaults to :data:`DEFAULT_HOST_UNITS`. Entries
        are validated so a malformed value cannot become a systemd argument.
        Setting the key to ``null`` or an empty list disables host-service
        tools entirely.
        """
        raw = self.security_config.get("host_units", DEFAULT_HOST_UNITS)
        if raw is None:
            return frozenset()
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, (list, tuple, set)):
            logger.warning("Ignoring security.host_units: expected a list of names")
            return frozenset()

        allowed = set()
        for unit in raw:
            if isinstance(unit, str) and HOST_UNIT_PATTERN.match(unit):
                allowed.add(unit)
            else:
                logger.warning("Ignoring invalid security.host_units entry: %r", unit)
        return frozenset(allowed)

    @property
    def health_disk_paths(self) -> tuple[str, ...]:
        """Absolute filesystem paths ``get_server_health`` reports.

        ``health.disk_paths`` accepts a list of absolute mount points (for
        example ``["/", "/mnt/storage"]``). Entries are validated, normalised
        and deduplicated while preserving their configured order. Invalid
        entries are ignored; when nothing valid remains the default ``["/"]``
        is used so the health report never silently loses its disk section.
        """
        health_config = self.config.get("health")
        if health_config is None:
            health_config = {}
        if not isinstance(health_config, dict):
            logger.warning("Ignoring health: expected a mapping")
            return DEFAULT_HEALTH_DISK_PATHS

        raw = health_config.get("disk_paths", DEFAULT_HEALTH_DISK_PATHS)
        if raw is None:
            raw = DEFAULT_HEALTH_DISK_PATHS
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, (list, tuple)):
            logger.warning("Ignoring health.disk_paths: expected a list of paths")
            return DEFAULT_HEALTH_DISK_PATHS

        paths: list[str] = []
        for candidate in raw:
            path = self.validate_disk_path(candidate)
            if path is not None and path not in paths:
                paths.append(path)

        if not paths:
            if raw:
                logger.warning(
                    "health.disk_paths contained no valid absolute path; using %s",
                    DEFAULT_HEALTH_DISK_PATHS,
                )
            return DEFAULT_HEALTH_DISK_PATHS
        return tuple(paths)

    @property
    def allowed_containers(self) -> frozenset[str]:
        """Container names explicitly allowed outside a service directory.

        ``security.allowed_containers`` exists for containers that are not
        part of a compose project below ``services_path`` (for example a
        standalone `watchtower` container). Entries are validated with the
        same pattern as service names, so they cannot inject Docker options.
        """
        raw = self.security_config.get("allowed_containers", [])
        if raw is None:
            return frozenset()
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, (list, tuple, set)):
            logger.warning(
                "Ignoring security.allowed_containers: expected a list of names"
            )
            return frozenset()

        allowed = set()
        for name in raw:
            if isinstance(name, str) and self.validate_service_name(name):
                allowed.add(name)
            else:
                logger.warning(
                    "Ignoring invalid security.allowed_containers entry: %r", name
                )
        return frozenset(allowed)

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

    def check_service_file_path(self, service: str, file_path: str) -> ServiceFilePath:
        """Validate a file path and classify it for the sensitive-file policy.

        Args:
            service: Service name (already validated)
            file_path: Relative file path within the service directory

        Returns:
            A :class:`ServiceFilePath`. ``path`` is set only when the file may
            be read; ``access`` distinguishes invalid paths from files refused
            by the sensitive-file policy and marks ``.env`` files for redaction.
        """
        if (
            not isinstance(service, str)
            or not service
            or service in {".", ".."}
            or PurePosixPath(service).parts != (service,)
        ):
            logger.warning("Invalid service name for file path: %r", service)
            return ServiceFilePath(
                None, FileAccess.BLOCKED_INVALID, "invalid service name"
            )

        if not file_path or not isinstance(file_path, str):
            logger.warning(f"Invalid file path: {file_path}")
            return ServiceFilePath(
                None, FileAccess.BLOCKED_INVALID, "file path is empty"
            )

        if len(file_path) > 500:
            logger.warning(f"File path too long: {len(file_path)} chars")
            return ServiceFilePath(
                None, FileAccess.BLOCKED_INVALID, "file path is too long"
            )

        if "\x00" in file_path:
            logger.warning("File path contains null byte")
            return ServiceFilePath(
                None, FileAccess.BLOCKED_INVALID, "file path contains a null byte"
            )

        file_path_lower = file_path.lower()
        for pattern in URL_ENCODED_TRAVERSAL:
            if pattern.lower() in file_path_lower:
                logger.warning(f"File path contains URL-encoded traversal: {pattern}")
                return ServiceFilePath(
                    None,
                    FileAccess.BLOCKED_INVALID,
                    "file path contains URL-encoded traversal",
                )

        for char in UNICODE_DOT_VARIANTS:
            if char in file_path:
                logger.warning("File path contains unicode dot variant: %r", char)
                return ServiceFilePath(
                    None,
                    FileAccess.BLOCKED_INVALID,
                    "file path contains a Unicode dot variant",
                )

        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in file_path:
                logger.warning(f"File path contains dangerous pattern: {pattern}")
                return ServiceFilePath(
                    None,
                    FileAccess.BLOCKED_INVALID,
                    "file path contains a traversal or shell pattern",
                )

        if file_path.startswith("/"):
            logger.warning(f"File path must be relative, not absolute: {file_path}")
            return ServiceFilePath(
                None, FileAccess.BLOCKED_INVALID, "file path must be relative"
            )

        access, reason = _relative_file_access(file_path)
        if access is FileAccess.BLOCKED_SENSITIVE:
            logger.warning("File path blocked by sensitive-file policy: %s", file_path)
            return ServiceFilePath(None, access, reason)

        # The path belongs to the target host, not to the MCP host. Building it
        # with PurePosixPath keeps it lexical: a symlink below services_path on
        # the MCP host can neither change the target path nor break validation.
        # The executor performs the authoritative realpath check on the target.
        service_base = str(PurePosixPath(self.services_base_path) / service)
        full_path = str(PurePosixPath(service_base) / file_path)
        if full_path != service_base and not full_path.startswith(service_base + "/"):
            logger.warning(
                "Lexical path escaped service directory: %s (base %s)",
                full_path,
                service_base,
            )
            return ServiceFilePath(
                None,
                FileAccess.BLOCKED_INVALID,
                "file path resolves outside the service directory",
            )
        return ServiceFilePath(full_path, access, reason)

    def validate_service_file_path(self, service: str, file_path: str) -> str | None:
        """
        Validate and construct a safe file path within /srv/{service}/.

        Args:
            service: Service name (already validated)
            file_path: Relative file path within service directory

        Returns:
            Full safe path, or None if invalid
        """
        return self.check_service_file_path(service, file_path).path

    def validate_disk_path(self, path: object) -> str | None:
        """Validate and normalise an absolute filesystem path for ``df``.

        Only paths are accepted (no shell syntax, globs or traversal) and the
        path must be absolute. ``PurePosixPath`` makes the result lexical, so
        the path is still resolved on the target host, not on the MCP host.

        Returns:
            The normalised absolute path, or ``None`` when invalid.
        """
        if not isinstance(path, str) or not path:
            logger.warning("Invalid health disk path: %r", path)
            return None

        if len(path) > 500:
            logger.warning("Health disk path too long: %d chars", len(path))
            return None

        if not path.startswith("/"):
            logger.warning("Health disk path must be absolute: %s", path)
            return None

        if "\x00" in path or any(ord(char) < 0x20 for char in path):
            logger.warning("Health disk path contains a control character: %r", path)
            return None

        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in path:
                logger.warning(
                    "Health disk path contains dangerous pattern %r: %s",
                    pattern,
                    path,
                )
                return None

        try:
            normalised = str(PurePosixPath(path))
        except Exception as e:  # pragma: no cover - PurePosixPath is defensive
            logger.warning("Could not normalise health disk path %r: %s", path, e)
            return None

        if not normalised.startswith("/"):
            return None
        return normalised

    def validate_host_unit(self, unit: str) -> bool:
        """Validate a systemd unit name against the configured allowlist.

        Args:
            unit: Unit name such as ``telegraf`` or ``docker``.

        Returns:
            True only when the name is well formed and explicitly allowed.
        """
        if not unit or not isinstance(unit, str):
            logger.warning("Invalid host unit: %r", unit)
            return False

        if not HOST_UNIT_PATTERN.match(unit):
            logger.warning("Host unit contains invalid characters: %s", unit)
            return False

        if unit not in self.allowed_host_units:
            logger.warning("Host unit is not in security.host_units: %s", unit)
            return False

        return True

    # ========================================================================
    # Log search and time-filter validation (remote-server-mcp)
    # ========================================================================

    def validate_search_pattern(self, pattern: str) -> str:
        """Validate a log search pattern and return it unchanged.

        ``search_service_logs`` filters lines locally in Python, so the pattern
        is data rather than shell syntax. Characters such as quotes, ``!``,
        ``#`` and ``~`` must keep their literal meaning; only length and control
        characters are rejected.

        Args:
            pattern: Raw search pattern

        Returns:
            The exact pattern, unchanged

        Raises:
            ValueError: If the pattern is empty, too long or contains control
                characters
        """
        if not pattern or not isinstance(pattern, str):
            raise ValueError("Search pattern must not be empty")

        if len(pattern) > MAX_SEARCH_PATTERN_LENGTH:
            raise ValueError(
                f"Search pattern too long ({len(pattern)} chars, "
                f"max {MAX_SEARCH_PATTERN_LENGTH})"
            )

        if SEARCH_CONTROL_CHARACTER_PATTERN.search(pattern):
            raise ValueError("Search pattern must not contain control characters")

        return pattern

    def validate_log_time(self, value: str, field: str = "time") -> bool:
        """Validate a ``docker logs --since/--until`` value.

        Args:
            value: RFC3339 timestamp, ``YYYY-MM-DD`` date or relative duration
            field: Name used in the warning (``since`` or ``until``)

        Returns:
            True if Docker can safely receive the value
        """
        if not value or not isinstance(value, str):
            logger.warning(f"Invalid log {field}: {value!r}")
            return False

        if len(value) > MAX_LOG_TIME_LENGTH:
            logger.warning(f"Log {field} too long: {len(value)} chars")
            return False

        if not LOG_TIME_PATTERN.match(value):
            logger.warning(f"Invalid log {field} format: {value!r}")
            return False

        if LOG_DATE_PATTERN.match(value):
            # The pattern only checks the shape; reject impossible dates such
            # as 2026-13-99 instead of passing them on to Docker.
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                logger.warning(f"Invalid log {field} date: {value!r}")
                return False

        return True

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
        Check whether a catalog command is safe to execute.

        The command must be a canonical argv vector (as rendered by
        :func:`shlex.join`) whose executable and leading arguments match the
        explicit allowlist. Unknown executables and hand-built shell syntax are
        rejected. ``security.allow_generic_commands`` has no effect.

        Args:
            command: Full command string

        Returns:
            True if safe
        """
        if not isinstance(command, str) or not command.strip():
            logger.warning("Invalid command: %r", command)
            return False

        if len(command) > 4096:
            logger.warning("Command too long: %d chars", len(command))
            return False

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

        # Parse the command and require canonical shlex.join output. A string
        # with bare shell syntax (``;``, ``&&``, a newline, ``>``, ...) does
        # not round-trip, so only catalog-rendered argv vectors get past this.
        try:
            argv = shlex.split(command)
        except ValueError:
            logger.warning("Command could not be parsed as an argv vector")
            return False

        if not argv:
            return False

        if shlex.join(argv) != command:
            logger.warning("Command is not a canonical argv vector: %s", command)
            return False

        for token in argv:
            if any(char in SHELL_METACHARACTERS for char in token):
                logger.warning(
                    "Command argument contains a shell metacharacter: %r", token
                )
                return False

        for prefix in ALLOWED_ARGV_PREFIXES:
            if tuple(argv[: len(prefix)]) == prefix:
                return True

        logger.warning("Command is not in the allowed operation catalog: %s", command)
        return False
