"""
SSH Connection Manager for Remote Server Operations

Handles SSH connections with strict security:

- Host keys are verified by default against ``ssh.known_hosts``.
- Key/agent authentication is used when no password is configured.
- Commands are validated before execution.
"""

import logging
import os
import shlex
from pathlib import Path

import asyncssh

from .security import SecurityValidator

logger = logging.getLogger(__name__)

DEFAULT_KNOWN_HOSTS = "~/.ssh/known_hosts"
DISABLED_KNOWN_HOSTS = {"", "none", "false", "off"}


class SSHConfigurationError(RuntimeError):
    """Raised when SSH settings cannot be turned into a safe connection."""


def _load_known_hosts(path: Path) -> str | bytes:
    """Load a known_hosts file, skipping entries asyncssh/cryptography cannot parse.

    Modern OpenSSL/cryptography rejects legacy DSA keys, and a single such line
    makes ``read_known_hosts()`` fail for the whole file. We keep verification
    enabled for every other entry instead of disabling it altogether.

    Returns the path when the file parses cleanly, otherwise a sanitized
    known_hosts payload (bytes) with unreadable lines removed.
    """
    try:
        asyncssh.read_known_hosts(str(path))
        return str(path)
    except Exception as e:
        logger.warning(
            "Could not parse %s as a whole (%s); skipping unreadable entries",
            path,
            e,
        )

    kept: list[str] = []
    skipped = 0
    for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            asyncssh.import_known_hosts(entry)
        except Exception:
            skipped += 1
            if skipped <= 3:
                logger.warning(
                    "Skipping unsupported known_hosts entry at %s:%d "
                    "(legacy or malformed key)",
                    path,
                    lineno,
                )
            continue
        kept.append(entry)

    if skipped > 3:
        logger.warning("Skipped %d unsupported known_hosts entries", skipped)
    if not kept:
        raise SSHConfigurationError(
            f"No usable host keys in {path}. Remove legacy entries or regenerate "
            "the file with ssh-keyscan."
        )
    logger.info(
        "Loaded %d known_hosts entries from %s (%d skipped)",
        len(kept),
        path,
        skipped,
    )
    return ("\n".join(kept) + "\n").encode()


class SSHManager:
    """Manages SSH connections with strict security controls."""

    def __init__(self, config: dict, security: SecurityValidator):
        """
        Initialize SSH manager.

        Args:
            config: Configuration dictionary with SSH settings
            security: Security validator instance
        """
        self.config = config
        self.security = security
        self.ssh_config = config.get("ssh", {}) or {}
        self.services_base_path = security.services_base_path
        self.connection: asyncssh.SSHClientConnection | None = None
        self._connected = False
        self._known_hosts_cache: str | bytes | None = None
        self._known_hosts_loaded = False

    # ------------------------------------------------------------------
    # Connection setup
    # ------------------------------------------------------------------

    def _known_hosts_option(self) -> str | bytes | None:
        """Return the known_hosts path, sanitized payload, or ``None``."""
        if self._known_hosts_loaded:
            return self._known_hosts_cache

        value = self._load_known_hosts_option()
        self._known_hosts_cache = value
        self._known_hosts_loaded = True
        return value

    def _load_known_hosts_option(self) -> str | bytes | None:
        value = self.ssh_config.get("known_hosts", DEFAULT_KNOWN_HOSTS)
        if value is None or (
            isinstance(value, str) and value.strip().lower() in DISABLED_KNOWN_HOSTS
        ):
            logger.warning(
                "SSH host key verification is DISABLED. This is insecure; "
                "set ssh.known_hosts to a known_hosts file to enable it."
            )
            return None

        path = Path(str(value)).expanduser()
        if not path.exists():
            raise SSHConfigurationError(
                f"SSH known_hosts file not found: {path}. Add the host key first "
                f"(ssh-keyscan -H <host> >> {path}) or set ssh.known_hosts to "
                "'none' to disable verification (insecure)."
            )
        return _load_known_hosts(path)

    def build_connect_kwargs(self) -> dict:
        """Build keyword arguments for :func:`asyncssh.connect`."""
        kwargs: dict = {"host": self.ssh_config.get("host") or "localhost"}

        kwargs["port"] = int(self.ssh_config.get("port") or 22)

        username = self.ssh_config.get("username")
        if username:
            kwargs["username"] = username

        key_path = self.ssh_config.get("key_path")
        if key_path:
            expanded_path = os.path.expanduser(str(key_path))
            kwargs["client_keys"] = [expanded_path]
            logger.info("Using SSH key: %s", expanded_path)

        password = self.ssh_config.get("password")
        if password:
            kwargs["password"] = password

        connect_timeout = self.ssh_config.get("connect_timeout")
        if connect_timeout:
            kwargs["connect_timeout"] = int(connect_timeout)

        # Explicitly pass known_hosts so that a missing file cannot silently
        # degrade to "no verification" (asyncssh does that by default).
        kwargs["known_hosts"] = self._known_hosts_option()

        return kwargs

    async def connect(self) -> None:
        """Establish SSH connection to the remote server."""
        kwargs = self.build_connect_kwargs()
        host = kwargs["host"]

        try:
            self.connection = await asyncssh.connect(**kwargs)
            self._connected = True
            logger.info(
                "Connected to %s:%s as %s",
                host,
                kwargs.get("port", 22),
                kwargs.get("username", "(default)"),
            )
        except Exception as e:
            self._connected = False
            self.connection = None
            logger.error("Failed to connect to %s: %s", host, e)
            raise

    async def disconnect(self) -> None:
        """Close SSH connection."""
        connection = self.connection
        self.connection = None
        self._connected = False
        if connection:
            connection.close()
            wait_closed = getattr(connection, "wait_closed", None)
            if wait_closed is not None:
                try:
                    await wait_closed()
                except Exception as e:  # pragma: no cover - best effort
                    logger.debug("Error while closing SSH connection: %s", e)
            logger.info("SSH connection closed")

    async def execute_safe_command(self, command: str, timeout: int = 30) -> str:
        """
        Execute a pre-validated safe command.

        Args:
            command: Pre-validated command (constructed by application code)
            timeout: Timeout in seconds (default: 30)

        Returns:
            Command output
        """
        if not self.security.is_command_safe(command):
            logger.error("Attempted to execute unsafe command: %s", command)
            return "❌ Security violation: Command blocked by security policy"

        if not self._connected or not self.connection:
            await self.connect()

        if self.connection is None:
            return "❌ Connection failed"

        try:
            result = await self.connection.run(
                command,
                check=False,
                timeout=timeout,
            )

            output: str = ""
            if result.stdout:
                output += str(result.stdout)
            if result.stderr:
                if output:
                    output += "\n--- STDERR ---\n"
                output += str(result.stderr)

            if result.exit_status != 0:
                output += f"\n\n⚠️ Exit code: {result.exit_status}"

            return output
        except (asyncssh.ConnectionLost, asyncssh.DisconnectError) as e:
            # Drop the dead connection so the next call reconnects.
            self.connection = None
            self._connected = False
            return f"❌ SSH connection lost: {e}"
        except asyncssh.Error as e:
            return f"❌ SSH error: {e}"
        except TimeoutError:
            return f"❌ Command timed out after {timeout}s"
        except Exception as e:
            return f"❌ Error executing command: {e}"

    async def check_service_exists(self, service: str) -> bool:
        """
        Check if a service directory exists under ``security.services_path``.

        Args:
            service: Service name (should be validated already)

        Returns:
            True if service exists
        """
        try:
            service_path = f"{self.services_base_path.rstrip('/')}/{service}"
            cmd = (
                f"test -d {shlex.quote(service_path)} "
                "&& echo 'exists' || echo 'not_exists'"
            )
            result = await self.execute_safe_command(cmd)
            return "exists" in result and "not_exists" not in result
        except Exception:
            return False

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
