"""
SSH Connection Manager for Remote Server Operations

Handles SSH connections with strict security:

- Host keys are verified by default against ``ssh.known_hosts``.
- Key/agent authentication is used when no password is configured.
- Commands are validated before execution.
"""

import asyncio
import logging
import os
import re
import shlex
import stat
import time
from pathlib import Path

import asyncssh

from .base import (
    ExecutorBase,
    RemoteDirEntry,
    RemoteFileError,
    RemotePathError,
    is_within,
)
from .output import sanitize_output
from .security import SecurityValidator

logger = logging.getLogger(__name__)

DEFAULT_KNOWN_HOSTS = "~/.ssh/known_hosts"
DISABLED_KNOWN_HOSTS = {"", "none", "false", "off"}
# Bound every SFTP metadata/read operation so a FIFO, stuck server or dropped
# connection cannot block a tool call forever.
SFTP_OPERATION_TIMEOUT = 30


async def _sftp_operation(awaitable, *, description: str):
    """Await an SFTP operation with a timeout and a readable error."""
    try:
        return await asyncio.wait_for(awaitable, timeout=SFTP_OPERATION_TIMEOUT)
    except TimeoutError as e:
        raise RemoteFileError(
            f"SFTP {description} timed out after {SFTP_OPERATION_TIMEOUT}s"
        ) from e


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
    skipped_lines: list[int] = []
    for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            asyncssh.import_known_hosts(entry)
        except Exception:
            skipped_lines.append(lineno)
            continue
        kept.append(entry)

    if skipped_lines:
        # One aggregated warning per file keeps the log readable while still
        # making the skipped entries identifiable.
        preview = ", ".join(str(line) for line in skipped_lines[:10])
        suffix = ", ..." if len(skipped_lines) > 10 else ""
        logger.warning(
            "Skipped %d unsupported known_hosts entr%s in %s (lines %s%s); "
            "host key verification stays enabled for the remaining entries",
            len(skipped_lines),
            "y" if len(skipped_lines) == 1 else "ies",
            path,
            preview,
            suffix,
        )
    if not kept:
        raise SSHConfigurationError(
            f"No usable host keys in {path}. Remove legacy entries or regenerate "
            "the file with ssh-keyscan."
        )
    logger.info(
        "Loaded %d known_hosts entries from %s (%d skipped)",
        len(kept),
        path,
        len(skipped_lines),
    )
    return ("\n".join(kept) + "\n").encode()


class SSHManager(ExecutorBase):
    """Manages SSH connections with strict security controls."""

    def __init__(self, config: dict, security: SecurityValidator):
        """
        Initialize SSH manager.

        Args:
            config: Configuration dictionary with SSH settings
            security: Security validator instance
        """
        super().__init__(config, security)
        self.ssh_config = config.get("ssh", {}) or {}
        self.connection: asyncssh.SSHClientConnection | None = None
        self._connected = False
        self._connect_lock = asyncio.Lock()
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
        """Establish SSH connection to the remote server.

        Concurrent tool calls share one connection. Without the lock they can
        all observe ``_connected == False`` and open overlapping connections,
        leaking every connection but the last one. The second check inside the
        lock makes the call idempotent: a caller that waited for an in-flight
        connect reuses the connection instead of opening another.
        """
        async with self._connect_lock:
            if self._connected and self.connection is not None:
                return

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
            self.audit.log("command_blocked", command=command)
            return "❌ Security violation: Command blocked by security policy"

        if not self._connected or not self.connection:
            await self.connect()

        if self.connection is None:
            return "❌ Connection failed"

        started = time.monotonic()
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

            sanitized = sanitize_output(
                output, self.max_output_bytes, label="command output"
            )
            self.audit.log(
                "command",
                command=command,
                exit_status=result.exit_status,
                duration_ms=round((time.monotonic() - started) * 1000, 1),
                output_bytes=len(output.encode("utf-8")),
                truncated=sanitized != output,
            )
            return sanitized
        except (asyncssh.ConnectionLost, asyncssh.DisconnectError) as e:
            # Drop the dead connection so the next call reconnects.
            self.connection = None
            self._connected = False
            self.audit.log("command_connection_lost", command=command, error=str(e))
            return f"❌ SSH connection lost: {e}"
        except asyncssh.Error as e:
            self.audit.log("command_error", command=command, error=str(e))
            return f"❌ SSH error: {e}"
        except TimeoutError:
            self.audit.log("command_timeout", command=command, timeout=timeout)
            return f"❌ Command timed out after {timeout}s"
        except Exception as e:
            self.audit.log("command_error", command=command, error=str(e))
            return f"❌ Error executing command: {e}"

    # ------------------------------------------------------------------
    # Remote files (SFTP; no shell involved)
    # ------------------------------------------------------------------

    async def _get_sftp(self) -> asyncssh.SFTPClient:
        if not self._connected or not self.connection:
            await self.connect()
        if self.connection is None:
            raise RemoteFileError("SSH connection failed")
        return await self.connection.start_sftp_client()

    async def read_remote_file(
        self,
        path: str,
        *,
        allowed_base: str | None = None,
        max_bytes: int | None = None,
    ) -> str:
        """Read a remote file over SFTP with an optional base-path check."""
        limit = max_bytes or self.max_output_bytes
        async with await self._get_sftp() as sftp:
            real_path = str(
                await _sftp_operation(sftp.realpath(path), description="realpath")
            )
            real_base = (
                str(
                    await _sftp_operation(
                        sftp.realpath(allowed_base), description="realpath"
                    )
                )
                if allowed_base is not None
                else None
            )
            if real_base is not None and not is_within(real_path, real_base):
                self.audit.log("file_read_blocked", path=path, resolved=real_path)
                raise RemotePathError(
                    f"Remote path escapes the allowed directory: {real_path}"
                )

            attrs = await _sftp_operation(sftp.stat(real_path), description="stat")
            if not stat.S_ISREG(attrs.permissions or 0):
                self.audit.log(
                    "file_read_blocked",
                    path=path,
                    resolved=real_path,
                    reason="not_regular_file",
                )
                raise RemoteFileError(f"Remote path is not a regular file: {real_path}")
            size = attrs.size or 0
            async with sftp.open(real_path, "rb") as handle:
                data = await _sftp_operation(handle.read(limit + 1), description="read")

        text = data.decode("utf-8", errors="replace")
        sanitized = sanitize_output(text, limit, label="file contents")
        self.audit.log(
            "file_read",
            path=real_path,
            size=size,
            truncated=len(data) > limit or sanitized != text,
        )
        return sanitized

    async def list_remote_dir(
        self,
        path: str,
        *,
        allowed_base: str | None = None,
    ) -> list[RemoteDirEntry]:
        """List a remote directory over SFTP with an optional base-path check."""
        async with await self._get_sftp() as sftp:
            real_path = str(
                await _sftp_operation(sftp.realpath(path), description="realpath")
            )
            real_base = (
                str(
                    await _sftp_operation(
                        sftp.realpath(allowed_base), description="realpath"
                    )
                )
                if allowed_base is not None
                else None
            )
            if real_base is not None and not is_within(real_path, real_base):
                self.audit.log("dir_list_blocked", path=path, resolved=real_path)
                raise RemotePathError(
                    f"Remote path escapes the allowed directory: {real_path}"
                )
            names = await _sftp_operation(
                sftp.readdir(real_path), description="readdir"
            )

        entries = [
            RemoteDirEntry(
                name=entry.filename,
                longname=entry.longname,
                size=entry.attrs.size or 0,
            )
            for entry in names
            if entry.filename not in {".", ".."}
        ]
        entries.sort(key=lambda entry: entry.name)
        self.audit.log("dir_list", path=real_path, entries=len(entries))
        return entries

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
            cmd = f"test -d {shlex.quote(service_path)}"
            result = await self.execute_safe_command(cmd)
            if "❌" in result:
                return False

            match = re.search(r"⚠️ Exit code:\s*(-?\d+)", result)
            return match is None or int(match.group(1)) == 0
        except Exception:
            return False

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
