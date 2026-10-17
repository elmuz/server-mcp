"""
Local command executor.

Runs the same validated operation catalog as the SSH executor, but on the host
where the MCP server runs. Commands are executed as argument vectors (never
through a shell), and file access is confined to the configured service base.
"""

import asyncio
import logging
import shlex
import stat
import time
from datetime import datetime
from pathlib import Path

from .base import (
    ExecutorBase,
    RemoteDirEntry,
    RemoteFileError,
    RemotePathError,
    is_within,
)
from .output import sanitize_output

logger = logging.getLogger(__name__)

SHELL_OPERATORS = {
    "&",
    "&&",
    ";",
    "|",
    "||",
    ">",
    ">>",
    "<",
    "<<",
    "2>",
    "2>&1",
}


class LocalExecutor(ExecutorBase):
    """Execute validated commands and file operations on the local host."""

    async def connect(self) -> None:
        """No-op; kept for interface parity with the SSH executor."""

    async def disconnect(self) -> None:
        """No-op; kept for interface parity with the SSH executor."""

    async def execute_safe_command(self, command: str, timeout: int = 30) -> str:
        """Execute a validated command as an argv vector (no shell)."""
        if not self.security.is_command_safe(command):
            logger.error("Attempted to execute unsafe command: %s", command)
            self.audit.log("command_blocked", command=command, executor="local")
            return "❌ Security violation: Command blocked by security policy"

        argv = shlex.split(command)
        if not argv:
            return "❌ Empty command"

        if any(token in SHELL_OPERATORS for token in argv):
            self.audit.log("command_blocked", command=command, reason="shell_operator")
            return (
                "❌ Shell operators are not supported by the local executor; "
                "the command must be a plain argv vector."
            )

        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            self.audit.log("command_error", command=command, error="not_found")
            return f"❌ Command not found: {argv[0]}"
        except OSError as e:
            self.audit.log("command_error", command=command, error=str(e))
            return f"❌ Error executing command: {e}"

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            self.audit.log("command_timeout", command=command, timeout=timeout)
            return f"❌ Command timed out after {timeout}s"

        output = stdout.decode("utf-8", errors="replace")
        error_output = stderr.decode("utf-8", errors="replace")
        if error_output:
            output += ("\n--- STDERR ---\n" if output else "") + error_output
        if process.returncode:
            output += f"\n\n⚠️ Exit code: {process.returncode}"

        sanitized = sanitize_output(
            output, self.max_output_bytes, label="command output"
        )
        self.audit.log(
            "command",
            command=command,
            executor="local",
            exit_status=process.returncode,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
            output_bytes=len(output.encode("utf-8")),
            truncated=sanitized != output,
        )
        return sanitized

    async def check_service_exists(self, service: str) -> bool:
        """Check the local service directory."""
        return (Path(self.services_base_path) / service).is_dir()

    async def read_remote_file(
        self,
        path: str,
        *,
        allowed_base: str | None = None,
        max_bytes: int | None = None,
    ) -> str:
        """Read a local file with the same confinement rules as SFTP reads."""
        limit = max_bytes or self.max_output_bytes
        real_path = Path(path).resolve()
        real_base = Path(allowed_base).resolve() if allowed_base else None
        if real_base is not None and not is_within(str(real_path), str(real_base)):
            self.audit.log("file_read_blocked", path=path, resolved=str(real_path))
            raise RemotePathError(f"Path escapes the allowed directory: {real_path}")

        try:
            with real_path.open("rb") as handle:
                data = handle.read(limit + 1)
        except OSError as e:
            raise RemoteFileError(f"Cannot read {real_path}: {e}") from e

        text = data.decode("utf-8", errors="replace")
        sanitized = sanitize_output(text, limit, label="file contents")
        self.audit.log(
            "file_read",
            path=str(real_path),
            size=real_path.stat().st_size,
            executor="local",
            truncated=len(data) > limit or sanitized != text,
        )
        return sanitized

    async def list_remote_dir(
        self,
        path: str,
        *,
        allowed_base: str | None = None,
    ) -> list[RemoteDirEntry]:
        """List a local directory with the same confinement rules."""
        real_path = Path(path).resolve()
        real_base = Path(allowed_base).resolve() if allowed_base else None
        if real_base is not None and not is_within(str(real_path), str(real_base)):
            self.audit.log("dir_list_blocked", path=path, resolved=str(real_path))
            raise RemotePathError(f"Path escapes the allowed directory: {real_path}")

        try:
            children = list(real_path.iterdir())
        except OSError as e:
            raise RemoteFileError(f"Cannot list {real_path}: {e}") from e

        entries = []
        for child in children:
            try:
                info = child.stat()
            except OSError:
                continue
            modified = datetime.fromtimestamp(info.st_mtime).strftime("%b %e %H:%M")
            longname = (
                f"{stat.filemode(info.st_mode)} {info.st_size:>10} "
                f"{modified} {child.name}"
            )
            entries.append(
                RemoteDirEntry(name=child.name, longname=longname, size=info.st_size)
            )
        entries.sort(key=lambda entry: entry.name)
        self.audit.log(
            "dir_list",
            path=str(real_path),
            entries=len(entries),
            executor="local",
        )
        return entries
