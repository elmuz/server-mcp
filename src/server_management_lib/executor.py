"""
Executor factory.

Selects the SSH or local implementation from ``config["executor"]``. Both
implement the same command/file interface, so MCP tools do not need to know
where they run.
"""

from typing import Protocol

from .base import RemoteDirEntry
from .local_executor import LocalExecutor
from .security import SecurityValidator
from .ssh_manager import SSHManager


class Executor(Protocol):
    """Interface shared by :class:`SSHManager` and :class:`LocalExecutor`."""

    services_base_path: str
    max_output_bytes: int

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    async def execute_safe_command(self, command: str, timeout: int = 30) -> str: ...

    async def check_service_exists(self, service: str) -> bool: ...

    async def read_remote_file(
        self,
        path: str,
        *,
        allowed_base: str | None = None,
        max_bytes: int | None = None,
    ) -> str: ...

    async def list_remote_dir(
        self, path: str, *, allowed_base: str | None = None
    ) -> list[RemoteDirEntry]: ...


def create_executor(
    config: dict, security: SecurityValidator
) -> SSHManager | LocalExecutor:
    """Create the executor selected by ``config["executor"]`` (default: ssh)."""
    mode = str(config.get("executor", "ssh")).strip().lower()
    if mode == "local":
        return LocalExecutor(config, security)
    if mode == "ssh":
        return SSHManager(config, security)
    raise ValueError(f"Unknown executor {mode!r}; expected 'ssh' or 'local'")
