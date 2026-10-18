"""
Shared executor primitives.

An executor runs validated commands and reads remote/local files. SSH and local
implementations share output limits, audit logging and path-confinement rules.
"""

from dataclasses import dataclass

from .audit import create_audit_logger
from .output import DEFAULT_MAX_OUTPUT_BYTES
from .security import SecurityValidator


class ExecutorError(RuntimeError):
    """Base class for executor errors."""


class RemotePathError(ExecutorError):
    """Raised when a path escapes its allowed base directory."""


class RemoteFileError(ExecutorError):
    """Raised when a file cannot be read safely."""


@dataclass(frozen=True)
class RemoteDirEntry:
    """A single directory entry returned by an executor."""

    name: str
    longname: str
    size: int


def is_within(path: str, base: str) -> bool:
    """Return True when ``path`` is ``base`` or below it (component-aware)."""
    base = base.rstrip("/")
    return path == base or path.startswith(base + "/")


class ExecutorBase:
    """Configuration, output limits and audit logging shared by executors."""

    def __init__(self, config: dict, security: SecurityValidator):
        self.config = config
        self.security = security
        self.services_base_path = security.services_base_path

        output_config = config.get("output", {}) or {}
        self.max_output_bytes = int(
            output_config.get("max_bytes", DEFAULT_MAX_OUTPUT_BYTES)
        )

        self.audit = create_audit_logger(config)
