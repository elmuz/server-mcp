"""
Append-only audit log for privileged operations.

Every command, file read and blocked operation can be recorded as one JSON
object per line. Logging is best effort: an unwritable log must never break the
operation, but it is reported once.
"""

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REDACTED = "***REDACTED***"
SENSITIVE_KEY_PARTS = ("password", "token", "secret", "api_key", "apikey", "key")


def _redact(value: Any, key: str = "") -> Any:
    if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
        return REDACTED
    if isinstance(value, dict):
        return {k: _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact(item) for item in value]
    return value


class AuditLogger:
    """Write JSONL audit records to ``path`` when enabled."""

    def __init__(self, path: str | Path | None = None, *, enabled: bool = False):
        self.enabled = bool(enabled and path)
        self.path = Path(path).expanduser() if path else None
        self._lock = threading.Lock()
        self._warned = False

    def log(self, event: str, **fields: Any) -> None:
        if not self.enabled or self.path is None:
            return

        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "event": event,
            **_redact(fields),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record, default=str)
            with self._lock, self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as e:  # pragma: no cover - environment dependent
            if not self._warned:
                logger.warning("Cannot write audit log %s: %s", self.path, e)
                self._warned = True


def create_audit_logger(config: dict) -> AuditLogger:
    """Build an :class:`AuditLogger` from the ``audit`` config section.

    The HTTP clients receive the same logger as the executors so query
    metadata is recorded in one audit log.
    """
    audit_config = config.get("audit", {}) or {}
    return AuditLogger(
        audit_config.get("path"),
        enabled=audit_config.get("enabled", False),
    )
