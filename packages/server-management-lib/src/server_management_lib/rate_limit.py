"""A small in-memory rate limiter for state-changing tool calls.

The limiter is scoped to one MCP server process (one client session in
practice). It is a sliding window over call timestamps: at most ``max_calls``
calls are allowed in any ``window_seconds`` period. It is deliberately simple
and local; it is not a substitute for host-level protections.
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitConfig:
    """Configuration for the destructive-action rate limiter."""

    enabled: bool = True
    max_calls: int = 10
    window_seconds: float = 60.0

    @classmethod
    def from_config(cls, config: dict) -> "RateLimitConfig":
        section = config.get("rate_limit")
        if not isinstance(section, dict):
            return cls()

        enabled = section.get("enabled", True)
        if not isinstance(enabled, bool):
            logger.warning("Ignoring non-boolean rate_limit.enabled")
            enabled = True

        max_calls = _positive_int(section.get("max_calls", 10), "rate_limit.max_calls")
        window = _positive_float(
            section.get("window_seconds", 60), "rate_limit.window_seconds"
        )
        return cls(enabled=enabled, max_calls=max_calls, window_seconds=window)


def _positive_int(value: object, name: str) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid %s: %r", name, value)
        return 10
    if parsed < 1:
        logger.warning("Ignoring non-positive %s: %r", name, value)
        return 10
    return parsed


def _positive_float(value: object, name: str) -> float:
    try:
        parsed = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid %s: %r", name, value)
        return 60.0
    if parsed <= 0:
        logger.warning("Ignoring non-positive %s: %r", name, value)
        return 60.0
    return parsed


class RateLimiter:
    """Sliding-window limiter with a monotonic clock (injectable for tests)."""

    def __init__(
        self,
        max_calls: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_calls < 1:
            raise ValueError("max_calls must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_calls = max_calls
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._calls and self._calls[0] <= cutoff:
            self._calls.popleft()

    def check(self) -> float | None:
        """Record a call; return ``None`` when allowed or the retry delay."""
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._calls) >= self.max_calls:
                return max(0.0, self.window_seconds - (now - self._calls[0]))
            self._calls.append(now)
            return None

    def reset(self) -> None:
        """Forget recorded calls (used by tests and session teardown)."""
        with self._lock:
            self._calls.clear()


def create_rate_limiter(config: dict) -> RateLimiter | None:
    """Build the destructive-action limiter, or ``None`` when disabled."""
    settings = RateLimitConfig.from_config(config)
    if not settings.enabled:
        return None
    return RateLimiter(
        settings.max_calls,
        settings.window_seconds,
    )
