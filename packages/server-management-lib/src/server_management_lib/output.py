"""
Output sanitization and size limits.

MCP tool output is fed directly to a model. Remote command output is untrusted:
it can contain terminal escape sequences, control characters, or megabytes of
data. Everything returned by the SSH layer and the HTTP clients goes through
:func:`sanitize_output`.
"""

import re

DEFAULT_MAX_OUTPUT_BYTES = 64_000

# CSI/OSC-style terminal escapes (colors, cursor movement, hyperlinks, ...)
ANSI_ESCAPE_PATTERN = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))"
)

# Control characters except tab, newline and carriage return.
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# A response that was already truncated at this limit must not be truncated
# again: composite tools assemble several capped blocks and then apply a final
# cap, which would otherwise append a second marker.
TRUNCATION_MARKER_PATTERN = re.compile(r"\n… \[[^\]]+ truncated to (\d+) bytes\]$")


def strip_ansi(text: str) -> str:
    """Remove ANSI terminal escape sequences."""
    return ANSI_ESCAPE_PATTERN.sub("", text)


def truncation_marker(label: str, max_bytes: int) -> str:
    """Return the marker appended when output is capped at ``max_bytes``."""
    return f"\n… [{label} truncated to {max_bytes} bytes]"


class BoundedCollector:
    """Collect at most ``limit`` bytes from one or more async byte streams.

    The budget is shared across streams, so stdout and stderr together cannot
    exceed the cap. Bytes beyond the cap are drained but not retained, which
    keeps the process memory bounded even when a command emits gigabytes.
    A non-positive limit disables the bound, matching :func:`sanitize_output`.
    """

    def __init__(self, limit: int):
        self.limit = int(limit)
        self.remaining = self.limit if self.limit > 0 else None
        self.truncated = False

    async def read(self, stream) -> bytes:
        """Read ``stream`` to EOF, retaining at most the shared budget."""
        chunks: list[bytes] = []
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            if self.remaining is None:
                chunks.append(chunk)
            elif self.remaining > 0:
                keep = chunk[: self.remaining]
                chunks.append(keep)
                self.remaining -= len(keep)
                if len(keep) < len(chunk):
                    self.truncated = True
            else:
                self.truncated = True
        return b"".join(chunks)


def sanitize_output(
    text: str,
    max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    *,
    label: str = "output",
) -> str:
    """Strip escapes/control characters and cap the encoded size.

    The cap is applied to the UTF-8 encoding so a single response cannot flood
    the model context. A truncation marker is appended when data was dropped.
    """
    if not text:
        return text

    cleaned = CONTROL_CHAR_PATTERN.sub("", strip_ansi(text))

    if max_bytes <= 0:
        return cleaned

    existing = TRUNCATION_MARKER_PATTERN.search(cleaned)
    if existing is not None and int(existing.group(1)) == max_bytes:
        return cleaned

    encoded = cleaned.encode("utf-8")
    if len(encoded) <= max_bytes:
        return cleaned

    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{truncated}{truncation_marker(label, max_bytes)}"
