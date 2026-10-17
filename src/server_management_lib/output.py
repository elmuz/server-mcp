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


def strip_ansi(text: str) -> str:
    """Remove ANSI terminal escape sequences."""
    return ANSI_ESCAPE_PATTERN.sub("", text)


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

    encoded = cleaned.encode("utf-8")
    if len(encoded) <= max_bytes:
        return cleaned

    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{truncated}\n… [{label} truncated to {max_bytes} bytes]"
