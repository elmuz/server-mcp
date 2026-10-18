"""
Redaction helpers for file contents returned to the model.

``.env`` files are useful for debugging a compose stack, but their values are
secrets. :func:`redact_env_content` keeps the keys, comments and structure so
the file stays readable while every assignment value is masked.
"""

import re

REDACTED_VALUE = "***"

# ``KEY=value`` and ``export KEY=value`` with optional whitespace around ``=``.
_ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<prefix>\s*(?:export\s+)?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<sep>\s*=\s*)(?P<value>.*)$"
)


def redact_env_content(text: str) -> str:
    """Mask the values of dotenv assignments, preserving the file structure.

    Comments and blank lines are kept unchanged. Recognized assignments keep
    their key and separator (``KEY=***``). Any other non-empty line is treated
    as a value or a continuation of one (for example a multi-line quoted
    secret) and is masked entirely, so no value text can leak. A trailing
    newline in the input is preserved.

    Args:
        text: Raw file contents.

    Returns:
        The contents with every assignment value replaced by ``***``.
    """
    if not text:
        return text

    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue

        match = _ASSIGNMENT_PATTERN.match(line)
        if match is None:
            lines.append(REDACTED_VALUE)
            continue

        lines.append(
            f"{match.group('prefix')}{match.group('key')}"
            f"{match.group('sep')}{REDACTED_VALUE}"
        )

    redacted = "\n".join(lines)
    if text.endswith("\n"):
        redacted += "\n"
    return redacted
