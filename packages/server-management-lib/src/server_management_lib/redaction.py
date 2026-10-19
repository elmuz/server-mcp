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


# ============================================================================
# General secret redaction (service config files and host status/log output)
# ============================================================================

# Key names whose values are secrets. Matching is on the key itself, so
# ``POSTGRES_PASSWORD``, ``GITHUB_TOKEN`` and ``api_key`` are covered without
# treating unrelated ``*.key`` file names as secrets (that policy lives in
# ``security.BLOCKED_PATH_*``).
_SENSITIVE_KEY_WORD = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|"
    r"authorization|access[_-]?key|client[_-]?secret|credential)",
    re.IGNORECASE,
)

# JSON object member: "key": "value" or "key": value
_JSON_MEMBER = re.compile(
    r'(?P<prefix>"(?P<key>[^"\n]+)"\s*:\s*)'
    r'(?P<value>"(?:[^"\\]|\\.)*"|[^,}\n]+)'
)

# YAML/INI/CLI assignment at the start of a line, including ``- KEY=value``.
_LINE_ASSIGNMENT = re.compile(
    r"^(?P<prefix>\s*(?:-\s*)?)"
    r'(?P<key>"?[A-Za-z0-9_.-]+"?)'
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<value>.*)$"
)

# KEY=value anywhere on the line (environment assignments in command lines).
_INLINE_ASSIGNMENT = re.compile(
    r"(?P<key>\b[A-Za-z_][A-Za-z0-9_.-]*)(?P<sep>=)"
    r'(?P<value>"[^"]*"|\'[^\']*\'|[^\s,;}]+)'
)

# --token value and --password=value command-line flags.
_CLI_FLAG = re.compile(
    r"(?P<key>--?[A-Za-z0-9_.-]+)(?P<sep>[=\s]+)"
    r'(?P<value>"[^"]*"|\'[^\']*\'|[^\s,;}]+)'
)

_BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT_VALUE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_URL_PASSWORD = re.compile(
    r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)(?P<user>[^/\s:@]+):"
    r"(?P<password>[^/\s@]+)@",
    re.IGNORECASE,
)


def _is_sensitive_key(key: str) -> bool:
    """Return True when an assignment key names a credential."""
    cleaned = key.strip().strip("\"'").lstrip("-")
    return bool(cleaned) and _SENSITIVE_KEY_WORD.search(cleaned) is not None


def _redact_line(line: str) -> str:
    if not line:
        return line

    stripped = line.lstrip()
    if stripped.startswith(("#", ";", "//")):
        return line

    json_changed = False

    def json_replacement(match: re.Match[str]) -> str:
        nonlocal json_changed
        if _is_sensitive_key(match.group("key")):
            json_changed = True
            return f'{match.group("prefix")}"***"'
        return match.group(0)

    line = _JSON_MEMBER.sub(json_replacement, line)

    if not json_changed:
        line_match = _LINE_ASSIGNMENT.match(line)
        if line_match is not None and _is_sensitive_key(line_match.group("key")):
            line = (
                f"{line_match.group('prefix')}{line_match.group('key')}"
                f"{line_match.group('sep')}{REDACTED_VALUE}"
            )

    def assignment_replacement(match: re.Match[str]) -> str:
        if _is_sensitive_key(match.group("key")):
            return f"{match.group('key')}{match.group('sep')}{REDACTED_VALUE}"
        return match.group(0)

    line = _INLINE_ASSIGNMENT.sub(assignment_replacement, line)

    def flag_replacement(match: re.Match[str]) -> str:
        if _is_sensitive_key(match.group("key")):
            return f"{match.group('key')}{match.group('sep')}{REDACTED_VALUE}"
        return match.group(0)

    line = _CLI_FLAG.sub(flag_replacement, line)
    line = _BEARER_VALUE.sub(f"Bearer {REDACTED_VALUE}", line)
    line = _JWT_VALUE.sub(REDACTED_VALUE, line)
    line = _URL_PASSWORD.sub(
        lambda match: f"{match.group('scheme')}{match.group('user')}:{REDACTED_VALUE}@",
        line,
    )
    return line


def redact_secrets(text: str) -> str:
    """Mask credentials in service config files and host status/log output.

    The redactor handles YAML/INI/dotenv assignments, JSON members, command-line
    flags, inline ``KEY=value`` pairs, ``Authorization: Bearer`` values, JWT
    shapes and credentials embedded in URLs. Keys, comments and the surrounding
    structure stay readable; only the value is replaced with ``***``.

    This is deliberately applied in addition to, not instead of, the sensitive
    file policy. Real key material and credential stores are still refused
    before any content is read.

    Args:
        text: File contents or command output.

    Returns:
        The text with recognized secret values masked.
    """
    if not text:
        return text

    lines = [_redact_line(line) for line in text.splitlines()]
    redacted = "\n".join(lines)
    if text.endswith("\n"):
        redacted += "\n"
    return redacted
