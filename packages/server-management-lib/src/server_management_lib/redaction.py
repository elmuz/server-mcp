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

# Key names whose values are secrets. Keys are split into words on separators
# (``_``, ``-``, ``.``, ...) and each word is checked, so ``POSTGRES_PASSWORD``,
# ``GITHUB_TOKEN``, ``api_key``, ``db-pass`` and a bare INI ``pass`` are covered
# without treating unrelated ``*.key`` file names as secrets (that policy lives
# in ``security.BLOCKED_PATH_*``).
#
# Short generic names are matched as word suffixes rather than substrings:
# ``dbpass``/``smtpPass`` are credentials, while ``tokenizer`` and ``keyboard``
# are not. The trade-off is deliberate: ``bypass`` is masked too, because a
# spurious mask is harmless and a missed credential is not.
_SENSITIVE_KEY_WORDS: tuple[str, ...] = (
    "authorization",
    "credential",
    "credentials",
    "key",
    "pass",
    "passphrase",
    "passwd",
    "password",
    "pw",
    "pwd",
    "secret",
    "secrets",
    "token",
    "tokens",
)

# Word separators used when normalizing a key (``db_pass`` -> ``db``, ``pass``).
_KEY_SEPARATOR = re.compile(r"[^A-Za-z0-9]+")

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


def _key_words(key: str) -> list[str]:
    """Split a normalized key into lowercase words on non-alphanumerics."""
    return [word.lower() for word in _KEY_SEPARATOR.split(key) if word]


def _is_sensitive_key(key: str) -> bool:
    """Return True when an assignment key names a credential.

    The key is normalized (quotes and leading CLI dashes removed) and split
    into words. A word matches when it equals a sensitive name or ends with
    one, so separators and concatenation (``api_key``, ``apikey``,
    ``db-pass``, ``dbpass``) are all recognized.
    """
    cleaned = key.strip().strip("\"'").lstrip("-").strip()
    if not cleaned:
        return False
    words = _key_words(cleaned)
    if not words:
        return False
    # ``AUTH_TYPE`` and ``AUTH_USERNAME`` are diagnostics, not credentials. A
    # bare ``AUTH`` or a key whose last word is ``auth`` (``BASIC_AUTH``,
    # ``PROXY_AUTH``) still names a credential and is masked.
    if words[-1] == "auth":
        return True
    return any(word.endswith(_SENSITIVE_KEY_WORDS) for word in words)


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
