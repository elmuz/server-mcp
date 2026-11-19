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
    """Mask every assignment value in a dotenv file (strict variant).

    Comments and blank lines are kept, but a recognized credential inside a
    comment (``# API_TOKEN=...``) is masked. Recognized assignments keep their
    key and separator (``KEY=***``). Any other non-empty line is treated as a
    value or a continuation of one (for example a multi-line quoted secret) and
    is masked entirely, so no value text can leak. A trailing newline in the
    input is preserved.

    This is the stricter whole-file variant. The MCP server uses
    :func:`redact_secrets` for ``.env`` reads so benign keys stay readable;
    this function remains public for callers that want every value masked.

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
        if not stripped:
            lines.append(line)
            continue
        if stripped.startswith("#"):
            lines.append(_redact_line(line))
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

# A comment line. The marker is kept so the comment stays recognizable while
# its body is still checked for credentials.
_COMMENT_LINE = re.compile(r"^(?P<indent>\s*)(?P<marker>#|;|//)(?P<body>.*)$")

# YAML block scalar header (``key: |``, ``key: >-``, ``key: |2``). The value
# lives on the following, more-indented lines, so the header alone is not
# enough to hide it.
_BLOCK_SCALAR = re.compile(
    r"^(?P<indent>\s*)(?:-\s*)?(?P<key>\"?[A-Za-z0-9_.-]+\"?)\s*[:=]\s*"
    r"(?P<indicator>[|>](?:[+-]?\d?|\d?[+-]?))\s*(?:#.*)?$"
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


def _redact_content(line: str) -> str:
    """Redact credentials in a single line of non-comment content."""
    if not line:
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


# A block-scalar header can itself be commented out, so a credential that was
# disabled in the file (``# api_token: |``) still owns the value lines below it.
# The header's key column is measured after the comment marker, and a value line
# is part of the scalar when its own content starts further right.
def _content_column(line: str) -> int:
    """Return the column where the line's content starts, ignoring a comment marker."""
    comment = _COMMENT_LINE.match(line)
    if comment is None:
        return len(line) - len(line.lstrip())
    body = comment.group("body")
    return (
        len(comment.group("indent"))
        + len(comment.group("marker"))
        + len(body)
        - len(body.lstrip())
    )


def _block_scalar_header(line: str) -> tuple[int, str] | None:
    """Return ``(key column, key)`` when the line opens a block scalar."""
    header = _BLOCK_SCALAR.match(line)
    if header is not None:
        return len(header.group("indent")), header.group("key")

    comment = _COMMENT_LINE.match(line)
    if comment is None:
        return None
    header = _BLOCK_SCALAR.match(comment.group("body"))
    if header is None:
        return None
    marker_end = len(comment.group("indent")) + len(comment.group("marker"))
    return marker_end + len(header.group("indent")), header.group("key")


# A masked value line inside a commented-out scalar keeps its marker and
# indentation, so the shape of the file stays readable and the leaked value does
# not. Non-comment value lines are masked entirely, as before.
def _masked_block_value(line: str) -> str:
    comment = _COMMENT_LINE.match(line)
    if comment is None:
        return REDACTED_VALUE
    body = comment.group("body")
    spacing = body[: len(body) - len(body.lstrip())]
    return (
        f"{comment.group('indent')}{comment.group('marker')}{spacing}{REDACTED_VALUE}"
    )


def _redact_line(line: str) -> str:
    """Redact a line, including credentials inside a comment.

    The comment marker and indentation are preserved so ordinary comments stay
    readable, but a commented-out assignment such as ``# API_TOKEN=...`` is
    still masked.
    """
    if not line:
        return line

    comment = _COMMENT_LINE.match(line)
    if comment is not None:
        body = _redact_content(comment.group("body"))
        return f"{comment.group('indent')}{comment.group('marker')}{body}"

    return _redact_content(line)


def redact_secrets(text: str) -> str:
    """Mask credentials in service config files and host status/log output.

    The redactor handles YAML/INI/dotenv assignments, JSON members, command-line
    flags, inline ``KEY=value`` pairs, ``Authorization: Bearer`` values, JWT
    shapes and credentials embedded in URLs. Keys, comments and the surrounding
    structure stay readable; only the value is replaced with ``***``.

    Comment bodies are checked too, so a commented-out credential such as
    ``# API_TOKEN=...`` is masked while ordinary comments stay readable. YAML
    block scalars (``api_token: |``) are followed onto their indented value
    lines, which are masked entirely; a trailing comment on the header and a
    commented-out header (``# api_token: |``) both keep the value lines in
    scope. Unknown formats are handled
    conservatively: a sensitive key followed by a block-scalar indicator masks
    the indented lines even when the surrounding syntax is not YAML.

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

    lines: list[str] = []
    block_indent: int | None = None
    for line in text.splitlines():
        if block_indent is not None:
            if not line.strip():
                # Blank lines are part of the scalar but carry no secret.
                lines.append(line)
                continue
            if _content_column(line) > block_indent:
                lines.append(_masked_block_value(line))
                continue
            # Dedented: the block scalar ended before this line.
            block_indent = None

        lines.append(_redact_line(line))

        header = _block_scalar_header(line)
        if header is not None and _is_sensitive_key(header[1]):
            block_indent = header[0]

    redacted = "\n".join(lines)
    if text.endswith("\n"):
        redacted += "\n"
    return redacted
