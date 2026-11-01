"""Streamable HTTP transport helpers for the MCP servers.

The default transport stays stdio. When an operator opts into Streamable HTTP,
this module enforces two rules:

- a non-loopback bind address requires a bearer token;
- when a token is configured, every HTTP request must present it.

The middleware is a plain ASGI application, so the library does not depend on
Starlette. Uvicorn is imported lazily where it is actually used (it is already
a dependency of the ``mcp`` package that the servers install).
"""

import hmac
import logging
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DEFAULT_HTTP_PATH = "/mcp"
DEFAULT_HTTP_PORT = 8000
# A bearer token is a short opaque string. Refuse huge files instead of reading
# an accidentally mounted secret store into memory.
TOKEN_FILE_MAX_BYTES = 4096


def is_loopback_host(host: str) -> bool:
    """Return True when ``host`` is a loopback bind address."""
    return host in LOOPBACK_HOSTS


def validate_http_binding(host: str, token: str | None) -> None:
    """Refuse a non-loopback Streamable HTTP bind without a token.

    Raises:
        ValueError: The binding would expose the tools unauthenticated.
    """
    if is_loopback_host(host) or token:
        return
    raise ValueError(
        f"Refusing to bind Streamable HTTP to '{host}' without an access token. "
        "Use a loopback host (127.0.0.1/::1/localhost) or configure a token "
        "(transport.token, MCP_HTTP_TOKEN, transport.token_file or "
        "--http-token-file)."
    )


def load_http_token_file(path: str | Path) -> str:
    """Read and validate a bearer-token file.

    The file is intentionally treated as a secret: it must be a regular file,
    must not be readable by group/other, and must contain one non-empty token.

    Raises:
        ValueError: The file is missing, not a regular file, too large, empty,
            or has unsafe permissions.
    """
    token_path = Path(path).expanduser()
    try:
        info = token_path.stat()
    except OSError as e:
        raise ValueError(f"Cannot read HTTP token file {token_path}: {e}") from e

    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"HTTP token file is not a regular file: {token_path}")
    if info.st_mode & 0o077:
        raise ValueError(
            f"HTTP token file {token_path} is accessible by group/other; "
            "set mode 0600 (or 0400)"
        )
    if info.st_size > TOKEN_FILE_MAX_BYTES:
        raise ValueError(
            f"HTTP token file {token_path} is larger than {TOKEN_FILE_MAX_BYTES} bytes"
        )

    try:
        raw = token_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"Cannot read HTTP token file {token_path}: {e}") from e

    token = raw.strip()
    if not token:
        raise ValueError(f"HTTP token file {token_path} is empty")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in token):
        raise ValueError(f"HTTP token file {token_path} contains a control character")
    return token


def resolve_http_token(token: str | None, token_file: str | Path | None) -> str | None:
    """Resolve the bearer token from inline configuration or a file.

    A token file takes precedence over an inline token so a container can mount
    the credential without putting it in the process environment. A warning is
    emitted when both are set, but neither value is logged.
    """
    if token_file:
        if token:
            logger.warning(
                "Both transport.token and transport.token_file are configured; "
                "using the token file"
            )
        return load_http_token_file(token_file)
    return token or None


class BearerTokenMiddleware:
    """Reject HTTP requests that do not carry the configured bearer token."""

    def __init__(self, app: Any, *, token: str, header: str = "authorization"):
        if not token:
            raise ValueError("A non-empty token is required")
        self.app = app
        self.token = token
        self.header = header.lower().encode("latin-1")
        self._token = token.encode("utf-8")

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        provided = b""
        for name, value in scope.get("headers") or []:
            if name.lower() == self.header:
                provided = value
                break

        # RFC 9110 auth schemes are case-insensitive: ``bearer`` and ``Bearer``
        # are equivalent. The credential itself is compared in constant time.
        scheme = b""
        credential = b""
        if provided:
            parts = provided.split(None, 1)
            if len(parts) == 2:
                scheme, credential = parts

        if scheme.lower() != b"bearer" or not hmac.compare_digest(
            credential, self._token
        ):
            logger.warning("Rejected unauthenticated Streamable HTTP request")
            body = b'{"error":"unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)


async def run_streamable_http(
    server: Any,
    *,
    host: str = "127.0.0.1",
    port: int = DEFAULT_HTTP_PORT,
    token: str | None = None,
    token_file: str | Path | None = None,
    path: str = DEFAULT_HTTP_PATH,
    json_response: bool = False,
) -> None:
    """Serve an MCPServer over Streamable HTTP with the safety rules above."""
    token = resolve_http_token(token, token_file)
    validate_http_binding(host, token)

    import uvicorn

    app = server.streamable_http_app(
        streamable_http_path=path,
        json_response=json_response,
        host=host,
    )
    if token:
        app = BearerTokenMiddleware(app, token=token)

    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    logger.info(
        "Serving Streamable HTTP on %s:%d%s (bearer token: %s)",
        host,
        port,
        path,
        "required" if token else "not set, loopback only",
    )
    await uvicorn.Server(config).serve()
