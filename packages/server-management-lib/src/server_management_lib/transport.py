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
from typing import Any

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DEFAULT_HTTP_PATH = "/mcp"
DEFAULT_HTTP_PORT = 8000


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
        "(transport.token, MCP_HTTP_TOKEN or --http-token-env)."
    )


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
    path: str = DEFAULT_HTTP_PATH,
    json_response: bool = False,
) -> None:
    """Serve an MCPServer over Streamable HTTP with the safety rules above."""
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
