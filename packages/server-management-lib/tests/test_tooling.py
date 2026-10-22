"""Tests for structured responses, rate limiting and the HTTP transport."""

import asyncio
import inspect
import sys
import types

import pytest

from server_management_lib.rate_limit import (
    RateLimitConfig,
    RateLimiter,
    create_rate_limiter,
)
from server_management_lib.responses import (
    ToolOutput,
    ToolResponse,
    as_text,
    build_response,
    make_structured_tool,
)
from server_management_lib.transport import (
    BearerTokenMiddleware,
    is_loopback_host,
    run_streamable_http,
    validate_http_binding,
)


class TestBuildResponse:
    def test_plain_string_success(self):
        response = build_response("list_services", "ok\nsecond line")

        assert response.ok is True
        assert response.tool == "list_services"
        assert response.summary == "ok"
        assert response.text == "ok\nsecond line"
        assert response.data == {}

    def test_error_marker_marks_not_ok(self):
        response = build_response("tool", "❌ failed")

        assert response.ok is False
        assert response.summary == "❌ failed"
        assert response.data["error"] == {
            "message": "❌ failed",
            "summary": "❌ failed",
        }

    def test_leading_whitespace_still_detects_error(self):
        assert build_response("tool", "\n  ❌ failed").ok is False

    def test_tool_output_uses_explicit_fields(self):
        result = ToolOutput(
            "⚠️ warning",
            ok=True,
            summary="custom summary",
            data={"count": 2},
        )

        response = build_response("tool", result)

        assert response.ok is True
        assert response.summary == "custom summary"
        assert response.data == {"count": 2}

    def test_tool_output_error_keeps_its_data_and_adds_an_error_object(self):
        result = ToolOutput(
            "❌ device unavailable",
            data={"device": "sda", "source": "smartctl"},
        )

        response = build_response("get_disk_health", result)

        assert response.ok is False
        assert response.data["device"] == "sda"
        assert response.data["error"]["message"] == "❌ device unavailable"

    def test_tool_output_defaults_and_data_copy(self):
        data = {"items": [1]}
        result = ToolOutput("done", data=data)

        response = build_response("tool", result)

        assert response.ok is True
        assert response.summary == "done"
        assert response.data == {"items": [1]}
        assert response.data is not data

    def test_empty_text_has_empty_summary(self):
        assert build_response("tool", "").summary == ""

    def test_as_text_unwraps_output(self):
        assert as_text("plain") == "plain"
        assert as_text(ToolOutput("wrapped")) == "wrapped"


class TestStructuredToolDecorator:
    def _decorator(self):
        registered = {}

        def register(name, wrapper, annotations):
            registered[name] = (wrapper, annotations)

        return make_structured_tool(register), registered

    def test_text_wrapper_keeps_original_interface(self):
        structured_tool, registered = self._decorator()

        @structured_tool("annotations")
        async def demo(value: int = 1) -> str:
            """Demo tool."""
            return f"value={value}"

        assert asyncio.run(demo(3)) == "value=3"
        wrapper, annotations = registered["demo"]
        assert annotations == "annotations"
        assert wrapper.__name__ == "demo"
        assert wrapper.__doc__ == "Demo tool."
        assert inspect.signature(wrapper).return_annotation is ToolResponse

    def test_structured_wrapper_returns_response(self):
        structured_tool, registered = self._decorator()

        @structured_tool(None)
        async def demo() -> ToolOutput:
            return ToolOutput("done", data={"ok": True})

        response = asyncio.run(registered["demo"][0]())

        assert isinstance(response, ToolResponse)
        assert response.data == {"ok": True}

    def test_structured_wrapper_unwraps_plain_error(self):
        structured_tool, registered = self._decorator()

        @structured_tool(None)
        async def demo() -> str:
            return "❌ nope"

        response = asyncio.run(registered["demo"][0]())

        assert response.ok is False


class TestRateLimitConfig:
    def test_defaults_without_section(self):
        settings = RateLimitConfig.from_config({})

        assert settings.enabled is True
        assert settings.max_calls == 10
        assert settings.window_seconds == 60.0

    def test_reads_valid_values(self):
        settings = RateLimitConfig.from_config(
            {"rate_limit": {"enabled": False, "max_calls": 3, "window_seconds": 5}}
        )

        assert settings.enabled is False
        assert settings.max_calls == 3
        assert settings.window_seconds == 5.0

    @pytest.mark.parametrize(
        "section",
        [
            "not a mapping",
            {"enabled": "yes", "max_calls": "x", "window_seconds": None},
            {"max_calls": 0, "window_seconds": -1},
        ],
    )
    def test_invalid_values_fall_back(self, section):
        settings = RateLimitConfig.from_config({"rate_limit": section})

        assert settings.enabled is True
        assert settings.max_calls == 10
        assert settings.window_seconds == 60.0

    def test_create_rate_limiter_respects_enabled(self):
        assert create_rate_limiter({}) is not None
        assert create_rate_limiter({"rate_limit": {"enabled": False}}) is None


class TestRateLimiter:
    def test_allows_up_to_the_limit_and_reports_retry(self):
        now = 0.0
        limiter = RateLimiter(2, 10, clock=lambda: now)

        assert limiter.check() is None
        assert limiter.check() is None
        assert limiter.check() == 10

        now = 4.0
        assert limiter.check() == 6

    def test_window_slides(self):
        now = 0.0
        limiter = RateLimiter(1, 10, clock=lambda: now)
        assert limiter.check() is None
        now = 11.0
        assert limiter.check() is None

    def test_reset_clears_calls(self):
        limiter = RateLimiter(1, 10, clock=lambda: 5.0)
        assert limiter.check() is None
        limiter.reset()
        assert limiter.check() is None

    @pytest.mark.parametrize(
        ("max_calls", "window"),
        [(0, 10), (1, 0), (-1, 10), (1, -1)],
    )
    def test_invalid_construction(self, max_calls, window):
        with pytest.raises(ValueError):
            RateLimiter(max_calls, window)

    def test_multiple_windows_recorded_calls_pruned(self):
        now = 0.0
        limiter = RateLimiter(2, 10, clock=lambda: now)
        limiter.check()
        now = 20.0
        assert limiter.check() is None
        assert limiter.check() is None


class TestTransportPolicy:
    def test_loopback_detection(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            assert is_loopback_host(host) is True
        assert is_loopback_host("0.0.0.0") is False

    def test_loopback_bind_needs_no_token(self):
        validate_http_binding("127.0.0.1", None)

    def test_public_bind_requires_token(self):
        with pytest.raises(ValueError, match="without an access token"):
            validate_http_binding("0.0.0.0", None)
        validate_http_binding("0.0.0.0", "secret")

    def test_middleware_requires_a_token(self):
        with pytest.raises(ValueError):
            BearerTokenMiddleware(object(), token="")


class TestBearerTokenMiddleware:
    def _call(self, token_header):
        calls = []

        async def app(scope, receive, send):
            calls.append(scope["path"])
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"ok"})

        sent = []

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": token_header,
        }
        middleware = BearerTokenMiddleware(app, token="secret")

        async def receive():
            return {}

        asyncio.run(middleware(scope, receive, send))
        return calls, sent

    def test_missing_token_returns_401(self):
        calls, sent = self._call([])

        assert calls == []
        assert sent[0]["status"] == 401
        assert (b"www-authenticate", b"Bearer") in sent[0]["headers"]

    def test_wrong_token_returns_401(self):
        calls, sent = self._call([(b"authorization", b"Bearer nope")])

        assert calls == []
        assert sent[0]["status"] == 401

    def test_correct_token_passes_through(self):
        calls, sent = self._call([(b"Authorization", b"Bearer secret")])

        assert calls == ["/mcp"]
        assert sent[0]["status"] == 200

    def test_non_http_scope_passes_through(self):
        called = []

        async def app(scope, receive, send):
            called.append(scope["type"])

        async def send(message):
            pass

        middleware = BearerTokenMiddleware(app, token="secret")

        async def receive():
            return {}

        asyncio.run(middleware({"type": "lifespan"}, receive, send))
        assert called == ["lifespan"]


class TestRunStreamableHttp:
    def _install_fake_uvicorn(self, monkeypatch):
        served = []

        class FakeServer:
            def __init__(self, config):
                self.config = config

            async def serve(self):
                served.append(self.config.app)

        class FakeConfig:
            def __init__(self, app, **kwargs):
                self.app = app
                self.kwargs = kwargs

        module = types.SimpleNamespace(Config=FakeConfig, Server=FakeServer)
        monkeypatch.setitem(sys.modules, "uvicorn", module)
        return served

    def _server(self):
        seen = {}

        class FakeMCP:
            def streamable_http_app(self, **kwargs):
                seen.update(kwargs)
                app = object()
                seen["app"] = app
                return app

        return FakeMCP(), seen

    def test_serves_the_app(self, monkeypatch):
        served = self._install_fake_uvicorn(monkeypatch)
        server, seen = self._server()

        asyncio.run(
            run_streamable_http(server, host="127.0.0.1", port=9000, path="/mcp")
        )

        assert seen["streamable_http_path"] == "/mcp"
        assert seen["host"] == "127.0.0.1"
        assert served == [seen["app"]]

    def test_wraps_with_token_middleware(self, monkeypatch):
        served = self._install_fake_uvicorn(monkeypatch)
        server, seen = self._server()

        asyncio.run(
            run_streamable_http(server, host="127.0.0.1", port=9000, token="secret")
        )

        assert isinstance(served[0], BearerTokenMiddleware)
        assert served[0].app is seen["app"]


class TestBearerCaseInsensitive:
    def test_lowercase_bearer_scheme_is_accepted(self):
        calls = []

        async def app(scope, receive, send):
            calls.append(scope["path"])
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"ok"})

        sent = []

        async def send(message):
            sent.append(message)

        middleware = BearerTokenMiddleware(app, token="secret")
        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", b"bearer secret")],
        }

        async def receive():
            return {}

        asyncio.run(middleware(scope, receive, send))

        assert calls == ["/mcp"]
        assert sent[0]["status"] == 200
