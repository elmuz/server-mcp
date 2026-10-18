"""Structured tool responses shared by both MCP servers.

Tools keep returning a human-readable ``str`` so they stay easy to test and
log. The :func:`make_structured_tool` factory registers a second, MCP-facing
wrapper that returns :class:`ToolResponse`, which MCPServer exposes as
``structuredContent`` next to the usual text block. Callers that only read the
text content therefore see no change, while clients that understand structured
output can consume the typed envelope (``ok``, ``tool``, ``summary``,
``data``).

A tool can return :class:`ToolOutput` instead of a plain string when it has
machine-readable details to publish. The text wrapper unwraps it back to the
readable string.
"""

import functools
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

# The markers the tools use for failures. ``⚠️`` is a warning that still carries
# a usable result (for example a skipped SMART self-test), so only ``❌`` marks
# a response as not ok.
ERROR_PREFIX = "❌"


class ToolResponse(BaseModel):
    """Structured envelope returned by every MCP tool."""

    ok: bool = Field(description="False when the tool reported an error")
    tool: str = Field(description="Name of the tool that produced this response")
    summary: str = Field(
        default="", description="First line of the human-readable output"
    )
    text: str = Field(description="Human-readable output, identical to the text block")
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Machine-readable details when the tool has structured data",
    )


@dataclass(slots=True)
class ToolOutput:
    """Readable text plus optional structured details from a tool."""

    text: str
    ok: bool | None = None
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)


ToolResult = str | ToolOutput


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def _ok_from_text(text: str) -> bool:
    return not text.lstrip().startswith(ERROR_PREFIX)


def as_text(result: ToolResult) -> str:
    """Return the readable text of a tool result."""
    return result.text if isinstance(result, ToolOutput) else result


def build_response(tool: str, result: ToolResult) -> ToolResponse:
    """Build the structured envelope for a tool result."""
    if isinstance(result, ToolOutput):
        text = result.text
        ok = _ok_from_text(text) if result.ok is None else result.ok
        summary = result.summary or _first_line(text)
        data = dict(result.data)
    else:
        text = result
        ok = _ok_from_text(text)
        summary = _first_line(text)
        data = {}
    return ToolResponse(ok=ok, tool=tool, summary=summary, text=text, data=data)


RegisterTool = Callable[[str, Callable[..., Awaitable[ToolResponse]], Any], None]
ToolDecorator = Callable[[Callable[..., Awaitable[ToolResult]]], Callable[..., Any]]


def make_structured_tool(register_tool: RegisterTool) -> Callable[[Any], ToolDecorator]:
    """Return a ``@structured_tool(annotations)`` decorator for one MCP server.

    ``register_tool(name, wrapper, annotations)`` is supplied by the server and
    is responsible for handing the structured wrapper to MCPServer.
    """

    def structured_tool(annotations: Any) -> ToolDecorator:
        def decorator(
            fn: Callable[..., Awaitable[ToolResult]],
        ) -> Callable[..., Any]:
            tool_name = fn.__name__

            async def structured_call(*args: Any, **kwargs: Any) -> ToolResponse:
                return build_response(tool_name, await fn(*args, **kwargs))

            structured_call.__name__ = tool_name
            structured_call.__doc__ = fn.__doc__
            # publish the ToolResponse output schema while keeping the original
            # parameter annotations for the tool input schema
            structured_call.__signature__ = inspect.signature(fn).replace(  # type: ignore[attr-defined]
                return_annotation=ToolResponse
            )
            register_tool(tool_name, structured_call, annotations)

            @functools.wraps(fn)
            async def text_call(*args: Any, **kwargs: Any) -> str:
                return as_text(await fn(*args, **kwargs))

            return text_call

        return decorator

    return structured_tool
