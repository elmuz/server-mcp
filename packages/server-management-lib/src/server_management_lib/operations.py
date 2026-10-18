"""
Shell-safe command templates shared by the MCP tool catalogs.

Commands are argument vectors, never concatenated shell strings. ``render``
substitutes values literally and quotes the resulting vector with
:func:`shlex.join`, so a validated value cannot become shell syntax.
"""

import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class Operation:
    """A shell-safe command template.

    ``argv`` items may contain ``$name`` placeholders. Values are substituted
    literally and the resulting vector is quoted by :func:`shlex.join`.
    """

    argv: tuple[str, ...]
    read_only: bool = True
    destructive: bool = False

    def render(self, **params: str | int) -> str:
        """Render the template with ``params`` substituted literally."""

        def substitute(part: str) -> str:
            for key, value in params.items():
                part = part.replace(f"${key}", str(value))
            return part

        return shlex.join(substitute(part) for part in self.argv)
