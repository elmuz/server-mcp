"""
Operation catalog for the remote-server MCP.

Commands are built as argument vectors and rendered with :func:`shlex.join`, so
no user-controlled value is ever concatenated into a shell string. Operations
also declare their safety level, which is used for MCP tool annotations and
audit records.
"""

import shlex
from dataclasses import dataclass

INSPECT_FORMAT = (
    "Name: {{.Name}}\n"
    "State: {{.State.Status}}\n"
    "Running: {{.State.Running}}\n"
    "RestartCount: {{.RestartCount}}\n"
    "StartedAt: {{.State.StartedAt}}"
)

STATS_FORMAT = "CPU: {{.CPUPerc}}\nMemory: {{.MemUsage}}\nNet I/O: {{.NetIO}}"


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
        def substitute(part: str) -> str:
            for key, value in params.items():
                part = part.replace(f"${key}", str(value))
            return part

        return shlex.join(substitute(part) for part in self.argv)


LS_SERVICES = Operation(("ls", "-1", "$path"))
DOCKER_PS = Operation(("docker", "ps", "--format", "{{.Names}}\t{{.Status}}"))
DOCKER_LOGS = Operation(("docker", "logs", "--tail", "$lines", "--", "$service"))
DOCKER_INSPECT = Operation(
    ("docker", "inspect", "--format", INSPECT_FORMAT, "--", "$service")
)
DOCKER_STATS = Operation(
    ("docker", "stats", "--no-stream", "--format", STATS_FORMAT, "--", "$service")
)
DOCKER_PORTS = Operation(("docker", "port", "--", "$service"))
DOCKER_RESTART = Operation(
    ("docker", "restart", "--", "$service"),
    read_only=False,
    destructive=True,
)
DOCKER_START = Operation(("docker", "start", "--", "$service"), read_only=False)
DOCKER_STOP = Operation(
    ("docker", "stop", "--", "$service"),
    read_only=False,
    destructive=True,
)

UPTIME = Operation(("uptime",))
FREE_MEMORY = Operation(("free", "-h"))
DISK_USAGE = Operation(("df", "-h", "$path"))


def docker_logs_grep(service: str, lines: int, pattern: str) -> str:
    """Log search: the only operation that intentionally uses a shell pipe."""
    logs = DOCKER_LOGS.render(service=service, lines=lines)
    return f"{logs} | grep -F {shlex.quote(pattern)}"
