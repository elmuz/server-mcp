"""
Operation catalog for the remote-server MCP.

Commands are built as argument vectors and rendered with :func:`shlex.join`, so
no user-controlled value is ever concatenated into a shell string. Operations
also declare their safety level, which is used for MCP tool annotations and
audit records.
"""

from server_management_lib import Operation

INSPECT_FORMAT = (
    "Name: {{.Name}}\n"
    "State: {{.State.Status}}\n"
    "Running: {{.State.Running}}\n"
    "Health: {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\n"
    "FailingStreak: "
    "{{if .State.Health}}{{.State.Health.FailingStreak}}{{else}}0{{end}}\n"
    "RestartCount: {{.RestartCount}}\n"
    "ExitCode: {{.State.ExitCode}}\n"
    "StartedAt: {{.State.StartedAt}}"
)

STATS_FORMAT = "CPU: {{.CPUPerc}}\nMemory: {{.MemUsage}}\nNet I/O: {{.NetIO}}"
HEALTH_FORMAT = "{{json .State.Health}}"

# One line per container, including stopped and crashed ones. The compose
# project label is how a service directory resolves to its containers.
CONTAINER_LIST_FORMAT = (
    '{{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Status}}'
)


ECHO_CONNECTION = Operation(("echo", "Connection successful"))
LS_SERVICES = Operation(("ls", "-1", "$path"))
# The trailing slash from -p distinguishes directories from plain files.
LS_SERVICE_DIRS = Operation(("ls", "-1", "-p", "$path"))
DOCKER_PS = Operation(("docker", "ps", "--format", "{{.Names}}\t{{.Status}}"))
DOCKER_PS_ALL = Operation(("docker", "ps", "-a", "--format", CONTAINER_LIST_FORMAT))
# Health status is only reported for containers with a healthcheck. Including
# stopped containers keeps a crashed or exited unhealthy service visible.
DOCKER_PS_UNHEALTHY = Operation(
    (
        "docker",
        "ps",
        "-a",
        "--filter",
        "health=unhealthy",
        "--format",
        "{{.Names}}\t{{.Status}}",
    )
)


def docker_logs_operation(
    *, since: str | None = None, until: str | None = None
) -> Operation:
    """Build a ``docker logs`` operation with optional time filters.

    ``--timestamps`` is always enabled so log lines can be correlated with
    host events. Time values are validated by the security layer before they
    reach this function.
    """
    argv = ["docker", "logs", "--tail", "$lines", "--timestamps"]
    if since:
        argv.extend(("--since", "$since"))
    if until:
        argv.extend(("--until", "$until"))
    argv.extend(("--", "$service"))
    return Operation(tuple(argv))


DOCKER_LOGS = docker_logs_operation()
DOCKER_INSPECT = Operation(
    ("docker", "inspect", "--format", INSPECT_FORMAT, "--", "$service")
)
DOCKER_STATS = Operation(
    ("docker", "stats", "--no-stream", "--format", STATS_FORMAT, "--", "$service")
)
DOCKER_PORTS = Operation(("docker", "port", "--", "$service"))
DOCKER_HEALTH = Operation(
    ("docker", "inspect", "--format", HEALTH_FORMAT, "--", "$service")
)
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

# Host infrastructure services are systemd units, not Docker containers. The
# unit name is validated against security.host_units before rendering.
SYSTEMCTL_STATUS = Operation(("systemctl", "status", "--no-pager", "--full", "$unit"))
JOURNALCTL_UNIT = Operation(
    (
        "journalctl",
        "-u",
        "$unit",
        "-n",
        "$lines",
        "--no-pager",
        "--output",
        "short-iso",
    )
)
