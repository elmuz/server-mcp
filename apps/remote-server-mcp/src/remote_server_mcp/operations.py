"""
Operation catalog for the remote-server MCP.

Commands are built as argument vectors and rendered with :func:`shlex.join`, so
no user-controlled value is ever concatenated into a shell string. Operations
also declare their safety level, which is used for MCP tool annotations and
audit records.

The container CLI is configurable (``container_runtime``): Docker, Podman and
nerdctl share the same command surface for the operations below. The module
level constants remain the Docker catalog for backwards compatibility and for
the command-policy tests.
"""

from dataclasses import dataclass

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


def container_logs_operation(
    *, runtime: str = "docker", since: str | None = None, until: str | None = None
) -> Operation:
    """Build a ``<runtime> logs`` operation with optional time filters.

    ``--timestamps`` is always enabled so log lines can be correlated with
    host events. Time values are validated by the security layer before they
    reach this function.
    """
    argv = [runtime, "logs", "--tail", "$lines", "--timestamps"]
    if since:
        argv.extend(("--since", "$since"))
    if until:
        argv.extend(("--until", "$until"))
    argv.extend(("--", "$service"))
    return Operation(tuple(argv))


@dataclass(frozen=True)
class ContainerCatalog:
    """Every container operation for one runtime."""

    runtime: str
    ps: Operation
    ps_all: Operation
    ps_unhealthy: Operation
    inspect: Operation
    stats: Operation
    ports: Operation
    health: Operation
    restart: Operation
    start: Operation
    stop: Operation
    compose_ps: Operation
    compose_pull: Operation
    compose_up: Operation
    compose_down: Operation

    def logs(self, *, since: str | None = None, until: str | None = None) -> Operation:
        return container_logs_operation(runtime=self.runtime, since=since, until=until)


def build_container_catalog(runtime: str = "docker") -> ContainerCatalog:
    """Build the container operation catalog for ``runtime``.

    ``runtime`` is validated by :class:`SecurityValidator` before it reaches
    this function; the command policy also rejects unknown runtimes.
    """
    return ContainerCatalog(
        runtime=runtime,
        ps=Operation((runtime, "ps", "--format", "{{.Names}}\t{{.Status}}")),
        ps_all=Operation((runtime, "ps", "-a", "--format", CONTAINER_LIST_FORMAT)),
        ps_unhealthy=Operation(
            (
                runtime,
                "ps",
                "-a",
                "--filter",
                "health=unhealthy",
                "--format",
                "{{.Names}}\t{{.Status}}",
            )
        ),
        inspect=Operation(
            (runtime, "inspect", "--format", INSPECT_FORMAT, "--", "$service")
        ),
        stats=Operation(
            (
                runtime,
                "stats",
                "--no-stream",
                "--format",
                STATS_FORMAT,
                "--",
                "$service",
            )
        ),
        ports=Operation((runtime, "port", "--", "$service")),
        health=Operation(
            (runtime, "inspect", "--format", HEALTH_FORMAT, "--", "$service")
        ),
        restart=Operation(
            (runtime, "restart", "--", "$service"),
            read_only=False,
            destructive=True,
        ),
        start=Operation((runtime, "start", "--", "$service"), read_only=False),
        stop=Operation(
            (runtime, "stop", "--", "$service"),
            read_only=False,
            destructive=True,
        ),
        # Compose commands are scoped to a service directory below
        # services_path. The security layer validates the directory and the
        # exact subcommand arguments.
        compose_ps=Operation(
            (
                runtime,
                "compose",
                "--project-directory",
                "$directory",
                "ps",
                "--format",
                "{{.Name}} {{.Status}}",
            )
        ),
        compose_pull=Operation(
            (runtime, "compose", "--project-directory", "$directory", "pull"),
            read_only=False,
        ),
        compose_up=Operation(
            (
                runtime,
                "compose",
                "--project-directory",
                "$directory",
                "up",
                "-d",
                "--remove-orphans",
            ),
            read_only=False,
        ),
        compose_down=Operation(
            (
                runtime,
                "compose",
                "--project-directory",
                "$directory",
                "down",
                "--remove-orphans",
            ),
            read_only=False,
            destructive=True,
        ),
    )


DEFAULT_CATALOG = build_container_catalog("docker")

ECHO_CONNECTION = Operation(("echo", "Connection successful"))
LS_SERVICES = Operation(("ls", "-1", "$path"))
# The trailing slash from -p distinguishes directories from plain files.
LS_SERVICE_DIRS = Operation(("ls", "-1", "-p", "$path"))
DOCKER_PS = DEFAULT_CATALOG.ps
DOCKER_PS_ALL = DEFAULT_CATALOG.ps_all
# Health status is only reported for containers with a healthcheck. Including
# stopped containers keeps a crashed or exited unhealthy service visible.
DOCKER_PS_UNHEALTHY = DEFAULT_CATALOG.ps_unhealthy
DOCKER_LOGS = DEFAULT_CATALOG.logs()
DOCKER_INSPECT = DEFAULT_CATALOG.inspect
DOCKER_STATS = DEFAULT_CATALOG.stats
DOCKER_PORTS = DEFAULT_CATALOG.ports
DOCKER_HEALTH = DEFAULT_CATALOG.health
DOCKER_RESTART = DEFAULT_CATALOG.restart
DOCKER_START = DEFAULT_CATALOG.start
DOCKER_STOP = DEFAULT_CATALOG.stop
COMPOSE_PS = DEFAULT_CATALOG.compose_ps
COMPOSE_PULL = DEFAULT_CATALOG.compose_pull
COMPOSE_UP = DEFAULT_CATALOG.compose_up
COMPOSE_DOWN = DEFAULT_CATALOG.compose_down

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


# Backwards-compatible alias used by the server and its tests.
def docker_logs_operation(
    *, since: str | None = None, until: str | None = None
) -> Operation:
    """Docker ``logs`` operation (kept for existing callers)."""
    return DEFAULT_CATALOG.logs(since=since, until=until)
