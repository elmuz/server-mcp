"""
Resolve a service directory or a container name to Docker containers.

A directory below ``services_path`` is a service. Its containers are
discovered through the ``com.docker.compose.project`` label, so the directory
and the container name no longer have to match. A container name is accepted
directly when it belongs to a service directory or is listed in
``security.allowed_containers``.

The resolver never builds a command from untrusted values: it only feeds
validated names into the operation catalog (``docker ps -a`` and
``test -d`` via the executor).
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from server_management_lib import Executor, SecurityValidator

from .operations import DEFAULT_CATALOG, LS_SERVICE_DIRS, ContainerCatalog

EXIT_CODE_PATTERN = re.compile(r"⚠️ Exit code:\s*(-?\d+)")
ERROR_MARKER = "❌"


class ResolutionError(RuntimeError):
    """Raised when a target cannot be resolved to an allowed container."""


@dataclass(frozen=True)
class Container:
    """One row from ``docker ps -a``."""

    name: str
    project: str
    status: str


@dataclass(frozen=True)
class Resolution:
    """The containers a service directory or container name maps to."""

    target: str
    service: str | None
    containers: tuple[str, ...]
    #: ``service`` (directory), ``container`` (via its compose project) or
    #: ``allowlist`` (``security.allowed_containers``).
    source: str

    @property
    def multiple(self) -> bool:
        return len(self.containers) > 1


def command_failure(output: str) -> str | None:
    """Return an error description when a command result represents a failure."""
    if ERROR_MARKER in output:
        return output.strip()
    match = EXIT_CODE_PATTERN.search(output)
    if match and int(match.group(1)) != 0:
        return output.strip()
    return None


def parse_container_listing(output: str) -> list[Container]:
    """Parse ``docker ps -a --format`` output into container records."""
    containers = []
    for line in output.splitlines():
        if not line.strip() or line.startswith(ERROR_MARKER):
            continue
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip():
            continue
        name = parts[0].strip()
        project = parts[1].strip() if len(parts) > 1 else ""
        status = parts[2].strip() if len(parts) > 2 else ""
        containers.append(Container(name=name, project=project, status=status))
    return containers


async def collect_containers(
    executor: Executor, catalog: ContainerCatalog = DEFAULT_CATALOG
) -> list[Container]:
    """List every container, including stopped and crashed ones."""
    output = await executor.execute_safe_command(catalog.ps_all.render())
    failure = command_failure(output)
    if failure is not None:
        raise ResolutionError(f"❌ Could not list Docker containers:\n{failure}")
    return parse_container_listing(output)


async def collect_service_directories(
    executor: Executor, security: SecurityValidator
) -> set[str]:
    """Return the directory names below ``services_path``."""
    base_path = security.services_base_path.rstrip("/") + "/"
    output = await executor.execute_safe_command(LS_SERVICE_DIRS.render(path=base_path))
    failure = command_failure(output)
    if failure is not None:
        raise ResolutionError(
            f"❌ Could not list service directories in {base_path}:\n{failure}"
        )
    return {
        line.strip().rstrip("/")
        for line in output.splitlines()
        if line.strip().endswith("/")
    }


def containers_for_service(
    containers: Iterable[Container], service: str
) -> list[Container]:
    """Return the containers of a compose project, falling back to its name."""
    by_project = [container for container in containers if container.project == service]
    if by_project:
        return by_project
    return [container for container in containers if container.name == service]


def _unknown_target(target: str, base_path: str) -> ResolutionError:
    return ResolutionError(
        f"❌ Unknown service or container: '{target}'\n"
        f"No directory at {base_path.rstrip('/')}/{target} and no Docker "
        f"container named '{target}'.\n"
        "Use list_services() for directories and list_containers() for "
        "Docker containers."
    )


def _service_without_containers(target: str, base_path: str) -> ResolutionError:
    return ResolutionError(
        f"❌ Service '{target}' exists in {base_path.rstrip('/')}/ but no Docker "
        "container is associated with it.\n"
        f"Expected a container whose com.docker.compose.project label or name "
        f"is '{target}'. Use list_containers() to inspect the labels."
    )


def _container_not_allowed(
    target: str, project: str, base_path: str
) -> ResolutionError:
    project_hint = (
        f"Its compose project is '{project}'."
        if project
        else "It is not part of a compose project."
    )
    return ResolutionError(
        f"❌ Container '{target}' is not backed by a service directory under "
        f"{base_path.rstrip('/')}/.\n"
        f"{project_hint}\n"
        "Create the matching directory or add the container name to "
        "security.allowed_containers."
    )


async def resolve_service_target(
    executor: Executor,
    security: SecurityValidator,
    target: str,
    catalog: ContainerCatalog = DEFAULT_CATALOG,
) -> Resolution:
    """Resolve a service directory or container name to allowed containers.

    The caller must validate ``target`` with
    :meth:`SecurityValidator.validate_service_name` first.
    """
    base_path = security.services_base_path
    is_service_dir = await executor.check_service_exists(target)
    containers = await collect_containers(executor, catalog)

    if is_service_dir:
        matches = containers_for_service(containers, target)
        if not matches:
            if containers:
                raise _service_without_containers(target, base_path)
            # An empty listing can mean "no containers" or an environment where
            # the listing could not be parsed. Keep the legacy behavior and let
            # Docker report the missing object.
            return Resolution(
                target=target,
                service=target,
                containers=(target,),
                source="service",
            )
        return Resolution(
            target=target,
            service=target,
            containers=tuple(container.name for container in matches),
            source="service",
        )

    match = next(
        (container for container in containers if container.name == target), None
    )
    if match is None:
        raise _unknown_target(target, base_path)

    if match.name in security.allowed_containers:
        return Resolution(
            target=target,
            service=match.project or None,
            containers=(match.name,),
            source="allowlist",
        )

    project = match.project
    if (
        project
        and security.validate_service_name(project)
        and await executor.check_service_exists(project)
    ):
        return Resolution(
            target=target,
            service=project,
            containers=(match.name,),
            source="container",
        )

    raise _container_not_allowed(target, project, base_path)


def service_target(
    container: Container,
    directories: set[str] | frozenset[str] = frozenset(),
    allowed_containers: frozenset[str] = frozenset(),
) -> str:
    """Return how a container can be addressed, or ``-`` when it cannot."""
    if container.name in allowed_containers:
        return "(allowlisted)"
    if container.project and container.project in directories:
        return container.project
    if container.name in directories:
        return container.name
    if container.project:
        return "(no directory)"
    return "-"


def format_container_table(
    containers: Sequence[Container],
    *,
    directories: set[str] | frozenset[str] = frozenset(),
    allowed_containers: frozenset[str] = frozenset(),
) -> str:
    """Render a readable ``docker ps -a`` table with a service mapping."""
    rows = [("NAME", "PROJECT", "SERVICE", "STATUS")]
    for container in sorted(containers, key=lambda item: item.name):
        rows.append(
            (
                container.name,
                container.project or "-",
                service_target(container, directories, allowed_containers),
                container.status or "-",
            )
        )

    widths = [max(len(row[index]) for row in rows) for index in range(3)]
    lines = []
    for row in rows:
        lines.append(
            "  ".join(row[index].ljust(widths[index]) for index in range(3))
            + f"  {row[3]}"
        )
    return "\n".join(lines)
