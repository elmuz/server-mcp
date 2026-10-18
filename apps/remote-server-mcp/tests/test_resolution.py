"""
Tests for service/container resolution.

The resolver is pure logic on top of ``docker ps -a`` output plus the executor
interface, so these tests need no SSH connection or Docker daemon.
"""

import asyncio

import pytest

from remote_server_mcp.resolution import (
    Container,
    ResolutionError,
    collect_containers,
    collect_service_directories,
    command_failure,
    format_container_table,
    parse_container_listing,
    resolve_service_target,
    service_target,
)
from server_management_lib import SecurityValidator

BASE_PATH = "/srv"

LISTING = (
    "immich-server\timmich\tUp 2 days\n"
    "immich-postgres\timmich\tUp 2 days (healthy)\n"
    "dawarich-sidekiq\tdawarich\tUp 1 hour\n"
    "watchtower\t\tUp 3 days\n"
)


class FakeExecutor:
    """Minimal executor implementing the two methods the resolver uses."""

    def __init__(
        self,
        listing: str = LISTING,
        directories=("immich", "dawarich"),
        dirs_listing: str = "",
    ):
        self.listing = listing
        self.directories = set(directories)
        self.dirs_listing = dirs_listing
        self.commands: list[str] = []

    async def execute_safe_command(self, command: str, timeout: int = 30) -> str:
        self.commands.append(command)
        if command.startswith("ls -1"):
            return self.dirs_listing
        return self.listing

    async def check_service_exists(self, service: str) -> bool:
        return service in self.directories


def resolve(target: str, *, executor=None, config=None):
    executor = executor or FakeExecutor()
    security = SecurityValidator(config or {"security": {"services_path": BASE_PATH}})
    return asyncio.run(resolve_service_target(executor, security, target))


class TestCommandFailure:
    def test_error_marker_is_a_failure(self):
        assert command_failure("❌ connection failed") is not None

    def test_nonzero_exit_code_is_a_failure(self):
        output = "some output\n\n⚠️ Exit code: 1"
        assert command_failure(output) is not None

    def test_zero_exit_code_is_success(self):
        assert command_failure("some output\n\n⚠️ Exit code: 0") is None

    def test_plain_output_is_success(self):
        assert command_failure("immich-server\timmich\tUp") is None


class TestParsing:
    def test_parses_name_project_and_status(self):
        assert parse_container_listing(LISTING) == [
            Container("immich-server", "immich", "Up 2 days"),
            Container("immich-postgres", "immich", "Up 2 days (healthy)"),
            Container("dawarich-sidekiq", "dawarich", "Up 1 hour"),
            Container("watchtower", "", "Up 3 days"),
        ]

    def test_ignores_error_and_blank_lines(self):
        output = "\n❌ docker unavailable\n\t\t\nstandalone\t\tExited (1)\n"
        assert parse_container_listing(output) == [
            Container("standalone", "", "Exited (1)")
        ]

    def test_collect_containers_reports_failures(self):
        executor = FakeExecutor(listing="❌ permission denied")
        with pytest.raises(ResolutionError, match="Could not list Docker"):
            asyncio.run(collect_containers(executor))


class TestServiceDirectoryResolution:
    def test_directory_maps_to_compose_project_containers(self):
        resolution = resolve("immich")

        assert resolution.service == "immich"
        assert resolution.containers == ("immich-server", "immich-postgres")
        assert resolution.source == "service"
        assert resolution.multiple is True

    def test_directory_without_project_label_falls_back_to_name(self):
        executor = FakeExecutor(
            listing="grafana\t\tUp 2 days\nother\tother\tUp\n",
            directories={"grafana"},
        )

        resolution = resolve("grafana", executor=executor)

        assert resolution.containers == ("grafana",)

    def test_directory_with_unrelated_containers_is_rejected(self):
        executor = FakeExecutor(
            listing="immich-server\timmich\tUp\n",
            directories={"orphan"},
        )

        with pytest.raises(ResolutionError, match="no Docker container is associated"):
            resolve("orphan", executor=executor)

    def test_empty_listing_keeps_legacy_container_name(self):
        executor = FakeExecutor(listing="", directories={"legacy"})

        resolution = resolve("legacy", executor=executor)

        assert resolution.containers == ("legacy",)
        assert resolution.source == "service"


class TestContainerNameResolution:
    def test_container_name_requires_its_project_directory(self):
        executor = FakeExecutor(directories={"immich"})

        resolution = resolve("immich-postgres", executor=executor)

        assert resolution.service == "immich"
        assert resolution.containers == ("immich-postgres",)
        assert resolution.source == "container"

    def test_container_name_can_be_allowlisted(self):
        executor = FakeExecutor(directories=set())
        config = {
            "security": {
                "services_path": BASE_PATH,
                "allowed_containers": ["watchtower"],
            }
        }

        resolution = resolve("watchtower", executor=executor, config=config)

        assert resolution.containers == ("watchtower",)
        assert resolution.source == "allowlist"

    def test_unknown_container_is_rejected(self):
        with pytest.raises(ResolutionError, match="Unknown service or container"):
            resolve("does-not-exist")

    def test_container_outside_services_path_is_rejected(self):
        with pytest.raises(ResolutionError, match="not backed by a service directory"):
            resolve("watchtower")

    def test_invalid_project_label_cannot_authorize_a_container(self):
        executor = FakeExecutor(
            listing="rogue\t../../etc\tUp 1 minute\n",
            directories=set(),
        )

        with pytest.raises(ResolutionError, match="not backed by a service directory"):
            resolve("rogue", executor=executor)

    def test_resolution_lists_containers_once(self):
        executor = FakeExecutor()
        resolve("immich-server", executor=executor)

        ps_commands = [c for c in executor.commands if c.startswith("docker ps -a")]
        assert len(ps_commands) == 1


class TestServiceDirectories:
    def test_collects_only_directories(self):
        executor = FakeExecutor(dirs_listing="immich/\ndawarich/\nREADME.md\nlinkdir\n")
        security = SecurityValidator({"security": {"services_path": BASE_PATH}})

        directories = asyncio.run(collect_service_directories(executor, security))

        assert directories == {"immich", "dawarich"}
        assert executor.commands[0].startswith("ls -1 -p")

    def test_reports_listing_failure(self):
        executor = FakeExecutor(dirs_listing="⚠️ Exit code: 2")
        security = SecurityValidator({"security": {"services_path": BASE_PATH}})

        with pytest.raises(ResolutionError, match="Could not list service directories"):
            asyncio.run(collect_service_directories(executor, security))


class TestServiceTarget:
    def test_project_with_directory_is_the_target(self):
        assert service_target(Container("immich-server", "immich", ""), {"immich"}) == (
            "immich"
        )

    def test_container_name_with_directory_is_the_target(self):
        assert service_target(Container("deluge", "", ""), {"deluge"}) == "deluge"

    def test_allowlist_wins_over_project(self):
        container = Container("watchtower", "tools", "")

        assert service_target(container, {"tools"}, frozenset({"watchtower"})) == (
            "(allowlisted)"
        )

    def test_project_without_directory_is_flagged(self):
        assert service_target(Container("orphan", "gone", ""), {"other"}) == (
            "(no directory)"
        )

    def test_standalone_container_without_directory_is_unknown(self):
        assert service_target(Container("standalone", "", ""), {"other"}) == "-"


class TestContainerTable:
    def test_maps_projects_and_marks_allowlisted_containers(self):
        table = format_container_table(
            parse_container_listing(LISTING),
            directories={"immich", "dawarich"},
            allowed_containers=frozenset({"watchtower"}),
        )

        assert "NAME" in table
        assert "PROJECT" in table
        assert "SERVICE" in table
        assert "immich" in table
        assert "(allowlisted)" in table
        assert "watchtower" in table

    def test_handles_containers_without_project(self):
        table = format_container_table(
            [Container("standalone", "", "Exited (1)")],
            directories={"standalone"},
        )

        assert "standalone" in table
        assert "Exited (1)" in table
