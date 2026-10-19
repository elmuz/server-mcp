"""
Tests for RSM tool command construction.

No SSH connection is made: the SSH manager is replaced with an AsyncMock and
the exact command strings are asserted. This catches argument-order bugs such
as ``docker stats --no-stream -- <service> --format=...``.
"""

import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from remote_server_mcp import operations, server
from server_management_lib import (
    ConfigNotFoundError,
    LocalExecutor,
    Operation,
    RemoteDirEntry,
    SecurityValidator,
)


@pytest.fixture(autouse=True)
def restore_server_state():
    """Keep apply_config() from leaking into other tests."""
    original_config = dict(server.config)
    original_security = server.security
    original_executor = server.executor
    original_limiter = server.rate_limiter
    # Most tests exercise a single action; the limiter has its own tests.
    server.rate_limiter = None
    yield
    server.config.clear()
    server.config.update(original_config)
    server.security = original_security
    server.executor = original_executor
    server.rate_limiter = original_limiter


@pytest.fixture
def custom_security():
    return SecurityValidator({"security": {"services_path": "/opt/services"}})


@pytest.fixture
def patched(monkeypatch, custom_security):
    """Patch the module-level security/SSH objects used by the tools."""
    executor = AsyncMock()
    executor.check_service_exists.return_value = True
    executor.execute_safe_command.return_value = "ok"
    executor.read_remote_file.return_value = "file contents"
    executor.list_remote_dir.return_value = [
        RemoteDirEntry(
            name="config.yml",
            longname="-rw-r--r-- 1 app app 42 Jan  1 00:00 config.yml",
            size=42,
        )
    ]

    monkeypatch.setattr(server, "security", custom_security)
    monkeypatch.setattr(server, "executor", executor)
    return executor


def _commands(executor) -> list[str]:
    return [call.args[0] for call in executor.execute_safe_command.await_args_list]


class TestServicePathConsistency:
    def test_server_health_reports_configured_disk_paths(self, patched, monkeypatch):
        monkeypatch.setattr(
            server,
            "security",
            SecurityValidator(
                {
                    "security": {"services_path": "/srv"},
                    "health": {
                        "disk_paths": ["/", "/mnt/storage", "/mnt/storage/"],
                    },
                }
            ),
        )

        asyncio.run(server.get_server_health())

        disk_commands = [
            command for command in _commands(patched) if command.startswith("df ")
        ]
        assert disk_commands == ["df -h /", "df -h /mnt/storage"]

    def test_server_health_lists_unhealthy_containers(self, patched):
        async def fake_command(command: str) -> str:
            if "health=unhealthy" in command:
                return "app\tUp 5 minutes (unhealthy)"
            return "ok"

        patched.execute_safe_command.side_effect = fake_command

        result = asyncio.run(server.get_server_health())

        assert "=== Unhealthy Containers ===" in result
        assert "app\tUp 5 minutes (unhealthy)" in result
        assert any(
            "--filter health=unhealthy" in command for command in _commands(patched)
        )

    def test_list_services_uses_configured_base_path(self, patched):
        asyncio.run(server.list_services())

        assert "/opt/services/" in _commands(patched)[0]
        assert "/srv/" not in _commands(patched)[0]

    def test_list_service_files_uses_configured_base_path(self, patched):
        asyncio.run(server.list_service_files("app"))

        call = patched.list_remote_dir.await_args
        assert call.args[0] == "/opt/services/app"
        assert call.kwargs["allowed_base"] == "/opt/services/app"

    def test_list_service_files_reports_a_policy_block(self, patched):
        result = asyncio.run(server.list_service_files("app", "secrets"))

        assert "sensitive-file policy" in result
        assert "Invalid subdirectory" not in result
        patched.list_remote_dir.assert_not_awaited()

    def test_get_service_file_uses_configured_base_path(self, patched):
        result = asyncio.run(server.get_service_file("app", "config.yml"))

        call = patched.read_remote_file.await_args
        assert call.args[0] == "/opt/services/app/config.yml"
        assert call.kwargs["allowed_base"] == "/opt/services/app"
        assert result == "file contents"

    def test_env_file_is_returned_with_masked_values(self, patched):
        patched.read_remote_file.return_value = (
            "# compose stack\nDB_PASSWORD=hunter2\nDB_HOST=db\n"
        )

        result = asyncio.run(server.get_service_file("app", ".env"))

        assert "hunter2" not in result
        assert "DB_PASSWORD=***" in result
        assert "DB_HOST=***" in result
        assert "masked" in result

    def test_sensitive_file_reports_the_policy_not_an_invalid_path(self, patched):
        result = asyncio.run(server.get_service_file("app", "keys/server.key"))

        assert "sensitive-file policy" in result
        assert "Invalid file path" not in result
        patched.read_remote_file.assert_not_awaited()

    def test_traversal_still_reports_an_invalid_path(self, patched):
        result = asyncio.run(server.get_service_file("app", "../../etc/shadow"))

        assert "Invalid file path" in result
        assert "sensitive-file policy" not in result
        patched.read_remote_file.assert_not_awaited()

    def test_server_health_defaults_to_root_not_services_path(self, patched):
        asyncio.run(server.get_server_health())

        commands = "\n".join(_commands(patched))
        assert "df -h /" in commands
        assert "df -h /opt/services" not in commands


class TestDockerCommandConstruction:
    def test_docker_stats_flags_come_before_terminator(self, patched):
        asyncio.run(server.get_service_status("app"))

        stats = [c for c in _commands(patched) if c.startswith("docker stats")]
        assert stats, "expected a docker stats command"
        command = stats[0]
        assert "--format" in command
        assert command.index("--format") < command.index(" -- app")
        assert command.endswith("-- app")

    def test_service_is_quoted(self, patched):
        asyncio.run(server.restart_service("app", confirm=True))

        commands = _commands(patched)
        assert any("docker restart -- app" in command for command in commands)

    def test_negative_log_lines_are_clamped(self, patched):
        asyncio.run(server.get_service_logs("app", lines=-5))

        logs = [c for c in _commands(patched) if c.startswith("docker logs")]
        assert logs and "--tail 1 " in logs[0]

    def test_log_search_filters_without_a_shell_pipe(self, patched):
        patched.execute_safe_command.return_value = (
            "line one\nits fine here\nit's fine here\n"
        )

        result = asyncio.run(server.search_service_logs("app", "it's fine"))

        assert result == "it's fine here"
        assert all("grep" not in command for command in _commands(patched))

    def test_log_search_keeps_punctuation_exact(self, patched):
        patched.execute_safe_command.return_value = (
            "plain line\n!important #tag ~home it's fine\n"
        )

        result = asyncio.run(
            server.search_service_logs("app", "!important #tag ~home it's fine")
        )

        assert result == "!important #tag ~home it's fine"

    def test_docker_logs_include_timestamps(self, patched):
        asyncio.run(server.get_service_logs("app"))

        logs = [c for c in _commands(patched) if c.startswith("docker logs")]
        assert logs and "--timestamps" in logs[0]

    def test_logs_accept_since_and_until(self, patched):
        asyncio.run(
            server.get_service_logs(
                "app", lines=50, since="30m", until="2026-10-18T21:00:00Z"
            )
        )

        logs = [c for c in _commands(patched) if c.startswith("docker logs")]
        assert logs == [
            "docker logs --tail 50 --timestamps --since 30m "
            "--until 2026-10-18T21:00:00Z -- app"
        ]

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("since", "--help"),
            ("since", "yesterday"),
            ("until", "-1h"),
            ("until", "2026-10-18 21:00:00"),
        ],
    )
    def test_invalid_log_times_are_rejected_before_execution(
        self, patched, field, value
    ):
        kwargs = {field: value}

        result = asyncio.run(server.get_service_logs("app", **kwargs))

        assert f"Invalid {field} time" in result
        assert _commands(patched) == []

    def test_search_rejects_invalid_log_times(self, patched):
        result = asyncio.run(server.search_service_logs("app", "error", since="-1h"))

        assert "Invalid since time" in result
        assert _commands(patched) == []

    def test_stopped_container_reports_not_running(self, patched):
        def run(command: str) -> str:
            if command.startswith("docker inspect"):
                return "Running: false\nState: exited"
            if command.startswith("docker stats"):
                return "CPU: 0.00%\nMemory: 0B / 0B\nNet I/O: 0B / 0B"
            return ""

        patched.execute_safe_command.side_effect = run

        result = asyncio.run(server.get_service_status("app"))

        assert "Container is not running" in result
        assert "0B / 0B" not in result
        commands = _commands(patched)
        assert not [c for c in commands if c.startswith("docker stats")]
        assert not [c for c in commands if c.startswith("docker port")]

    def test_running_container_keeps_stats(self, patched):
        def run(command: str) -> str:
            if command.startswith("docker inspect"):
                return "Running: true\nState: running"
            if command.startswith("docker stats"):
                return "CPU: 2.00%\nMemory: 10MiB / 1GiB\nNet I/O: 1kB / 2kB"
            return ""

        patched.execute_safe_command.side_effect = run

        result = asyncio.run(server.get_service_status("app"))

        assert "Memory: 10MiB / 1GiB" in result
        assert "Container is not running" not in result
        commands = _commands(patched)
        assert [c for c in commands if c.startswith("docker stats")]
        assert [c for c in commands if c.startswith("docker port")]


class TestContainerHealth:
    def test_inspect_format_reports_health_fields(self):
        assert "Health:" in operations.INSPECT_FORMAT
        assert "FailingStreak:" in operations.INSPECT_FORMAT
        assert "ExitCode:" in operations.INSPECT_FORMAT

    def test_inspect_format_emits_newlines_from_template_actions(self):
        # `docker inspect` does not expand `\n` in the literal part of a
        # format string; it stays on one line and `_container_running` never
        # matches. The newline must come from a template action.
        assert '{{"\\n"}}' in operations.INSPECT_FORMAT
        assert operations.INSPECT_FORMAT.count('{{"\\n"}}') == 7
        assert "\\n" not in operations.INSPECT_FORMAT.replace('{{"\\n"}}', "")

    def test_stats_format_keeps_plain_escapes(self):
        # `docker stats` expands `\n` before parsing the template. A template
        # action would become a real newline inside the quoted literal and
        # fail with "unterminated quoted string", so this one must stay plain.
        assert "\\n" in operations.STATS_FORMAT
        assert '{{"\\n"}}' not in operations.STATS_FORMAT
        assert "\n" not in operations.STATS_FORMAT

    def test_get_container_health_returns_recent_probes(self, patched):
        health = {
            "Status": "unhealthy",
            "FailingStreak": 2,
            "Log": [
                {
                    "Start": "2026-10-18T10:00:00Z",
                    "ExitCode": 1,
                    "Output": "old probe",
                },
                {
                    "Start": "2026-10-18T10:01:00Z",
                    "ExitCode": 1,
                    "Output": "Process 'openvpn|wg' is not running",
                },
            ],
        }
        patched.execute_safe_command.return_value = json.dumps(health)

        result = asyncio.run(server.get_container_health("deluge", entries=1))

        assert "Status: unhealthy" in result
        assert "FailingStreak: 2" in result
        assert "Process 'openvpn|wg' is not running" in result
        assert "old probe" not in result
        command = patched.execute_safe_command.await_args.args[0]
        assert command.startswith("docker inspect --format")
        assert command.endswith(" -- deluge")

    def test_get_container_health_without_healthcheck(self, patched):
        patched.execute_safe_command.return_value = "null"

        result = asyncio.run(server.get_container_health("app"))

        assert "no healthcheck configured" in result

    def test_get_container_health_returns_docker_error(self, patched):
        patched.execute_safe_command.return_value = "error: no such object: app"

        result = asyncio.run(server.get_container_health("app"))

        assert result == "error: no such object: app"

    def test_entries_are_clamped(self, patched):
        probes = [
            {"Start": f"probe-{index}", "ExitCode": 0, "Output": ""}
            for index in range(25)
        ]
        health = {"Status": "healthy", "FailingStreak": 0, "Log": probes}
        patched.execute_safe_command.return_value = json.dumps(health)

        result = asyncio.run(server.get_container_health("app", entries=1000))

        assert "Last 20 probe(s):" in result
        assert "probe-5" in result
        assert "probe-4" not in result


MULTI_CONTAINER_LISTING = (
    "immich-server\timmich\tUp 2 days\n"
    "immich-postgres\timmich\tUp 2 days (healthy)\n"
    "immich-redis\timmich\tUp 2 days\n"
    "dawarich-sidekiq\tdawarich\tUp 1 hour\n"
    "watchtower\t\tUp 3 days\n"
    "vllm\t\tExited (1) 2 days ago"
)


def _dispatch(listing: str, default: str = "ok"):
    """Return a fake executor that serves the container listing on `docker ps`."""

    def run(command: str) -> str:
        if command.startswith("docker ps -a"):
            return listing
        if command.startswith("docker logs"):
            container = command.rsplit(" -- ", 1)[-1]
            return f"{container} log line\nboom here"
        return default

    return run


def _dispatch_with_dirs(listing: str, directories):
    """Serve a directory listing for `ls` and the container listing for `ps`."""
    base = _dispatch(listing)

    def run(command: str) -> str:
        if command.startswith("ls -1"):
            return "\n".join(f"{name}/" for name in directories)
        return base(command)

    return run


def _targets(commands: list[str], prefix: str) -> list[str]:
    return [
        command.rsplit(" -- ", 1)[-1]
        for command in commands
        if command.startswith(prefix)
    ]


class TestServiceResolution:
    def test_directory_resolves_compose_project_containers(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        asyncio.run(server.get_service_status("immich"))

        commands = _commands(patched)
        assert _targets(commands, "docker inspect") == [
            "immich-server",
            "immich-postgres",
            "immich-redis",
        ]
        assert not any("dawarich" in command for command in commands)

    def test_container_name_resolves_through_project_label(self, patched):
        patched.check_service_exists.side_effect = [False, True]
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.get_service_status("immich-server"))

        commands = _commands(patched)
        assert _targets(commands, "docker inspect") == ["immich-server"]
        assert "=== Docker Status ===" in result
        assert "=== Container:" not in result

    def test_service_without_associated_containers_is_rejected(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.get_service_status("orphan"))

        assert "no Docker container is associated" in result
        assert not any(c.startswith("docker inspect") for c in _commands(patched))

    def test_unknown_container_is_rejected(self, patched):
        patched.check_service_exists.return_value = False
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.get_service_status("does-not-exist"))

        assert "Unknown service or container" in result
        assert not any(c.startswith("docker inspect") for c in _commands(patched))

    def test_container_outside_services_path_is_rejected(self, patched):
        patched.check_service_exists.return_value = False
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.get_service_status("watchtower"))

        assert "not backed by a service directory" in result
        assert "security.allowed_containers" in result
        assert not any(c.startswith("docker inspect") for c in _commands(patched))

    def test_allowlisted_container_is_accepted(self, patched, monkeypatch):
        from server_management_lib import SecurityValidator

        security = SecurityValidator(
            {
                "security": {
                    "services_path": "/opt/services",
                    "allowed_containers": ["watchtower"],
                }
            }
        )
        monkeypatch.setattr(server, "security", security)
        patched.check_service_exists.return_value = False
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        asyncio.run(server.get_service_status("watchtower"))

        assert _targets(_commands(patched), "docker inspect") == ["watchtower"]

    def test_traversal_target_is_rejected_before_resolution(self, patched):
        result = asyncio.run(server.get_service_status("../../etc"))

        assert "Invalid service name" in result
        assert _commands(patched) == []
        patched.check_service_exists.assert_not_awaited()

    def test_multicontainer_logs_are_labelled(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.get_service_logs("immich", lines=10))

        assert "=== Container: immich-server ===" in result
        assert "=== Container: immich-postgres ===" in result
        assert "immich-redis log line" in result
        assert "dawarich" not in result

    def test_multicontainer_search_prefixes_container_names(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.search_service_logs("immich", "boom"))

        assert "[immich-server] boom here" in result
        assert "[immich-postgres] boom here" in result

    def test_logs_can_target_one_container_in_a_project(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(
            server.get_service_logs("immich", container="immich-postgres")
        )

        assert _targets(_commands(patched), "docker logs") == ["immich-postgres"]
        assert "immich-server log line" not in result
        assert "immich-postgres log line" in result

    def test_logs_reject_container_outside_the_project(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.get_service_logs("immich", container="deluge"))

        assert "is not part of 'immich'" in result
        assert "immich-server" in result
        assert not _targets(_commands(patched), "docker logs")

    def test_logs_reject_invalid_container_names(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(
            server.get_service_logs("immich", container="../../etc/passwd")
        )

        assert "Invalid container name" in result
        assert not _targets(_commands(patched), "docker logs")

    def test_restart_targets_every_project_container(self, patched):
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        result = asyncio.run(server.restart_service("immich", confirm=True))

        assert _targets(_commands(patched), "docker restart") == [
            "immich-server",
            "immich-postgres",
            "immich-redis",
        ]
        assert "restarted" in result

    def test_write_failure_is_not_reported_as_success(self, patched):
        def run(command: str) -> str:
            if command.startswith("docker ps -a"):
                return MULTI_CONTAINER_LISTING
            if command.endswith(" -- immich-redis"):
                return "error\n\n⚠️ Exit code: 1"
            return "ok"

        patched.execute_safe_command.side_effect = run

        result = asyncio.run(server.restart_service("immich", confirm=True))

        assert "⚠️ Service 'immich' restarted with failures: immich-redis" in result
        assert "✅" not in result

    def test_start_and_stop_use_resolved_containers(self, patched):
        patched.check_service_exists.side_effect = [False, True, False, True]
        patched.execute_safe_command.side_effect = _dispatch(MULTI_CONTAINER_LISTING)

        asyncio.run(server.start_service("immich-server"))
        asyncio.run(server.stop_service("immich-postgres", confirm=True))

        commands = _commands(patched)
        assert _targets(commands, "docker start") == ["immich-server"]
        assert _targets(commands, "docker stop") == ["immich-postgres"]


class TestListContainers:
    def test_includes_stopped_and_crashed_containers(self, patched):
        patched.execute_safe_command.side_effect = _dispatch_with_dirs(
            MULTI_CONTAINER_LISTING, {"immich", "watchtower"}
        )

        result = asyncio.run(server.list_containers())

        assert "Docker Containers (6)" in result
        assert "vllm" in result
        assert "Exited (1) 2 days ago" in result
        assert "immich" in result
        assert "watchtower" in result

        immich_row = next(
            line for line in result.splitlines() if line.startswith("immich-server")
        )
        watchtower_row = next(
            line for line in result.splitlines() if line.startswith("watchtower")
        )
        assert "immich" in immich_row
        assert "watchtower" in watchtower_row

        commands = _commands(patched)
        assert commands[0].startswith("docker ps -a")
        assert "com.docker.compose.project" in commands[0]
        assert any(command.startswith("ls -1 -p") for command in commands)

    def test_allowlisted_container_is_marked(self, patched, monkeypatch):
        from server_management_lib import SecurityValidator

        monkeypatch.setattr(
            server,
            "security",
            SecurityValidator({"security": {"allowed_containers": ["watchtower"]}}),
        )
        patched.execute_safe_command.side_effect = _dispatch_with_dirs(
            MULTI_CONTAINER_LISTING, set()
        )

        result = asyncio.run(server.list_containers())

        assert "(allowlisted)" in result

    def test_docker_error_is_reported(self, patched):
        patched.execute_safe_command.return_value = "❌ Cannot connect to Docker"

        result = asyncio.run(server.list_containers())

        assert "Could not list Docker containers" in result
        assert "Cannot connect to Docker" in result

    def test_directory_mapping_failure_is_reported(self, patched):
        def run(command: str) -> str:
            if command.startswith("docker ps -a"):
                return MULTI_CONTAINER_LISTING
            if command.startswith("ls -1"):
                return "ls: cannot access '/srv'\n\n⚠️ Exit code: 2"
            return "ok"

        patched.execute_safe_command.side_effect = run

        result = asyncio.run(server.list_containers())

        assert "Could not map service directories" in result
        assert "Docker Containers (6)" in result

    def test_no_containers(self, patched):
        patched.execute_safe_command.return_value = ""

        assert asyncio.run(server.list_containers()) == "No Docker containers found."


class TestOperationCatalog:
    def test_every_operation_passes_the_command_policy(self):
        security = SecurityValidator({})
        for name, operation in vars(operations).items():
            if not isinstance(operation, Operation):
                continue
            command = operation.render(
                service="app",
                lines=10,
                path="/srv/app",
                unit="telegraf",
                directory="/srv/app",
            )
            assert security.is_command_safe(command) is True, (name, command)

    def test_time_filtered_log_operations_pass_the_command_policy(self):
        security = SecurityValidator({})
        command = operations.docker_logs_operation(
            since="30m", until="2026-10-18T21:00:00Z"
        ).render(
            service="app",
            lines=10,
            since="30m",
            until="2026-10-18T21:00:00Z",
        )

        assert security.is_command_safe(command) is True
        assert "--since 30m" in command
        assert "--until 2026-10-18T21:00:00Z" in command


class TestToolAnnotations:
    def test_read_only_tools_are_annotated(self):
        tools = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}
        for name in (
            "list_services",
            "list_containers",
            "get_service_logs",
            "get_service_file",
            "get_container_health",
            "get_host_service_status",
            "get_host_service_logs",
        ):
            assert tools[name].annotations.read_only_hint is True
            assert tools[name].annotations.destructive_hint is False

    def test_destructive_tools_are_annotated(self):
        tools = {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}
        assert tools["restart_service"].annotations.read_only_hint is False
        assert tools["restart_service"].annotations.destructive_hint is True
        assert tools["stop_service"].annotations.destructive_hint is True
        assert tools["start_service"].annotations.destructive_hint is False


class TestHostServices:
    def test_status_uses_systemctl_for_allowlisted_unit(self, patched):
        result = asyncio.run(server.get_host_service_status("telegraf"))

        assert _commands(patched) == ["systemctl status --no-pager --full telegraf"]
        assert "=== Host Service: telegraf ===" in result

    def test_logs_use_journalctl_with_bounded_lines(self, patched):
        asyncio.run(server.get_host_service_logs("telegraf", lines=200))

        assert _commands(patched) == [
            "journalctl -u telegraf -n 200 --no-pager --output short-iso"
        ]

    def test_lines_are_clamped(self, patched):
        asyncio.run(server.get_host_service_logs("docker", lines=100000))

        assert "-n 1000 " in _commands(patched)[0]

    def test_arbitrary_units_are_rejected(self, patched):
        for unit in (
            "sshd",
            "telegraf;rm -rf /",
            "../../etc/passwd",
            "telegraf.service",
        ):
            result = asyncio.run(server.get_host_service_status(unit))
            assert "Host unit not allowed" in result

        assert _commands(patched) == []

    def test_rejection_lists_the_allowlist(self, patched):
        result = asyncio.run(server.get_host_service_logs("sshd"))

        assert "security.host_units" in result
        assert "telegraf" in result

    def test_configured_allowlist_is_honoured(self, patched, monkeypatch):
        monkeypatch.setattr(
            server,
            "security",
            SecurityValidator({"security": {"host_units": ["nginx"]}}),
        )

        asyncio.run(server.get_host_service_status("nginx"))

        assert _commands(patched) == ["systemctl status --no-pager --full nginx"]


class TestCompositeOutputCap:
    def test_list_service_files_is_capped_once(self, patched, monkeypatch):
        monkeypatch.setitem(server.config, "output", {"max_bytes": 200})
        patched.list_remote_dir.return_value = [
            RemoteDirEntry(
                name=f"file{i}.txt",
                longname=("-rw-r--r-- 1 app app " + "x" * 80 + f" file{i}.txt"),
                size=1,
            )
            for i in range(20)
        ]

        result = asyncio.run(server.list_service_files("app"))

        assert result.count("truncated to 200 bytes") == 1
        assert "tool output truncated to 200 bytes" in result


class TestConfigBootstrap:
    def test_apply_config_rebuilds_dependencies(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "ssh:\n"
            "  host: example.com\n"
            "security:\n"
            "  services_path: /data/srv\n"
            "influxdb:\n"
            "  enabled: false\n"
        )
        monkeypatch.setenv("REMOTE_SERVER_MCP_CONFIG", str(config_file))

        resolved = server.apply_config()

        assert resolved == config_file
        assert server.config["ssh"]["host"] == "example.com"
        assert server.executor.services_base_path == "/data/srv"

    def test_apply_config_missing_required_file_raises(self, tmp_path):
        with pytest.raises(ConfigNotFoundError):
            server.apply_config(tmp_path / "missing.yaml")

    def test_apply_config_can_select_local_executor(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("executor: local\nsecurity:\n  services_path: /srv\n")

        server.apply_config(config_file)

        assert isinstance(server.executor, LocalExecutor)
