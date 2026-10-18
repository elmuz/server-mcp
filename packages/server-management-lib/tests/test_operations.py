"""Tests for the shared shell-safe Operation template."""

import shlex

from server_management_lib import Operation


def test_render_substitutes_values_literally():
    operation = Operation(("docker", "logs", "--tail", "$lines", "--", "$service"))

    assert operation.render(lines=10, service="myapp") == (
        "docker logs --tail 10 -- myapp"
    )


def test_render_quotes_values_that_could_be_shell_syntax():
    operation = Operation(("docker", "logs", "--", "$service"))

    command = operation.render(service="app; rm -rf /")

    assert command == "docker logs -- 'app; rm -rf /'"
    assert shlex.split(command)[-1] == "app; rm -rf /"


def test_operation_marks_write_actions():
    read = Operation(("docker", "ps"))
    write = Operation(("docker", "start", "$service"), read_only=False)

    assert read.read_only is True
    assert read.destructive is False
    assert write.read_only is False
