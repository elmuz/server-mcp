"""Runtime validation shared by the containerized MCP entry points.

``--check-config`` and the container startup path use this module to catch
mount and credential mistakes before the server tries to connect to a target.
It never opens an SSH connection.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .ssh_manager import DEFAULT_KNOWN_HOSTS, DISABLED_KNOWN_HOSTS
from .transport import resolve_http_token, validate_http_binding

HTTP_TRANSPORTS = frozenset({"streamable-http", "streamable_http", "http"})


@dataclass(frozen=True)
class RuntimeCheck:
    """Result of validating a loaded configuration."""

    executor: str
    transport: str
    token_source: str
    issues: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.issues


def _readable_file(path: str | Path, description: str) -> str | None:
    expanded = Path(str(path)).expanduser()
    if not expanded.is_file():
        return f"{description} not found or not a regular file: {expanded}"
    if not os.access(expanded, os.R_OK):
        return f"{description} is not readable: {expanded}"
    return None


def _audit_issue(config: dict, *, container: bool) -> tuple[str | None, str | None]:
    audit = config.get("audit", {}) or {}
    if not audit.get("enabled", False):
        return None, None

    raw_path = audit.get("path")
    if not raw_path:
        return "audit is enabled but audit.path is empty", None

    path = Path(str(raw_path)).expanduser()
    parent = path.parent
    if parent.exists():
        if not parent.is_dir():
            return f"audit.path parent is not a directory: {parent}", None
        if not os.access(parent, os.W_OK):
            return f"audit.path parent is not writable: {parent}", None
        return None, None

    if container:
        return (
            f"audit.path parent does not exist: {parent}. "
            "Mount the audit directory read-write at this path",
            None,
        )
    return None, f"audit.path parent does not exist and will be created: {parent}"


def collect_runtime_check(
    config: dict,
    *,
    container: bool = False,
    token_file_override: str | Path | None = None,
) -> RuntimeCheck:
    """Validate configuration that depends on the runtime environment.

    Args:
        config: A fully merged configuration dictionary.
        container: True when running from the MCP container image. In that
            mode ``executor: local`` is rejected and the audit directory must
            already be mounted.
        token_file_override: Optional CLI token-file path.

    Returns:
        A :class:`RuntimeCheck`. ``issues`` are fatal; ``warnings`` are
        actionable but do not prevent startup.
    """
    issues: list[str] = []
    warnings: list[str] = []

    executor = str(config.get("executor", "ssh")).strip().lower()
    if executor not in {"ssh", "local"}:
        issues.append(f"unknown executor {executor!r}; expected 'ssh' or 'local'")
    if container and executor == "local":
        issues.append(
            "executor: local is not supported inside the MCP container; "
            "use executor: ssh and connect to the target"
        )

    security_config = config.get("security", {}) or {}
    services_path = security_config.get("services_path", "/srv")
    if not isinstance(services_path, str) or not services_path.startswith("/"):
        issues.append("security.services_path must be an absolute path")

    if executor == "ssh":
        ssh_config = config.get("ssh", {}) or {}
        key_path = ssh_config.get("key_path")
        password = ssh_config.get("password")
        if key_path:
            issue = _readable_file(key_path, "ssh.key_path")
            if issue:
                issues.append(issue)
        elif not password:
            warnings.append(
                "ssh.key_path and ssh.password are unset; "
                "the server will use ssh-agent or ~/.ssh/config"
            )

        known_hosts = ssh_config.get("known_hosts", DEFAULT_KNOWN_HOSTS)
        if known_hosts is None or (
            isinstance(known_hosts, str)
            and known_hosts.strip().lower() in DISABLED_KNOWN_HOSTS
        ):
            warnings.append(
                "SSH host key verification is disabled; "
                "set ssh.known_hosts to a known_hosts file"
            )
        else:
            issue = _readable_file(known_hosts, "ssh.known_hosts")
            if issue:
                issues.append(issue)

    transport_config = config.get("transport", {}) or {}
    transport = str(transport_config.get("type", "stdio")).strip().lower()
    token_source = "none"
    token = None
    token_file = token_file_override or transport_config.get("token_file")
    if token_file:
        token_source = "file"
    elif transport_config.get("token"):
        token_source = "inline"

    if token_file or transport_config.get("token"):
        try:
            token = resolve_http_token(transport_config.get("token"), token_file)
        except ValueError as e:
            issues.append(str(e))

    if transport in HTTP_TRANSPORTS:
        host = str(transport_config.get("host", "127.0.0.1"))
        try:
            port = int(transport_config.get("port", 8000))
        except (TypeError, ValueError):
            port = 0
        path = str(transport_config.get("path", "/mcp"))
        if not 1 <= port <= 65535:
            issues.append(f"transport.port is outside 1..65535: {port}")
        if not path.startswith("/"):
            issues.append(f"transport.path must start with '/': {path}")
        try:
            validate_http_binding(host, token)
        except ValueError as e:
            issues.append(str(e))
    elif transport != "stdio":
        issues.append(
            f"unknown transport {transport!r}; expected stdio or streamable-http"
        )

    audit_issue, audit_warning = _audit_issue(config, container=container)
    if audit_issue:
        issues.append(audit_issue)
    if audit_warning:
        warnings.append(audit_warning)

    return RuntimeCheck(
        executor=executor,
        transport=transport,
        token_source=token_source,
        issues=tuple(issues),
        warnings=tuple(warnings),
    )
