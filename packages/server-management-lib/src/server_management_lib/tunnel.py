"""
Optional SSH local port forwarding for loopback-only metric endpoints.

A metric service (InfluxDB, Prometheus) may listen only on the target host's
loopback interface.  In that case the MCP cannot reach it directly: the normal
mode is an HTTPS reverse proxy with a token.  This module lets the MCP create a
local tunnel through the configured SSH connection instead of requiring the
operator to keep ``ssh -N -L`` running by hand.

The tunnel is deliberately narrow:

- it listens on a loopback address only (never ``0.0.0.0``);
- it forwards to the host/port configured in the database section;
- it uses the same SSH settings (host key verification, key, agent) as the
  executor.
"""

import logging
from dataclasses import dataclass
from typing import Any

import asyncssh

from .security import SecurityValidator
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
MAX_PORT = 65535

# Section name -> default remote port.  The database port is the remote port
# when ``ssh_tunnel.remote_port`` is not set.
METRIC_SECTIONS: tuple[tuple[str, int], ...] = (
    ("influxdb", 8181),
    ("prometheus", 9090),
)


class SSHTunnelError(RuntimeError):
    """Raised when an SSH tunnel cannot be configured or opened."""


@dataclass(frozen=True)
class TunnelEndpoint:
    """Local address a tunnel is listening on."""

    host: str
    port: int


@dataclass(frozen=True)
class TunnelConfig:
    """Validated ``ssh_tunnel`` settings for one metric section."""

    remote_host: str
    remote_port: int
    local_host: str = "127.0.0.1"
    local_port: int = 0

    @classmethod
    def from_config(
        cls,
        value: Any,
        *,
        default_remote_port: int,
    ) -> "TunnelConfig":
        """Validate a raw ``ssh_tunnel`` mapping.

        ``default_remote_port`` is the database section's ``port`` (or its
        built-in default), so a minimal configuration only needs
        ``enabled: true``.
        """
        if not isinstance(value, dict):
            raise SSHTunnelError("ssh_tunnel must be a mapping")

        remote_host = _validate_host(
            value.get("remote_host", "127.0.0.1"),
            "ssh_tunnel.remote_host",
        )
        raw_remote_port = value.get("remote_port")
        if raw_remote_port is None:
            raw_remote_port = default_remote_port
        remote_port = _validate_port(
            raw_remote_port,
            "ssh_tunnel.remote_port",
            allow_zero=False,
        )
        local_host = _validate_host(
            value.get("local_host", "127.0.0.1"),
            "ssh_tunnel.local_host",
        )
        if local_host not in LOOPBACK_HOSTS:
            raise SSHTunnelError(
                "ssh_tunnel.local_host must be a loopback address "
                f"({', '.join(sorted(LOOPBACK_HOSTS))})"
            )
        local_port = _validate_port(
            value.get("local_port", 0),
            "ssh_tunnel.local_port",
            allow_zero=True,
        )
        return cls(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        )


def _validate_host(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise SSHTunnelError(f"{name} must be a hostname or IP address")
    host = value.strip()
    if not host:
        raise SSHTunnelError(f"{name} must not be empty")
    if len(host) > 253 or any(char.isspace() or ord(char) < 32 for char in host):
        raise SSHTunnelError(f"{name} contains an invalid character")
    return host


def _validate_port(value: Any, name: str, *, allow_zero: bool) -> int:
    if isinstance(value, bool):
        raise SSHTunnelError(f"{name} must be an integer between 0 and {MAX_PORT}")
    try:
        port = int(value)
    except (TypeError, ValueError) as e:
        raise SSHTunnelError(
            f"{name} must be an integer between 0 and {MAX_PORT}"
        ) from e
    minimum = 0 if allow_zero else 1
    if not minimum <= port <= MAX_PORT:
        raise SSHTunnelError(f"{name} must be between {minimum} and {MAX_PORT}")
    return port


class SSHTunnel:
    """One local port forward over a dedicated SSH connection."""

    def __init__(
        self,
        ssh_config: dict[str, Any],
        tunnel_config: dict[str, Any],
        *,
        default_remote_port: int,
    ):
        self.ssh_config = dict(ssh_config or {})
        self.config = TunnelConfig.from_config(
            tunnel_config,
            default_remote_port=default_remote_port,
        )
        self._manager: SSHManager | None = None
        self._listener: asyncssh.SSHListener | None = None

    async def start(self) -> TunnelEndpoint:
        """Open the SSH connection and the local listener."""
        manager = SSHManager({"ssh": self.ssh_config}, SecurityValidator({}))
        try:
            await manager.connect()
            connection = manager.connection
            if connection is None:
                raise SSHTunnelError("SSH connection failed")
            listener = await connection.forward_local_port(
                self.config.local_host,
                self.config.local_port,
                self.config.remote_host,
                self.config.remote_port,
            )
        except SSHTunnelError:
            await manager.disconnect()
            raise
        except Exception as e:
            await manager.disconnect()
            raise SSHTunnelError(f"Could not open SSH tunnel: {e}") from e

        self._manager = manager
        self._listener = listener
        port = listener.get_port() or self.config.local_port
        logger.info(
            "SSH tunnel listening on %s:%s for %s:%s",
            self.config.local_host,
            port,
            self.config.remote_host,
            self.config.remote_port,
        )
        return TunnelEndpoint(self.config.local_host, port)

    async def close(self) -> None:
        """Close the listener and the SSH connection (idempotent)."""
        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
            try:
                await listener.wait_closed()
            except Exception as e:  # pragma: no cover - best effort
                logger.debug("Error while closing SSH tunnel listener: %s", e)

        manager = self._manager
        self._manager = None
        if manager is not None:
            await manager.disconnect()

    async def __aenter__(self) -> TunnelEndpoint:
        return await self.start()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


@dataclass
class ActiveTunnel:
    """A tunnel opened from configuration and the endpoint it replaced."""

    section: str
    tunnel: SSHTunnel
    endpoint: TunnelEndpoint


async def open_metric_tunnels(config: dict[str, Any]) -> list[ActiveTunnel]:
    """Open tunnels for enabled ``influxdb``/``prometheus`` sections.

    The section's ``host``/``port`` are rewritten to the local tunnel endpoint
    so the existing HTTP clients can use them unchanged.  When any tunnel
    fails, all previously opened tunnels are closed before the error is
    re-raised.
    """
    ssh_config = config.get("ssh", {}) or {}
    pending: list[tuple[str, dict[str, Any], dict[str, Any], int]] = []

    # Validate every configured tunnel before opening any of them so a typo
    # cannot leave an earlier tunnel running.
    for section, default_port in METRIC_SECTIONS:
        section_config = config.get(section)
        if not isinstance(section_config, dict):
            continue
        if not section_config.get("enabled", False):
            continue
        tunnel_config = section_config.get("ssh_tunnel")
        if tunnel_config is None or tunnel_config is False:
            continue
        if not isinstance(tunnel_config, dict):
            raise SSHTunnelError(
                f"{section}.ssh_tunnel must be a mapping with enabled: true"
            )
        if not tunnel_config.get("enabled"):
            continue
        pending.append((section, section_config, tunnel_config, default_port))

    active: list[ActiveTunnel] = []
    try:
        for section, section_config, tunnel_config, default_port in pending:
            tunnel = SSHTunnel(
                ssh_config,
                tunnel_config,
                default_remote_port=section_config.get("port") or default_port,
            )
            endpoint = await tunnel.start()
            section_config["host"] = endpoint.host
            section_config["port"] = endpoint.port
            active.append(ActiveTunnel(section, tunnel, endpoint))
    except Exception:
        await close_metric_tunnels(active)
        raise

    return active


async def close_metric_tunnels(tunnels: list[ActiveTunnel]) -> None:
    """Close every tunnel opened by :func:`open_metric_tunnels`."""
    while tunnels:
        active = tunnels.pop()
        try:
            await active.tunnel.close()
        except Exception as e:  # pragma: no cover - best effort
            logger.debug("Error while closing %s tunnel: %s", active.section, e)
