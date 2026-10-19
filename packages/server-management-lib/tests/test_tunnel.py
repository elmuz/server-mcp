"""Tests for the optional SSH metric tunnel (no network or real SSH)."""

import asyncio
from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server_management_lib.tunnel import (
    ActiveTunnel,
    SSHTunnel,
    SSHTunnelError,
    TunnelConfig,
    TunnelEndpoint,
    close_metric_tunnels,
    open_metric_tunnels,
)


class FakeListener:
    def __init__(self, port=45678):
        self._port = port
        self.close = MagicMock()
        self.wait_closed = AsyncMock(return_value=None)

    def get_port(self):
        return self._port


class FakeConnection:
    def __init__(self, listener=None, error=None):
        self.listener = listener or FakeListener()
        self.error = error
        self.forward_local_port = AsyncMock(
            side_effect=error, return_value=self.listener
        )


class FakeManager:
    instances: ClassVar[list] = []

    def __init__(self, config, security):
        self.config = config
        self.security = security
        self.connection = FakeConnection()
        self.connect = AsyncMock(return_value=None)
        self.disconnect = AsyncMock(return_value=None)
        FakeManager.instances.append(self)


class TestTunnelConfig:
    def test_minimal_config_uses_database_port(self):
        config = TunnelConfig.from_config({"enabled": True}, default_remote_port=8181)
        assert config == TunnelConfig(
            remote_host="127.0.0.1",
            remote_port=8181,
            local_host="127.0.0.1",
            local_port=0,
        )

    def test_none_remote_port_falls_back(self):
        config = TunnelConfig.from_config(
            {"enabled": True, "remote_port": None}, default_remote_port=9090
        )
        assert config.remote_port == 9090

    def test_explicit_values_and_string_port(self):
        config = TunnelConfig.from_config(
            {
                "enabled": True,
                "remote_host": "metrics.internal",
                "remote_port": "8181",
                "local_host": "::1",
                "local_port": "12345",
            },
            default_remote_port=1,
        )
        assert config == TunnelConfig("metrics.internal", 8181, "::1", 12345)

    @pytest.mark.parametrize("value", [None, [], "enabled"])
    def test_non_mapping_rejected(self, value):
        with pytest.raises(SSHTunnelError):
            TunnelConfig.from_config(value, default_remote_port=8181)

    @pytest.mark.parametrize(
        "host",
        [None, "", "   ", "bad host", "bad\nhost", "a" * 254],
    )
    def test_invalid_remote_host_rejected(self, host):
        with pytest.raises(SSHTunnelError):
            TunnelConfig.from_config({"remote_host": host}, default_remote_port=8181)

    def test_local_host_must_be_loopback(self):
        with pytest.raises(SSHTunnelError, match="loopback"):
            TunnelConfig.from_config(
                {"local_host": "0.0.0.0"}, default_remote_port=8181
            )

    @pytest.mark.parametrize("port", [True, "nope", 0, -1, 65536])
    def test_invalid_remote_port_rejected(self, port):
        with pytest.raises(SSHTunnelError):
            TunnelConfig.from_config({"remote_port": port}, default_remote_port=8181)

    @pytest.mark.parametrize("port", [True, "nope", -1, 65536])
    def test_invalid_local_port_rejected(self, port):
        with pytest.raises(SSHTunnelError):
            TunnelConfig.from_config({"local_port": port}, default_remote_port=8181)


class TestSSHTunnel:
    def test_start_and_close(self):
        ssh_config = {"host": "server.example.com", "username": "admin"}
        tunnel = SSHTunnel(
            ssh_config,
            {"remote_host": "127.0.0.1", "remote_port": 8181},
            default_remote_port=8181,
        )

        async def run():
            with patch("server_management_lib.tunnel.SSHManager", FakeManager):
                endpoint = await tunnel.start()
                manager = FakeManager.instances[-1]
                assert endpoint == TunnelEndpoint("127.0.0.1", 45678)
                assert manager.config == {"ssh": ssh_config}
                manager.connection.forward_local_port.assert_awaited_once_with(
                    "127.0.0.1", 0, "127.0.0.1", 8181
                )
                listener = manager.connection.listener
                await tunnel.close()
                listener.close.assert_called_once()
                listener.wait_closed.assert_awaited_once()
                manager.disconnect.assert_awaited_once()
                # Closing twice is harmless.
                await tunnel.close()

        asyncio.run(run())

    def test_context_manager(self):
        tunnel = SSHTunnel({}, {"remote_port": 8181}, default_remote_port=8181)

        async def run():
            with patch("server_management_lib.tunnel.SSHManager", FakeManager):
                async with tunnel as endpoint:
                    assert endpoint.port == 45678
                manager = FakeManager.instances[-1]
                manager.disconnect.assert_awaited_once()

        asyncio.run(run())

    def test_missing_connection_is_an_error(self):
        tunnel = SSHTunnel({}, {"remote_port": 8181}, default_remote_port=8181)

        class NoConnectionManager(FakeManager):
            def __init__(self, config, security):
                super().__init__(config, security)
                self.connection = None

        async def run():
            with patch("server_management_lib.tunnel.SSHManager", NoConnectionManager):
                with pytest.raises(SSHTunnelError, match="connection failed"):
                    await tunnel.start()
                manager = NoConnectionManager.instances[-1]
                manager.disconnect.assert_awaited_once()

        asyncio.run(run())

    def test_forwarding_failure_is_wrapped(self):
        tunnel = SSHTunnel({}, {"remote_port": 8181}, default_remote_port=8181)

        class FailingManager(FakeManager):
            def __init__(self, config, security):
                super().__init__(config, security)
                self.connection = FakeConnection(error=OSError("bind failed"))

        async def run():
            with patch("server_management_lib.tunnel.SSHManager", FailingManager):
                with pytest.raises(SSHTunnelError, match="bind failed"):
                    await tunnel.start()
                manager = FailingManager.instances[-1]
                manager.disconnect.assert_awaited_once()

        asyncio.run(run())

    def test_connect_failure_is_wrapped(self):
        tunnel = SSHTunnel({}, {"remote_port": 8181}, default_remote_port=8181)

        class ConnectFailingManager(FakeManager):
            def __init__(self, config, security):
                super().__init__(config, security)
                self.connect = AsyncMock(side_effect=OSError("refused"))

        async def run():
            with patch(
                "server_management_lib.tunnel.SSHManager",
                ConnectFailingManager,
            ):
                with pytest.raises(SSHTunnelError, match="refused"):
                    await tunnel.start()
                manager = ConnectFailingManager.instances[-1]
                manager.disconnect.assert_awaited_once()

        asyncio.run(run())


class WatchedConnection(FakeConnection):
    def __init__(self, drop_event=None, listener=None):
        super().__init__(listener=listener)
        self.drop_event = drop_event

    async def wait_closed(self):
        if self.drop_event is None:
            # The replacement connection stays alive until close() cancels the
            # monitor task.
            await asyncio.Event().wait()
        else:
            await self.drop_event.wait()


class ReconnectManager(FakeManager):
    def __init__(self, config, security):
        first = not FakeManager.instances
        super().__init__(config, security)
        self.connection = WatchedConnection(drop_event=RE_DROP if first else None)


RE_DROP: asyncio.Event | None = None


class TestTunnelReconnect:
    """A dropped SSH connection re-opens the forward on the same port."""

    def test_dropped_connection_reopens_forward(self):
        tunnel = SSHTunnel({}, {"remote_port": 8181}, default_remote_port=8181)

        async def run():
            global RE_DROP
            RE_DROP = asyncio.Event()
            FakeManager.instances.clear()
            with patch("server_management_lib.tunnel.SSHManager", ReconnectManager):
                try:
                    endpoint = await tunnel.start()
                    assert len(FakeManager.instances) == 1

                    RE_DROP.set()
                    for _ in range(100):
                        if len(FakeManager.instances) >= 2:
                            break
                        await asyncio.sleep(0.01)

                    assert len(FakeManager.instances) == 2
                    replacement = FakeManager.instances[1]
                    replacement.connect.assert_awaited_once()
                    replacement.connection.forward_local_port.assert_awaited_once_with(
                        "127.0.0.1",
                        endpoint.port,
                        "127.0.0.1",
                        8181,
                    )
                    assert tunnel.down is False
                    assert tunnel.last_error is None
                finally:
                    await tunnel.close()

        asyncio.run(run())

    def test_reconnect_failure_is_reported_and_retried(self):
        tunnel = SSHTunnel({}, {"remote_port": 8181}, default_remote_port=8181)

        class FailingReconnectManager(ReconnectManager):
            def __init__(self, config, security):
                super().__init__(config, security)
                if len(FakeManager.instances) > 1:
                    self.connect = AsyncMock(side_effect=OSError("refused"))

        async def run():
            global RE_DROP
            RE_DROP = asyncio.Event()
            FakeManager.instances.clear()
            with patch(
                "server_management_lib.tunnel.SSHManager",
                FailingReconnectManager,
            ):
                try:
                    await tunnel.start()
                    RE_DROP.set()
                    for _ in range(100):
                        if tunnel.down:
                            break
                        await asyncio.sleep(0.01)

                    assert tunnel.down is True
                    assert "refused" in (tunnel.last_error or "")
                finally:
                    await tunnel.close()

        asyncio.run(run())


class FakeTunnel:
    def __init__(self, section, should_fail=False):
        self.section = section
        self.should_fail = should_fail
        self.start = AsyncMock(side_effect=self._start)
        self.close = AsyncMock(return_value=None)

    async def _start(self):
        if self.should_fail:
            raise SSHTunnelError(f"{self.section} failed")
        return TunnelEndpoint("127.0.0.1", 45678)


class TestMetricTunnels:
    def test_only_enabled_sections_are_tunnelled(self):
        config = {
            "ssh": {"host": "server.example.com"},
            "influxdb": {
                "enabled": True,
                "host": "influxdb.example.com",
                "port": 443,
                "ssh_tunnel": {"enabled": True},
            },
            "prometheus": {
                "enabled": False,
                "host": "prometheus.example.com",
                "port": 443,
                "ssh_tunnel": {"enabled": False},
            },
        }
        fake = FakeTunnel("influxdb")

        async def run():
            with patch(
                "server_management_lib.tunnel.SSHTunnel",
                MagicMock(return_value=fake),
            ):
                active = await open_metric_tunnels(config)
            assert len(active) == 1
            assert active[0].section == "influxdb"
            assert config["influxdb"]["host"] == "127.0.0.1"
            assert config["influxdb"]["port"] == 45678
            assert config["prometheus"]["host"] == "prometheus.example.com"

        asyncio.run(run())

    def test_non_mapping_section_is_ignored(self):
        config = {
            "influxdb": None,
            "prometheus": {"enabled": True, "ssh_tunnel": {"enabled": False}},
        }

        async def run():
            with patch("server_management_lib.tunnel.SSHTunnel") as tunnel_cls:
                assert await open_metric_tunnels(config) == []
            tunnel_cls.assert_not_called()

        asyncio.run(run())

    def test_missing_tunnel_block_is_ignored(self):
        config = {"influxdb": {"enabled": True}}

        async def run():
            assert await open_metric_tunnels(config) == []

        asyncio.run(run())

    def test_boolean_ssh_tunnel_is_rejected(self):
        config = {"influxdb": {"enabled": True, "ssh_tunnel": True}}

        async def run():
            with pytest.raises(SSHTunnelError, match="must be a mapping"):
                await open_metric_tunnels(config)

        asyncio.run(run())

    def test_invalid_config_closes_previously_opened_tunnels(self):
        config = {
            "influxdb": {
                "enabled": True,
                "port": 8181,
                "ssh_tunnel": {"enabled": True},
            },
            "prometheus": {
                "enabled": True,
                "port": 9090,
                "ssh_tunnel": {"enabled": True},
            },
        }
        influx = FakeTunnel("influxdb")

        async def run():
            with patch(
                "server_management_lib.tunnel.SSHTunnel",
                MagicMock(
                    side_effect=[influx, SSHTunnelError("invalid tunnel config")]
                ),
            ):
                with pytest.raises(SSHTunnelError, match="invalid tunnel config"):
                    await open_metric_tunnels(config)
            influx.close.assert_awaited_once()

        asyncio.run(run())

    def test_failure_closes_previously_opened_tunnels(self):
        config = {
            "influxdb": {
                "enabled": True,
                "port": 8181,
                "ssh_tunnel": {"enabled": True},
            },
            "prometheus": {
                "enabled": True,
                "port": 9090,
                "ssh_tunnel": {"enabled": True},
            },
        }
        influx = FakeTunnel("influxdb")
        prometheus = FakeTunnel("prometheus", should_fail=True)
        created = [influx, prometheus]

        async def run():
            with patch(
                "server_management_lib.tunnel.SSHTunnel",
                MagicMock(side_effect=created),
            ):
                with pytest.raises(SSHTunnelError, match="prometheus failed"):
                    await open_metric_tunnels(config)
            influx.close.assert_awaited_once()

        asyncio.run(run())

    def test_close_metric_tunnels(self):
        tunnel = FakeTunnel("influxdb")
        active = [
            ActiveTunnel(
                section="influxdb",
                tunnel=tunnel,
                endpoint=TunnelEndpoint("127.0.0.1", 45678),
            )
        ]

        async def run():
            await close_metric_tunnels(active)
            tunnel.close.assert_awaited_once()

        asyncio.run(run())
