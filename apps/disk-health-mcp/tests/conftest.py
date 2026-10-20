"""
Shared test fixtures for disk-health-mcp.

Mocks SSH manager, security validator, and config
so server.py tool handlers can be tested without a real host.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class FakeConfig(dict):
    """Dict that also supports .get() with nested defaults."""

    def get(self, key, default=None):
        return super().get(key, default or {})


@pytest.fixture
def mock_config():
    """Return a minimal config dict with host and influxdb enabled."""
    return FakeConfig(
        ssh={"host": "localhost", "port": 22, "username": "test"},
        host={"enabled": True},
        influxdb={
            "enabled": True,
            "host": "localhost",
            "port": 8181,
            "database": "telegraf",
        },
        prometheus={"enabled": False},
        security={"allow_generic_commands": False},
    )


@pytest.fixture
def mock_ssh_manager():
    """Return an AsyncMock for SSHManager."""
    mgr = AsyncMock()
    mgr.connect = AsyncMock(return_value=None)
    mgr.disconnect = AsyncMock(return_value=None)
    mgr.execute_safe_command = AsyncMock(return_value="{}")
    return mgr


@pytest.fixture
def mock_security():
    """Return a MagicMock for SecurityValidator (sync methods)."""
    sec = MagicMock()
    sec.validate_device_name.return_value = True
    sec.is_command_safe.return_value = True
    sec.validate_smart_test_type.return_value = True
    sec.validate_prometheus_query.return_value = "query"
    sec.validate_influxdb_query.return_value = "query"
    return sec


@pytest.fixture
def sample_smart_json():
    """Minimal SMART JSON output for testing."""
    return {
        "json_format_version": [1, 0],
        "smartctl": {
            "version": [7, 4],
            "svn_revision": "5500",
            "platform_info": "x86_64-linux",
        },
        "device": {"name": "/dev/sda", "protocol": "ATA"},
        "model_name": "ST18000NT001-3NF101",
        "serial_number": "ZVTFE2SL",
        "smart_status": {"passed": True},
        "temperature": {"current": 33},
        "power_on_time": {"hours": 10508},
        "ata_smart_attributes": {
            "table": [
                {
                    "id": 1,
                    "name": "Raw_Read_Error_Rate",
                    "value": 80,
                    "worst": 60,
                    "thresh": 6,
                    "when_failed": "",
                    "flags": {
                        "value": 15,
                        "string": "POSR-K",
                        "prefailure": True,
                        "updated_online": True,
                    },
                    "raw": {"value": 12345678},
                },
                {
                    "id": 5,
                    "name": "Reallocated_Sector_Ct",
                    "value": 100,
                    "worst": 100,
                    "thresh": 10,
                    "when_failed": "",
                    "flags": {
                        "value": 51,
                        "string": "PO--K-",
                        "prefailure": True,
                        "updated_online": False,
                    },
                    "raw": {"value": 0},
                },
                {
                    "id": 197,
                    "name": "Current_Pending_Sector",
                    "value": 100,
                    "worst": 100,
                    "thresh": 0,
                    "when_failed": "",
                    "flags": {
                        "value": 18,
                        "string": "-O--CK",
                        "prefailure": False,
                        "updated_online": True,
                    },
                    "raw": {"value": 0},
                },
            ]
        },
    }


@pytest.fixture
def sample_lsblk_json():
    """Minimal lsblk JSON output for testing."""
    return json.dumps(
        {
            "blockdevices": [
                {
                    "name": "sda",
                    "model": "ST18000NT001",
                    "serial": "ZVTFE2SL",
                    "size": "16.4T",
                    "type": "disk",
                    "tran": "sata",
                },
            ]
        }
    )


@pytest.fixture
def patched_server(
    mock_config, mock_ssh_manager, mock_security, sample_smart_json, sample_lsblk_json
):
    """Patch all server-level globals so tool handlers can be tested."""

    def smart_exec(cmd):
        if "lsblk" in cmd:
            return sample_lsblk_json
        return json.dumps(sample_smart_json)

    with (
        patch("disk_health_mcp.server.config", mock_config),
        patch("disk_health_mcp.server.executor", mock_ssh_manager),
        patch("disk_health_mcp.server.security", mock_security),
        patch.object(
            mock_ssh_manager,
            "execute_safe_command",
            new=AsyncMock(side_effect=smart_exec),
        ),
    ):
        yield {
            "config": mock_config,
            "executor": mock_ssh_manager,
            "security": mock_security,
        }


@pytest.fixture(autouse=True)
def _isolate_metric_clients():
    """Drop the cached InfluxDB/Prometheus clients around every test.

    ``server._metric_clients`` is a module-level cache. Without this, a client
    built for one test (usually an ``AsyncMock``) is returned to the next test
    that patches ``config`` with an equivalent endpoint, so the assertions see
    another test's response. Observed as an intermittent failure in the
    attribute-lookup tests before the cache key was made content-based.
    """
    from disk_health_mcp import server

    server._metric_clients.clear()
    yield
    server._metric_clients.clear()
