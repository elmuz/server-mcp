"""
Tests for server.py tool handlers.

Uses mocked SSH, security, and config to test
the actual tool logic without a real host.
"""

import pytest

from disk_health_mcp import server
from disk_health_mcp.server import (
    _enrich_error_output,
    _format_influxdb_device_health,
)


@pytest.fixture(autouse=True)
def restore_server_state():
    """Keep apply_config() from leaking into other tests."""
    original_config = dict(server.config)
    original_security = server.security
    original_executor = server.executor
    yield
    server.config.clear()
    server.config.update(original_config)
    server.security = original_security
    server.executor = original_executor


# ============================================================================
# Error Enrichment
# ============================================================================


class TestEnrichErrorOutput:
    """Verify error hinting works in isolation."""

    def test_permission_denied(self):
        result = _enrich_error_output("smartctl: /dev/sda: Permission denied")
        assert "require root privileges" in result

    def test_command_not_found(self):
        result = _enrich_error_output("bash: smartctl: command not found")
        assert "Hint" in result

    def test_clean_output_passthrough(self):
        clean = "smartctl 7.4, JSON output follows"
        assert _enrich_error_output(clean) == clean


# ============================================================================
# InfluxDB Health Formatting
# ============================================================================


class TestInfluxDBHealthFormatting:
    """Verify _format_influxdb_device_health renders correctly."""

    def test_healthy_sata_drive(self):
        row = {
            "device": "sda",
            "model": "ST18000NT001-3NF101",
            "serial_no": "ZVTFE2SL",
            "health_ok": True,
            "temp_c": 33,
            "power_on_hours": 10508,
            "power_cycle_count": 133,
        }
        result = _format_influxdb_device_health(row)
        assert "/dev/sda" in result
        assert "ST18000NT001" in result
        assert "PASSED" in result
        assert "33°C" in result
        assert "10,508" in result
        assert "🔥" not in result

    def test_healthy_nvme_drive(self):
        row = {
            "device": "nvme0",
            "model": "CT1000P2SSD8",
            "serial_no": "2146E5E54409",
            "health_ok": True,
            "temp_c": 33,
            "power_on_hours": 32881,
            "power_cycle_count": 210,
            "percentage_used": 7,
            "critical_warning": 0,
            "media_errors": 0,
            "error_log_entries": 556,
            "available_spare": 100,
            "unsafe_shutdowns": 128,
        }
        result = _format_influxdb_device_health(row)
        assert "NVMe Life Used: 7%" in result
        assert "Error Log Entries: 556" in result
        assert "near end of life" not in result

    def test_nvme_near_end_of_life(self):
        row = {
            "device": "nvme0",
            "model": "CT1000P2SSD8",
            "serial_no": "2146E5E54409",
            "health_ok": True,
            "temp_c": 33,
            "power_on_hours": 32881,
            "power_cycle_count": 210,
            "percentage_used": 92,
            "critical_warning": 0,
            "media_errors": 0,
            "error_log_entries": 0,
            "available_spare": 100,
            "unsafe_shutdowns": 128,
        }
        result = _format_influxdb_device_health(row)
        assert "near end of life" in result

    def test_high_temperature_warning(self):
        row = {
            "device": "sda",
            "model": "ST18000NT001-3NF101",
            "serial_no": "ZVTFE2SL",
            "health_ok": True,
            "temp_c": 60,
            "power_on_hours": 10508,
            "power_cycle_count": 133,
        }
        result = _format_influxdb_device_health(row)
        assert "🔥" in result

    def test_failed_health(self):
        row = {
            "device": "sdb",
            "model": "ST18000NT001-3NF101",
            "serial_no": "ZVTFF270",
            "health_ok": False,
            "temp_c": 35,
            "power_on_hours": 10509,
            "power_cycle_count": 131,
        }
        result = _format_influxdb_device_health(row)
        assert "FAILED" in result


# ============================================================================
# Tool Handler Tests (with mocked infrastructure)
# ============================================================================


class TestGetDiskHealth:
    """Test get_disk_health with mocked backend."""

    async def test_valid_device(self, patched_server):
        """Should return health report for valid device."""
        from disk_health_mcp.server import get_disk_health

        result = await get_disk_health("sda")
        assert "sda" in result

    async def test_invalid_device(self, patched_server, mock_security):
        """Should reject invalid device names."""
        mock_security.validate_device_name.return_value = False
        from disk_health_mcp.server import get_disk_health

        result = await get_disk_health("sda;rm -rf /")
        assert "Invalid device name" in result


class TestListDisks:
    """Test list_disks with mocked backend."""

    async def test_returns_json(self, patched_server):
        """Should return disk list as JSON."""
        from disk_health_mcp.server import list_disks

        result = await list_disks()
        assert "blockdevices" in result


# ============================================================================
# InfluxDB Smart Attributes (SSD wear context)
# ============================================================================


class TestInfluxDBSmartAttributes:
    """Test get_smart_attributes via InfluxDB with SSD wear context."""

    async def test_ssd_wear_summary_shown(self, mock_config, mock_security):
        """SSD with wear data should show SSD Wear Summary."""
        import json
        from unittest.mock import AsyncMock, patch

        influx_device_result = {
            "device": "sdd",
            "model": "CT480BX500SSD1",
            "health_ok": True,
            "temp_c": 29,
            "power_on_hours": 3945,
            "power_cycle_count": 21,
            "percent_lifetime_remain": 97,
            "percentage_used": 3,
            "media_errors": 0,
            "available_spare": 100,
        }
        influx_attrs_result = [
            {"name": "Percent_Lifetime_Remain", "raw_value": 97, "device": "sdd"},
            {"name": "Wear_Leveling_Count", "raw_value": 50, "device": "sdd"},
            {"name": "Reallocated_Sector_Ct", "raw_value": 0, "device": "sdd"},
        ]

        mock_client = AsyncMock()

        async def fake_query(query, database=None):
            if "smart_device" in query:
                return f"✅ Query successful\n\n{json.dumps([influx_device_result])}"
            if "smart_attribute" in query:
                return f"✅ Query successful\n\n{json.dumps(influx_attrs_result)}"
            return "✅ Query successful\n\n[]"

        mock_client.query = fake_query

        from disk_health_mcp.server import get_smart_attributes

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=mock_client,
            ),
        ):
            result = await get_smart_attributes("sdd")

        assert "SSD Wear Summary" in result
        assert "Life Remaining: 97%" in result
        assert "Percentage Used: 3%" in result
        assert "Percent_Lifetime_Remain" in result
        assert "100=new, 0=EOL, norm" in result

    async def test_ssd_end_of_life_warning(self, mock_config, mock_security):
        """SSD at 90%+ used should show end-of-life warning."""
        import json
        from unittest.mock import AsyncMock, patch

        influx_device_result = {
            "device": "sdd",
            "model": "CT480BX500SSD1",
            "health_ok": True,
            "percent_lifetime_remain": 5,
            "percentage_used": 95,
            "media_errors": 2,
            "available_spare": 10,
        }
        influx_attrs_result = [
            {"name": "Percent_Lifetime_Remain", "raw_value": 5, "device": "sdd"},
            {"name": "Reallocated_Sector_Ct", "raw_value": 10, "device": "sdd"},
        ]

        mock_client = AsyncMock()

        async def fake_query(query, database=None):
            if "smart_device" in query:
                return f"✅ Query successful\n\n{json.dumps([influx_device_result])}"
            if "smart_attribute" in query:
                return f"✅ Query successful\n\n{json.dumps(influx_attrs_result)}"
            return "✅ Query successful\n\n[]"

        mock_client.query = fake_query

        from disk_health_mcp.server import get_smart_attributes

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=mock_client,
            ),
        ):
            result = await get_smart_attributes("sdd")

        assert "🔴" in result  # Critical status
        assert "Drive is near end of life" in result
        assert "Media Errors: 2" in result
        assert "🔴 critical" in result  # Reallocated sectors flagged


class TestNvmeDeviceValidation:
    """The device must be validated before any database query."""

    async def test_invalid_device_never_reaches_influxdb(
        self, patched_server, mock_security
    ):
        from unittest.mock import AsyncMock, patch

        from disk_health_mcp.server import get_nvme_health

        mock_security.validate_device_name.return_value = False
        influx_lookup = AsyncMock(return_value={"device": "evil"})

        with patch("disk_health_mcp.server._get_influxdb_latest_device", influx_lookup):
            result = await get_nvme_health("x' OR '1'='1")

        assert "Invalid device name" in result
        influx_lookup.assert_not_awaited()


class TestConfigBootstrap:
    def test_apply_config_rebuilds_dependencies(self, tmp_path, monkeypatch):
        from disk_health_mcp import server

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "ssh:\n"
            "  host: diskhost.example.com\n"
            "security:\n"
            "  services_path: /data/srv\n"
            "host:\n"
            "  enabled: false\n"
        )
        monkeypatch.setenv("DISK_HEALTH_MCP_CONFIG", str(config_file))

        resolved = server.apply_config()

        assert resolved == config_file
        assert server.config["ssh"]["host"] == "diskhost.example.com"
        assert server.executor.services_base_path == "/data/srv"
