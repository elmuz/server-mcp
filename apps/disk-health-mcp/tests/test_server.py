"""
Tests for server.py tool handlers.

Uses mocked SSH, security, and config to test
the actual tool logic without a real host.
"""

from datetime import UTC

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


class TestCommandFailureDetection:
    """Executor output must be classified before parsing."""

    def test_nonzero_exit_is_failure(self):
        assert server._command_failed("output\n\n⚠️ Exit code: 127") is True

    def test_zero_exit_is_not_failure(self):
        assert server._command_failed("output\n\n⚠️ Exit code: 0") is False

    def test_command_not_found_is_failure(self):
        assert server._command_failed("zsh:1: command not found: smartctl") is True


class TestEnrichErrorOutput:
    """Verify error hinting works in isolation."""

    def test_permission_denied(self):
        result = _enrich_error_output("smartctl: /dev/sda: Permission denied")
        assert "read access" in result
        assert "does not run sudo" in result

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

    def test_kernel_device_label_overrides_influx_tag(self):
        row = {
            "device": "nvme0",
            "model": "CT1000P2SSD8",
            "health_ok": True,
            "temp_c": 35,
            "power_on_hours": 37328,
            "power_cycle_count": 294,
        }
        result = _format_influxdb_device_health(row, "nvme0n1")
        assert "/dev/nvme0n1" in result
        assert "/dev/nvme0\n" not in result


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

    async def test_no_data_returns_error_not_healthy_report(
        self, mock_config, mock_security
    ):
        """A failed fallback must not be rendered as 100/100."""
        from unittest.mock import AsyncMock, patch

        from disk_health_mcp.server import get_disk_health

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            return_value=(
                "zsh:1: command not found: /usr/sbin/smartctl\n\n⚠️ Exit code: 127"
            )
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await get_disk_health("sda")

        assert "No SMART data available" in result
        assert "100/100" not in result
        assert "No issues detected" not in result

    async def test_text_fallback_failure_returns_error(
        self, mock_config, mock_security
    ):
        """Invalid JSON plus failed text fallback must return an error."""
        from unittest.mock import AsyncMock, patch

        from disk_health_mcp.server import get_disk_health

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            side_effect=[
                "not json",
                "zsh:1: command not found: /usr/sbin/smartctl\n\n⚠️ Exit code: 127",
            ]
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await get_disk_health("sda")

        assert "No SMART data available" in result
        assert "100/100" not in result

    async def test_fallback_uses_absolute_smartctl(
        self, mock_config, mock_security, sample_smart_json
    ):
        """The SSH fallback must not rely on /usr/sbin being on PATH."""
        import json
        from unittest.mock import AsyncMock, patch

        from disk_health_mcp.server import get_disk_health

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            return_value=json.dumps(sample_smart_json)
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await get_disk_health("sda")

        assert "PASSED" in result
        command = executor.execute_safe_command.await_args.args[0]
        assert command.startswith("/usr/sbin/smartctl -j -a /dev/sda")


class TestInfluxDBDeviceMapping:
    """NVMe namespace names must match Telegraf's namespace-less tags."""

    @pytest.mark.parametrize(
        ("kernel_name", "influx_tag"),
        [
            ("nvme0n1", "nvme0"),
            ("nvme12n1", "nvme12"),
            ("sda", "sda"),
            ("mmcblk0p1", "mmcblk0p1"),
        ],
    )
    def test_device_name_mapping(self, kernel_name, influx_tag):
        assert server._influxdb_device_name(kernel_name) == influx_tag

    async def test_device_lookup_uses_normalized_name(self, mock_config):
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(
                '✅ Query successful\n\n[{"device": "nvme0", "health_ok": true}]'
            )
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=client,
            ),
        ):
            row = await server._get_influxdb_latest_device("nvme0n1")

        assert row == {"device": "nvme0", "health_ok": True}
        query = client.query.await_args.args[0]
        assert "device = 'nvme0'" in query
        assert "nvme0n1" not in query
        assert "exit_status = 0" in query
        assert f"INTERVAL '{server.SMART_LOOKBACK}'" in query

    async def test_attribute_lookup_uses_normalized_name(self, mock_config):
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(
                "✅ Query successful\n\n"
                '[{"name": "Percentage_Used", "raw_value": 7, "device": "nvme0"}]'
            )
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=client,
            ),
        ):
            rows = await server._get_influxdb_latest_attributes("nvme0n1")

        assert rows == [{"name": "Percentage_Used", "raw_value": 7, "device": "nvme0"}]
        query = client.query.await_args.args[0]
        assert "device = 'nvme0'" in query
        assert "nvme0n1" not in query
        assert "exit_status = 0" in query
        assert f"INTERVAL '{server.SMART_LOOKBACK}'" in query


class TestInfluxValidSamples:
    """Standby rows are not health data and must never be rendered as such."""

    @staticmethod
    def _success(rows):
        import json

        return f"✅ Query successful\n\n{json.dumps(rows)}"

    def test_standby_row_matches_the_reported_shape(self):
        """Document the Telegraf standby row the filter is designed for."""
        standby = {
            "device": "sda",
            "exit_status": 2,
            "time": "2026-10-18T21:50:00",
        }

        assert "health_ok" not in standby
        assert "temp_c" not in standby

    async def test_standby_only_series_returns_no_valid_sample(self, mock_config):
        """A sleeping disk must not become Unknown / 0°C / 0 hours."""
        from unittest.mock import AsyncMock, patch

        standby = {
            "device": "sda",
            "exit_status": 2,
            "time": "2026-10-18T21:50:00",
        }
        queries: list[str] = []

        async def query(sql: str) -> str:
            queries.append(sql)
            if "exit_status = 0" in sql:
                return self._success([])
            return self._success([standby])

        client = AsyncMock()
        client.query = AsyncMock(side_effect=query)
        influx_only = dict(mock_config)
        influx_only["host"] = {"enabled": False}

        with (
            patch("disk_health_mcp.server.config", influx_only),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
        ):
            result = await server.get_disk_health("sda")

        assert "No SMART data available" in result
        assert "no recent valid sample" in result
        assert "Unknown" not in result
        assert "0°C" not in result
        assert "0 hours" not in result
        assert queries
        assert any("exit_status = 0" in sql for sql in queries)
        assert any("exit_status != 0" in sql for sql in queries)
        assert all(f"INTERVAL '{server.SMART_LOOKBACK}'" in sql for sql in queries)
        assert "Recent failed polls" in result
        assert "standby/skipped" in result

    async def test_latest_valid_sample_wins_over_newer_standby_rows(self, mock_config):
        """The valid row is used even when standby rows are more recent."""
        from unittest.mock import AsyncMock, patch

        valid = {
            "device": "sda",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "temp_c": 33,
            "power_on_hours": 10508,
            "time": "2026-10-18T21:05:00",
        }
        client = AsyncMock()
        client.query = AsyncMock(return_value=self._success([valid]))

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
        ):
            result = await server.get_disk_health("sda")

        assert "PASSED" in result
        assert "33°C" in result
        assert "Sample:" in result
        assert "Standby" not in result

    def test_sample_age_is_reported(self):
        from datetime import datetime, timedelta

        row = {"time": datetime.now(UTC) - timedelta(minutes=45)}
        row["time"] = row["time"].replace(tzinfo=None).isoformat()

        age = server._format_sample_age(row)

        assert age is not None
        assert age.startswith("4")
        assert "minutes ago" in age

    def test_invalid_sample_time_is_ignored(self):
        assert server._format_sample_age({"time": "not-a-time"}) is None
        assert server._format_sample_age({}) is None

    def test_missing_health_fields_are_not_zeroed(self):
        row = {
            "device": "sda",
            "health_ok": True,
            "model": "ST18000NT001",
            "serial_no": "ZVTFE2SL",
        }

        result = _format_influxdb_device_health(row)

        assert "PASSED" in result
        assert "0°C" not in result
        assert "0 hours" not in result
        assert "Power Cycles: 0" not in result

    async def test_attribute_lookup_ignores_standby_rows(self, mock_config):
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(return_value=self._success([]))

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
        ):
            rows = await server._get_influxdb_latest_attributes("sda")

        assert rows is None
        query = client.query.await_args.args[0]
        assert "exit_status = 0" in query

    async def test_overview_counts_only_valid_samples(self, mock_config):
        from unittest.mock import AsyncMock, patch

        valid = {
            "device": "sda",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "temp_c": 33,
            "power_on_hours": 10508,
            "time": "2026-10-18T21:05:00",
        }
        client = AsyncMock()
        client.query = AsyncMock(return_value=self._success([valid]))

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._metric_clients", {}),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await server.get_full_disk_report()

        assert "Found 1 devices" in result
        assert "/dev/sda" in result
        assert "Sample:" in result

        # One window-function query returns the latest valid row per device and
        # one query reports recent failed polls; still no per-disk N+1 query.
        assert client.query.await_count == 2
        queries = [call.args[0] for call in client.query.await_args_list]
        assert any("exit_status = 0" in query for query in queries)
        assert any("exit_status != 0" in query for query in queries)
        device_query = next(
            query
            for query in queries
            if "ROW_NUMBER() OVER (PARTITION BY device" in query
        )
        assert "exit_status = 0" in device_query

    async def test_overview_without_valid_samples_falls_back_to_ssh(
        self, mock_config, sample_smart_json
    ):
        import json
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(return_value=self._success([]))
        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            side_effect=[
                json.dumps(
                    {
                        "blockdevices": [
                            {
                                "name": "sda",
                                "model": "ST18000NT001",
                                "size": "16.4T",
                                "type": "disk",
                            }
                        ]
                    }
                ),
                json.dumps(sample_smart_json),
            ]
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.executor", executor),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
        ):
            result = await server.get_full_disk_report()

        assert "No valid SMART sample in InfluxDB" in result
        assert "Health: " in result

    def test_influx_rows_parser_handles_bad_payloads(self):
        assert server._parse_influx_rows("❌ failed") == []
        assert server._parse_influx_rows("✅ Query successful\n\nnot json") == []
        assert server._parse_influx_rows("✅ Query successful\n\n{}") == []


class TestInfluxFreshnessAndIdentity:
    """T-05: stale, failed or mismatched samples must not look current."""

    @staticmethod
    def _row(**overrides):
        from datetime import datetime, timedelta

        row = {
            "device": "sda",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "serial_no": "ZVTFE2SL",
            "temp_c": 33,
            "power_on_hours": 10508,
            "time": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        }
        row.update(overrides)
        return row

    @staticmethod
    def _live(name="sda", model="ST18000NT001", serial="ZVTFE2SL"):
        return {"name": name, "model": model, "serial": serial}

    async def test_fresh_matching_sample_is_green(self, mock_config):
        from unittest.mock import AsyncMock, patch

        row = self._row()
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value={"sda": self._live()}),
            ),
        ):
            result = await server.get_disk_health("sda")

        assert result.startswith("✅")
        assert "Freshness: current" in result
        assert "Identity: verified" in result
        assert "Serial: ZVTFE2SL" in result
        assert "Sample Device Tag: sda" in result
        assert "Recent failed polls: none" in result

    async def test_stale_sample_is_amber_not_green(self, mock_config):
        from datetime import datetime, timedelta
        from unittest.mock import AsyncMock, patch

        stale_time = datetime.now(UTC) - timedelta(minutes=30)
        row = self._row(time=stale_time.isoformat())
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value={"sda": self._live()}),
            ),
        ):
            result = await server.get_disk_health("sda")

        assert "✅" not in result
        assert "🟡" in result
        assert "STALE" in result
        assert "not current health" in result
        assert "Recent failed polls: none" in result

    async def test_stale_sample_with_failed_polls_is_red(self, mock_config):
        from datetime import datetime, timedelta
        from unittest.mock import AsyncMock, patch

        now = datetime.now(UTC)
        row = self._row(time=(now - timedelta(minutes=30)).isoformat())
        failures = [
            {
                "device": "sda",
                "exit_status": 1,
                "time": (now - timedelta(minutes=1)).isoformat(),
            }
        ]
        sample = server._InfluxSample(row, failures)
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=sample),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value={"sda": self._live()}),
            ),
        ):
            result = await server.get_disk_health("sda")

        assert "✅" not in result
        assert result.startswith("🔴")
        assert "STALE" in result
        assert "Recent failed polls" in result
        assert "exit_status=1" in result

    async def test_fresh_sample_still_reports_recent_failed_polls(self, mock_config):
        from datetime import datetime, timedelta
        from unittest.mock import AsyncMock, patch

        now = datetime.now(UTC)
        failures = [
            {
                "device": "sda",
                "exit_status": 2,
                "time": (now - timedelta(minutes=2)).isoformat(),
            }
        ]
        sample = server._InfluxSample(self._row(), failures)
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=sample),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value={"sda": self._live()}),
            ),
        ):
            result = await server.get_disk_health("sda")

        assert "✅" in result
        assert "Recent failed polls" in result
        assert "standby/skipped" in result

    @pytest.mark.parametrize(
        ("tool_name", "device", "live_name"),
        [
            ("get_disk_health", "sda", "sda"),
            ("get_nvme_health", "nvme0n1", "nvme0n1"),
        ],
    )
    async def test_identity_mismatch_refuses_healthy(
        self, mock_config, tool_name, device, live_name
    ):
        from unittest.mock import AsyncMock, patch

        row = self._row(
            device="nvme0" if live_name.startswith("nvme") else "sda",
            model="KINGSTON-SOMETHING",
            serial_no="KINGSTON-SERIAL",
        )
        live = {
            live_name: self._live(
                name=live_name,
                model="CT1000P2SSD8",
                serial="CT1000-SERIAL",
            )
        }
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=live),
            ),
        ):
            result = await getattr(server, tool_name)(device)

        assert "✅" not in result
        assert result.startswith("🔴")
        assert "MISMATCH" in result
        assert "KINGSTON-SERIAL" in result
        assert "CT1000-SERIAL" in result
        assert "Health: PASSED" not in result
        assert "UNKNOWN — sample belongs to a different disk" in result

    async def test_unresolved_live_identity_is_not_green(self, mock_config):
        from unittest.mock import AsyncMock, patch

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=self._row()),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await server.get_disk_health("sda")

        assert "✅" not in result
        assert "Live Device: unavailable" in result
        assert "Identity: ⚠️ UNVERIFIED" in result

    async def test_full_report_overview_reports_stale_mismatch_and_failures(
        self, mock_config
    ):
        from datetime import datetime, timedelta
        from unittest.mock import AsyncMock, patch

        now = datetime.now(UTC)
        row = self._row(
            device="nvme0",
            model="KINGSTON-SOMETHING",
            serial_no="KINGSTON-SERIAL",
            time=(now - timedelta(minutes=30)).isoformat(),
        )
        failures = [
            {
                "device": "nvme0",
                "exit_status": 1,
                "time": (now - timedelta(minutes=1)).isoformat(),
            }
        ]
        sample = server._InfluxSample(row, failures)
        live = {
            "nvme0n1": self._live(
                name="nvme0n1",
                model="CT1000P2SSD8",
                serial="CT1000-SERIAL",
            )
        }
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._influxdb_latest_device_rows",
                new=AsyncMock(return_value=[sample]),
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=live),
            ),
        ):
            result = await server.get_full_disk_report()

        assert "✅" not in result
        assert "STALE" in result
        assert "Identity: MISMATCH" in result
        assert "KINGSTON-SERIAL" in result
        assert "CT1000-SERIAL" in result
        assert "Recent failed polls" in result
        assert "exit_status=1" in result

    async def test_full_report_without_sample_reports_failed_polls(self, mock_config):
        from datetime import datetime, timedelta
        from unittest.mock import AsyncMock, patch

        now = datetime.now(UTC)
        failures = {
            "sda": [
                {
                    "device": "sda",
                    "exit_status": 1,
                    "time": (now - timedelta(minutes=1)).isoformat(),
                }
            ]
        }
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._influxdb_latest_device_rows",
                new=AsyncMock(return_value=[]),
            ),
            patch(
                "disk_health_mcp.server._influxdb_recent_failures_by_device",
                new=AsyncMock(return_value=failures),
            ),
            patch(
                "disk_health_mcp.server._get_full_report_via_ssh",
                new=AsyncMock(return_value="ssh fallback"),
            ),
        ):
            result = await server.get_full_disk_report()

        assert "No valid SMART sample" in result
        assert "Recent non-success SMART polls" in result
        assert "exit_status=1" in result


class TestAbsoluteHostToolPaths:
    """Host tool fallbacks must not rely on /usr/sbin being on PATH."""

    async def test_smart_attributes_uses_absolute_smartctl(
        self, mock_config, mock_security, sample_smart_json
    ):
        import json
        from unittest.mock import AsyncMock, patch

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            return_value=json.dumps(sample_smart_json)
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_attributes",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await server.get_smart_attributes("sda")

        assert "Reallocated_Sector_Ct" in result
        command = executor.execute_safe_command.await_args.args[0]
        assert command.startswith("/usr/sbin/smartctl -j -a /dev/sda")

    async def test_nvme_health_uses_absolute_nvme_cli(self, mock_config, mock_security):
        from unittest.mock import AsyncMock, patch

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            return_value="NVMe SMART/Health Information"
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await server.get_nvme_health("nvme0n1")

        assert "SMART/Health" in result
        command = executor.execute_safe_command.await_args.args[0]
        assert command.startswith("/usr/sbin/nvme smart-log /dev/nvme0n1")

    async def test_smart_test_uses_absolute_smartctl(self, mock_config, mock_security):
        from unittest.mock import AsyncMock, patch

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            return_value="SMART self-test started"
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.security", mock_security),
            patch("disk_health_mcp.server.executor", executor),
        ):
            result = await server.run_smart_test("sda", "short")

        assert "started" in result
        commands = [
            call.args[0] for call in executor.execute_safe_command.await_args_list
        ]
        assert commands == [
            "/usr/sbin/smartctl --version",
            "/usr/sbin/smartctl -n standby -t short /dev/sda",
        ]


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
