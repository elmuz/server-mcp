"""
Tests for server.py tool handlers.

Uses mocked SSH, security, and config to test
the actual tool logic without a real host.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import ClassVar

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


class TestDiskDisplayName:
    """Reports name the role label and the current kernel device together."""

    def test_label_and_live_device_are_combined(self):
        assert server._describe_disk("Data1", "sda", "sda") == "Data1 (/dev/sda)"

    def test_nvme_label_uses_live_namespace(self):
        assert server._describe_disk("Cache1", "nvme0n1") == "Cache1 (/dev/nvme0n1)"

    def test_legacy_kernel_name_tag_is_not_shown_as_label(self):
        assert server._describe_disk("sdd", "sdc", "sdc") == "/dev/sdc"

    def test_missing_live_device_falls_back_to_requested(self):
        assert server._describe_disk("Data1", "", "sda") == "/dev/sda"

    def test_unresolved_disk_is_named(self):
        assert server._describe_disk("", "", "") == "unknown disk"

    def test_pairing_can_be_suppressed(self):
        assert server._describe_disk("Data2", "sda", pair=False) == "/dev/sda"

    def test_mismatched_sample_is_not_paired_with_the_requested_device(self):
        """The title must not assert a label/device pairing the report denies."""
        row = {
            "device": "Data2",
            "serial_no": "ZVTFE2SL",
            "model": "ST18000NT001",
            "exit_status": 0,
            "health_ok": True,
            "time": datetime.now(UTC).isoformat(),
        }
        live = {"name": "sda", "model": "ST18000NT001", "serial": "ZVTFF270"}

        text, data, ok = server._render_influxdb_health(row, "sda", live_device=live)

        assert ok is False
        assert data["identity"]["state"] == "mismatch"
        assert text.splitlines()[0] == "🔴 Device Health Report: /dev/sda"
        assert "Data2 (/dev/sda)" not in text
        assert "Sample Device Tag: Data2" in text

    def test_verified_sample_is_paired(self):
        row = {
            "device": "Data1",
            "serial_no": "ZVTFF270",
            "model": "ST18000NT001",
            "exit_status": 0,
            "health_ok": True,
            "time": datetime.now(UTC).isoformat(),
        }
        live = {"name": "sda", "model": "ST18000NT001", "serial": "ZVTFF270"}

        text, data, _ = server._render_influxdb_health(row, "sda", live_device=live)

        assert data["identity"]["state"] == "verified"
        assert text.splitlines()[0] == "✅ Device Health Report: Data1 (/dev/sda)"


class TestMetricClientCache:
    """The HTTP client cache is keyed by endpoint, not by config object identity."""

    def test_equal_endpoints_share_one_client(self):
        calls = []

        def factory():
            client = object()
            calls.append(client)
            return client

        first = server._cached_client("influxdb", {"host": "h", "port": 1}, factory)
        second = server._cached_client("influxdb", {"host": "h", "port": 1}, factory)

        assert first is second
        assert len(calls) == 1

    def test_a_different_endpoint_gets_a_new_client(self):
        first = server._cached_client(
            "influxdb", {"host": "h", "port": 1}, lambda: object()
        )
        second = server._cached_client(
            "influxdb", {"host": "h", "port": 2}, lambda: object()
        )

        assert first is not second


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
        assert "Error Information Log Entries: 556" in result
        assert "not media errors" in result
        assert "Media_and_Data_Integrity_Errors: 0" in result
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
        # The newest-sample query is no longer the last call: failed polls are
        # looked up afterwards (by serial when present, label as the fallback).
        queries = [call.args[0] for call in client.query.await_args_list]
        sample_query = next(q for q in queries if "exit_status = 0" in q)
        assert "device = 'nvme0'" in sample_query
        assert "nvme0n1" not in sample_query
        assert f"INTERVAL '{server.SMART_LOOKBACK}'" in sample_query

    async def test_serial_lookup_wins_over_device_tag(self, mock_config):
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(
                '✅ Query successful\n\n[{"device": "Parity1", "serial_no": "ZVTFF3JB", '
                '"exit_status": 0, "health_ok": true}]'
            )
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=client,
            ),
        ):
            row = await server._get_influxdb_latest_device("sdc", serial="ZVTFF3JB")

        assert row == {
            "device": "Parity1",
            "serial_no": "ZVTFF3JB",
            "exit_status": 0,
            "health_ok": True,
        }
        queries = [call.args[0] for call in client.query.await_args_list]
        sample_query = next(q for q in queries if "exit_status = 0" in q)
        assert "serial_no = 'ZVTFF3JB'" in sample_query
        assert "device = 'sdc'" not in sample_query
        # Failed polls are matched on the label of the successful sample (and on
        # the serial for pollers that report one), never on the requested
        # kernel name: kernel names are reused across disks.
        failure_query = next(q for q in queries if "exit_status != 0" in q)
        assert "serial_no = 'ZVTFF3JB'" in failure_query
        assert "device = 'Parity1'" in failure_query
        assert "sdc" not in failure_query

    async def test_failed_polls_ignore_a_reused_kernel_name(self, mock_config):
        """`sdd` was the parity disk's tag before the redeploy and is the System
        SSD's kernel name now; its failures must not be attached to it."""
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(
            return_value=(
                '✅ Query successful\n\n[{"device": "System", '
                '"serial_no": "2421E8B28A83", "exit_status": 0}]'
            )
        )
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=client,
            ),
        ):
            await server._get_influxdb_latest_device("sdd", serial="2421E8B28A83")

        failure_query = next(
            q
            for q in (call.args[0] for call in client.query.await_args_list)
            if "exit_status != 0" in q
        )
        assert "device = 'System'" in failure_query
        assert "device = 'sdd'" not in failure_query

    async def test_get_disk_health_resolves_serial_without_mismatch(self, mock_config):
        """A label tag plus a live kernel name must resolve to one disk."""
        from datetime import UTC, datetime
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        sample = {
            "device": "Data2",
            "serial_no": "ZVTFE2SL",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "temp_c": 33,
            "time": datetime.now(UTC).isoformat(),
        }
        client.query = AsyncMock(
            return_value=("✅ Query successful\n\n" + json.dumps([sample]))
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._metric_clients", {}),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=client,
            ),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(
                    return_value={
                        "sdb": {
                            "name": "sdb",
                            "model": "ST18000NT001",
                            "serial": "ZVTFE2SL",
                        }
                    }
                ),
            ),
        ):
            result = await server.get_disk_health("sdb")

        assert "Identity: verified" in result
        assert "Live Device: /dev/sdb" in result
        assert "Sample Device Tag: Data2" in result
        queries = [call.args[0] for call in client.query.await_args_list]
        sample_query = next(q for q in queries if "exit_status = 0" in q)
        assert "serial_no = 'ZVTFE2SL'" in sample_query
        assert "device = 'sdb'" not in sample_query

    async def test_attributes_lookup_uses_serial(self, mock_config):
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(
            return_value='✅ Query successful\n\n[{"name": "Temperature_Celsius", "raw_value": 30}]'
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._make_influxdb_client",
                return_value=client,
            ),
        ):
            await server._get_influxdb_latest_attributes("sda", serial="ZVTFF270")

        query = client.query.await_args.args[0]
        assert "serial_no = 'ZVTFF270'" in query
        assert "device = 'sda'" not in query

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
        # NVMe smart_attribute rows carry no exit_status in Telegraf, so the
        # filter would discard every NVMe attribute.
        assert "exit_status" not in query
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
        from datetime import datetime, timedelta
        from unittest.mock import AsyncMock, patch

        valid = {
            "device": "Data1",
            "serial_no": "ZVTFF270",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "temp_c": 33,
            "power_on_hours": 10508,
            "time": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        }
        client = AsyncMock()
        client.query = AsyncMock(return_value=self._success([valid]))

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(
                    return_value={
                        "sda": {
                            "name": "sda",
                            "model": "ST18000NT001",
                            "serial": "ZVTFF270",
                        }
                    }
                ),
            ),
        ):
            result = await server.get_disk_health("sda")

        assert "PASSED" in result
        assert "33°C" in result
        assert "Sample:" in result
        assert "1 minutes" not in result
        assert "Standby" not in result

    def test_sample_age_is_reported(self):
        from datetime import datetime, timedelta

        row = {"time": datetime.now(UTC) - timedelta(minutes=45)}
        row["time"] = row["time"].replace(tzinfo=None).isoformat()

        age = server._format_sample_age(row)

        assert age is not None
        assert age.startswith("4")
        assert "minutes ago" in age

    @pytest.mark.parametrize(
        ("age", "expected"),
        [
            (timedelta(seconds=1), "1 second ago"),
            (timedelta(seconds=59), "59 seconds ago"),
            (timedelta(minutes=1), "1 minute ago"),
            (timedelta(minutes=2), "2 minutes ago"),
            (timedelta(hours=1), "1 hour ago"),
            (timedelta(days=1), "1 day ago"),
            (timedelta(days=2), "2 days ago"),
        ],
    )
    def test_sample_age_is_pluralized(self, age, expected):
        from datetime import datetime

        row = {"time": (datetime.now(UTC) - age).replace(tzinfo=None).isoformat()}

        result = server._format_sample_age(row)

        assert result is not None
        assert result.startswith(f"{expected} (")
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

    async def test_attribute_lookup_returns_none_without_rows(self, mock_config):
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
        # Attribute rows are only written for successful samples, so standby
        # rows need no exit_status filter (and NVMe rows have no such field).
        assert "device = 'sda'" in query
        assert "exit_status" not in query

    async def test_overview_counts_only_valid_samples(self, mock_config):
        from unittest.mock import AsyncMock, patch

        valid = {
            "device": "Data1",
            "serial_no": "ZVTFF270",
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
        # The label is display only; the serial is the identity.
        assert "Data1" in result
        assert "Serial: ZVTFF270" in result
        assert "Sample:" in result

        # One window-function query returns the latest valid row per disk and
        # one query reports recent failed polls; still no per-disk N+1 query.
        assert client.query.await_count == 2
        queries = [call.args[0] for call in client.query.await_args_list]
        assert any("exit_status = 0" in query for query in queries)
        assert any("exit_status != 0" in query for query in queries)
        device_query = next(
            query
            for query in queries
            if "ROW_NUMBER() OVER (PARTITION BY serial_no" in query
        )
        assert "exit_status = 0" in device_query
        assert "serial_no IS NOT NULL" in device_query

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


class TestInfluxSelectorHardening:
    """Host values are allowlisted before they enter an InfluxDB SQL literal."""

    @pytest.mark.parametrize(
        "value",
        [
            "ZVTFE2SL",
            "2146E5E54409",
            "WD-WCC4M1234567",
            "50026B7383E4529D",
            "Data1",
            "NVMe2",
        ],
    )
    def test_ordinary_serials_and_labels_are_accepted(self, value):
        assert server._sql_literal(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "X' OR '1'='1",
            "x'); DROP TABLE smart_device; --",
            "a\\",
            "-- comment",
            "a\nb",
            "'",
            "",
            "   ",
            None,
        ],
    )
    def test_unsafe_values_are_dropped(self, value):
        assert server._sql_literal(value) == ""

    def test_hostile_serial_falls_back_to_the_device_tag(self):
        assert server._identity_selector("sda", "X' OR '1'='1") == "device = 'sda'"
        assert server._identity_selector("sda", "ZVTFE2SL") == "serial_no = 'ZVTFE2SL'"

    def test_failed_poll_selector_matches_label_and_serial(self):
        assert server._failed_poll_selector("sda") == "device = 'sda'"
        assert server._failed_poll_selector("sda", "ZVTFF270") == (
            "(serial_no = 'ZVTFF270' OR "
            "(device = 'sda' AND (serial_no IS NULL OR serial_no = '')))"
        )
        # An NVMe namespace name keeps its legacy namespace-less tag.
        assert server._failed_poll_selector("nvme0n1") == "device = 'nvme0'"
        assert server._failed_poll_selector("'") is None
        assert server._failed_poll_selector("", "'") is None


class TestFailedPollAttribution:
    """T-20: failed polls follow the serial, not the mutable device label."""

    @staticmethod
    def _success(rows):
        import json

        return f"✅ Query successful\n\n{json.dumps(rows)}"

    @staticmethod
    def _valid_row(**overrides):
        from datetime import datetime

        row = {
            "device": "Data1",
            "serial_no": "ZVTFF270",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001",
            "temp_c": 33,
            "time": datetime.now(UTC).isoformat(),
        }
        row.update(overrides)
        return row

    async def test_failed_polls_follow_the_serial_across_a_label_change(
        self, mock_config
    ):
        from unittest.mock import AsyncMock, patch

        valid = self._valid_row()
        # The standby row was written under the old label; only the serial ties
        # it to the disk whose newest valid sample now carries "Data1".
        standby = {
            "device": "sda",
            "serial_no": "ZVTFF270",
            "exit_status": 2,
            "time": valid["time"],
        }
        client = AsyncMock()
        client.query = AsyncMock(
            side_effect=lambda sql: self._success(
                [valid] if "exit_status = 0" in sql else [standby]
            )
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await server.get_full_disk_report()

        assert "Recent failed polls" in result
        assert "standby/skipped" in result
        failure_query = next(
            call.args[0]
            for call in client.query.await_args_list
            if "exit_status != 0" in call.args[0]
        )
        assert "serial_no" in failure_query

    async def test_failed_poll_without_a_serial_falls_back_to_the_label(
        self, mock_config
    ):
        from unittest.mock import AsyncMock, patch

        valid = self._valid_row()
        standby = {
            "device": "Data1",
            "exit_status": 2,
            "time": valid["time"],
        }
        client = AsyncMock()
        client.query = AsyncMock(
            side_effect=lambda sql: self._success(
                [valid] if "exit_status = 0" in sql else [standby]
            )
        )

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server._make_influxdb_client", return_value=client),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=None),
            ),
        ):
            result = await server.get_full_disk_report()

        assert "Recent failed polls" in result
        assert "standby/skipped" in result

    def test_groups_use_the_label_for_the_no_sample_report(self):
        serial_row = {
            "device": "Data1",
            "serial_no": "ZVTFF270",
            "exit_status": 2,
            "time": "2026-10-21T21:30:00",
        }
        label_row = {
            "device": "sda",
            "exit_status": 2,
            "time": "2026-10-21T21:30:00",
        }
        failures = server._FailedPolls(
            by_serial={"ZVTFF270": [serial_row]},
            by_label={"sda": [label_row]},
        )

        assert failures.for_disk("ZVTFF270", "Data1") == [serial_row]
        # A legacy label that wrote failures without a serial belongs to the
        # same disk, so both evidence sources are merged.
        assert failures.for_disk("ZVTFF270", "sda") == [serial_row, label_row]
        assert failures.for_disk("OTHER", "sda") == [label_row]
        assert failures.groups() == {"Data1": [serial_row], "sda": [label_row]}


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

        # A sample for an NVMe disk must carry NVMe wear fields: a row with
        # ATA-only ``exit_status`` is detected as SATA and refused by
        # ``get_nvme_health`` before the identity check.
        nvme_fields = {"percentage_used": 5, "available_spare": 100}
        row = self._row(
            device="nvme0" if live_name.startswith("nvme") else "sda",
            model="KINGSTON-SOMETHING",
            serial_no="KINGSTON-SERIAL",
            **(nvme_fields if live_name.startswith("nvme") else {}),
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

    async def test_missing_requested_name_is_amber_not_verified(self, mock_config):
        """A name that no longer resolves must not turn into a green report
        about whichever disk owns the stale tag."""
        from unittest.mock import AsyncMock, patch

        row = self._row(device="sdd", serial_no="ZVTFF3JB")
        live = {"sdc": self._live(name="sdc", serial="ZVTFF3JB")}
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
            result = await server.get_disk_health("sdd")

        assert "✅" not in result
        assert result.startswith("🟡")
        assert "Identity: verified" not in result
        assert "UNVERIFIED for /dev/sdd" in result
        assert "belongs to live /dev/sdc" in result
        assert "Health: UNVERIFIED" in result

    async def test_resolved_device_without_serial_is_not_verified(self, mock_config):
        """A resolvable device with an unreadable serial keeps the name as the
        reference, so another disk's sample cannot be called verified."""
        from unittest.mock import AsyncMock, patch

        row = self._row(device="sdd", serial_no="ZVTFF3JB")
        live = {"sdd": self._live(name="sdd", serial="")}
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
            result = await server.get_disk_health("sdd")

        assert "✅" not in result
        assert "Identity: verified" not in result
        assert "Identity: ⚠️ UNVERIFIED" in result

    async def test_health_report_runs_lsblk_once(self, mock_config):
        """Resolving the serial and verifying the sample share one lsblk call."""
        from unittest.mock import AsyncMock, patch

        live_devices = AsyncMock(return_value={"sda": self._live()})
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=self._row()),
            ),
            patch("disk_health_mcp.server._get_live_devices", new=live_devices),
        ):
            await server.get_disk_health("sda")

        assert live_devices.await_count == 1

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
                "disk_health_mcp.server._influxdb_recent_failures_by_disk",
                new=AsyncMock(return_value=server._FailedPolls({}, failures)),
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
            "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json",
            "/usr/sbin/smartctl -n standby -i /dev/sda",
            "/usr/sbin/smartctl -n standby -t short /dev/sda",
        ]


class TestListDisks:
    """Test list_disks with mocked backend."""

    async def test_returns_a_readable_table(self, patched_server):
        """The text form is a table; the raw records stay in data.devices."""
        from disk_health_mcp.server import mcp

        tool = mcp._tool_manager.get_tool("list_disks")
        response = await tool.fn()
        assert "Storage Devices (1)" in response.text
        assert "NAME" in response.text
        assert "ST18000NT001" in response.text
        assert response.data["devices"][0]["name"] == "sda"


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


class TestDeviceVocabulary:
    """T-11: every device spelling resolves to the same physical disk."""

    LIVE: ClassVar[dict[str, dict]] = {
        "sda": {
            "name": "sda",
            "model": "ST18000NT001-3NF101",
            "serial": "ZVTFF3JB",
            "tran": "sata",
        },
        "nvme0n1": {
            "name": "nvme0n1",
            "model": "CT1000P2SSD8",
            "serial": "2146E5E54409",
            "tran": "nvme",
        },
    }

    @staticmethod
    def _nvme_sample():
        return {
            "device": "Cache1",
            "reset_status": 0,
            "health_ok": True,
            "model": "CT1000P2SSD8",
            "serial_no": "2146E5E54409",
            "percentage_used": 8,
            "available_spare": 100,
            "temp_c": 35,
            "power_on_hours": 37429,
            "time": datetime.now(UTC).isoformat(),
        }

    @pytest.mark.parametrize(
        "spelling",
        [
            "nvme0n1",
            "nvme0",
            "/dev/nvme0n1",
            "/dev/disk/by-id/nvme-CT1000P2SSD8_2146E5E54409",
            "2146E5E54409",
            "Cache1",
        ],
    )
    async def test_every_spelling_resolves_to_the_nvme_disk(
        self, mock_config, spelling
    ):
        from unittest.mock import AsyncMock, patch

        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=self.LIVE),
            ),
            patch(
                "disk_health_mcp.server._influxdb_identity_serial",
                new=AsyncMock(return_value="2146E5E54409"),
            ),
        ):
            resolved = await server._resolve_device_argument(spelling)

        assert resolved is not None
        assert resolved.kernel == "nvme0n1"
        # A canonical name is canonical without a host round trip; the tool
        # resolves its serial from lsblk. Every other spelling resolves it here.
        assert resolved.serial in {"", "2146E5E54409"}

    @pytest.mark.parametrize("spelling", ["nvme0n1", "nvme0"])
    async def test_smart_attributes_returns_one_attribute_set(
        self, mock_config, spelling
    ):
        from unittest.mock import AsyncMock, patch

        attributes = [{"name": "Percentage_Used", "raw_value": 8}]
        attr_lookup = AsyncMock(return_value=attributes)
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=self.LIVE),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_attributes",
                attr_lookup,
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=self._nvme_sample()),
            ),
        ):
            result = await server.get_smart_attributes(spelling)

        assert "SMART Attributes for nvme0n1" in result
        assert attr_lookup.await_args.kwargs["serial"] == "2146E5E54409"
        assert attr_lookup.await_args.args[0] == "nvme0n1"

    async def test_smart_test_renders_the_resolved_kernel_name(self, mock_config):
        from unittest.mock import AsyncMock, patch

        executor = AsyncMock()
        executor.execute_safe_command = AsyncMock(
            return_value="SMART self-test started"
        )
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch("disk_health_mcp.server.executor", executor),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=self.LIVE),
            ),
        ):
            await server.run_smart_test("nvme0", "short")

        commands = [
            call.args[0] for call in executor.execute_safe_command.await_args_list
        ]
        assert "/usr/sbin/smartctl -i /dev/nvme0n1" in commands
        assert "/usr/sbin/smartctl -t short /dev/nvme0n1" in commands
        assert all(
            "-n standby" not in command for command in commands if "nvme" in command
        )
        assert all("/dev/nvme0 " not in command for command in commands)

    async def test_label_resolves_through_influxdb_to_the_live_disk(self, mock_config):
        from unittest.mock import AsyncMock, patch

        client = AsyncMock()
        client.query = AsyncMock(
            return_value=('✅ Query successful\n\n[{"serial_no": "2146E5E54409"}]')
        )
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=self.LIVE),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_client",
                new=lambda: client,
            ),
        ):
            resolved = await server._resolve_device_argument("Cache1")

        assert resolved is not None
        assert resolved.kernel == "nvme0n1"
        assert resolved.serial == "2146E5E54409"
        query = client.query.await_args.args[0]
        assert "device = 'Cache1'" in query

    async def test_resolved_command_contains_only_the_kernel_name(self, patched_server):
        from unittest.mock import AsyncMock, patch

        from server_management_lib import SecurityValidator

        patched_server["config"]["influxdb"]["enabled"] = False
        executor = patched_server["executor"]
        with patch(
            "disk_health_mcp.server._get_live_devices",
            new=AsyncMock(return_value=self.LIVE),
        ):
            await server.get_smart_attributes("2146E5E54409")

        commands = [
            call.args[0] for call in executor.execute_safe_command.await_args_list
        ]
        assert commands == ["/usr/sbin/smartctl -j -a /dev/nvme0n1"]
        assert "2146E5E54409" not in commands[0]
        assert SecurityValidator({}).is_command_safe(commands[0]) is True

    @pytest.mark.parametrize("raw", ["sda;rm -rf /", "../../etc", "sda1", ""])
    async def test_invalid_spelling_never_touches_a_data_source(self, mock_config, raw):
        from unittest.mock import AsyncMock, patch

        influx_lookup = AsyncMock(return_value=None)
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=self.LIVE),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                influx_lookup,
            ),
        ):
            result = await server.get_disk_health(raw)

        assert "Invalid device name" in result
        assert "Accepted forms" in result
        influx_lookup.assert_not_awaited()


def _nvme_tool():
    """Return the structured ``get_nvme_health`` wrapper.

    The module-level function is the text wrapper used by direct callers; the
    registered tool returns the ``ToolResponse`` that carries structured data.
    """
    return server.mcp._tool_manager.get_tool("get_nvme_health").fn


class TestNvmeDeviceTypeCheck:
    """T-11: get_nvme_health must refuse a non-NVMe disk."""

    @staticmethod
    def _sata_row():
        return {
            "device": "Parity1",
            "exit_status": 0,
            "health_ok": True,
            "model": "ST18000NT001-3NF101",
            "serial_no": "ZVTFF3JB",
            "temp_c": 30,
            "power_on_hours": 14980,
            "reallocated_sectors_count": 0,
            "wwn": "5000c500e8e30d8b",
            "time": datetime.now(UTC).isoformat(),
        }

    async def test_sata_disk_from_lsblk_is_refused(self, mock_config):
        from unittest.mock import AsyncMock, patch

        run_command = AsyncMock(return_value="should not run")
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(
                    return_value={
                        "sda": {
                            "name": "sda",
                            "model": "ST18000NT001-3NF101",
                            "serial": "ZVTFF3JB",
                            "tran": "sata",
                        }
                    }
                ),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=None),
            ),
            patch("disk_health_mcp.server._run_command", run_command),
        ):
            result = await _nvme_tool()("sda")

        assert result.ok is False
        assert "SATA (ATA/SAT)" in result.text
        assert "not NVMe" in result.text
        assert result.data["detected_type"] == "SATA (ATA/SAT)"
        assert result.data["detection_source"] == "lsblk"
        run_command.assert_not_awaited()

    async def test_influxdb_only_sata_sample_is_refused(self, mock_config):
        from unittest.mock import AsyncMock, patch

        config = dict(mock_config)
        config["host"] = {"enabled": False}
        run_command = AsyncMock(return_value="should not run")
        with (
            patch("disk_health_mcp.server.config", config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=self._sata_row()),
            ),
            patch("disk_health_mcp.server._run_command", run_command),
        ):
            result = await _nvme_tool()("sda")

        assert result.ok is False
        assert "not NVMe" in result.text
        assert result.data["detection_source"] == "influxdb"
        run_command.assert_not_awaited()

    @pytest.mark.parametrize("spelling", ["nvme0", "nvme0n1", "2146E5E54409"])
    async def test_nvme_disk_is_not_refused(self, mock_config, spelling):
        from unittest.mock import AsyncMock, patch

        live = {
            "nvme0n1": {
                "name": "nvme0n1",
                "model": "CT1000P2SSD8",
                "serial": "2146E5E54409",
                "tran": "nvme",
            }
        }
        with (
            patch("disk_health_mcp.server.config", mock_config),
            patch(
                "disk_health_mcp.server._get_live_devices",
                new=AsyncMock(return_value=live),
            ),
            patch(
                "disk_health_mcp.server._get_influxdb_latest_device",
                new=AsyncMock(return_value=TestDeviceVocabulary._nvme_sample()),
            ),
        ):
            result = await _nvme_tool()(spelling)

        assert "not NVMe" not in result.text
        assert result.data["device"] == "nvme0n1"


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


def test_failed_poll_summary_uses_readable_status_labels():
    rows = [
        {
            "device": "Data1",
            "exit_status": 2,
            "time": "2026-10-22T20:00:00Z",
        }
        for _ in range(196)
    ]

    text = server._format_failed_polls(rows)

    assert "latest status: exit_status=2 (standby/skipped)" in text
    assert "seen: standby/skipped (196)" in text
    assert "2 x196" not in text
