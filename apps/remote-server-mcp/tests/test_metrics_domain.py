"""Focused tests for the extracted metrics domain handlers."""

from unittest.mock import AsyncMock

import pytest

from remote_server_mcp import metrics
from server_management_lib import ToolOutput


class _Security:
    def __init__(self, *, query: str | None = "SELECT 1", table: str | None = None):
        self.query = query
        self.table = table

    def validate_influxdb_query(self, value: str) -> str | None:
        return value if self.query is not None else None

    def validate_influxdb_table_name(self, value: str) -> str | None:
        return value if self.table is not None else None

    def validate_prometheus_query(self, value: str) -> str | None:
        return value if self.query is not None else None


def _audit(*args, **kwargs) -> None:
    pass


def test_query_data_decodes_rows_and_objects():
    assert metrics.query_data('✅ Query successful\n\n[{"a": 1}]') == {
        "rows": [{"a": 1}],
        "row_count": 1,
    }
    assert metrics.query_data('✅ Query successful\n\n{"a": 1}') == {"result": {"a": 1}}


def test_query_data_ignores_failures_and_bad_payloads():
    assert metrics.query_data("not a success") == {}
    assert metrics.query_data("✅ Query successful") == {}
    assert metrics.query_data("✅ Query successful\n\ndata is not json") == {}


async def test_disabled_and_invalid_influx_queries_do_not_reach_the_client():
    client = AsyncMock()
    disabled = await metrics.query_influxdb(
        "SELECT 1",
        None,
        config={"influxdb": {"enabled": False}},
        security=_Security(),
        audit=_audit,
        get_client=lambda: client,
    )
    assert isinstance(disabled, str)
    assert "not enabled" in disabled

    invalid = await metrics.query_influxdb(
        "DROP TABLE cpu",
        None,
        config={"influxdb": {"enabled": True, "database": "db"}},
        security=_Security(query=None),
        audit=_audit,
        get_client=lambda: client,
    )
    assert isinstance(invalid, str)
    assert "Invalid query" in invalid
    client.query.assert_not_awaited()


async def test_influx_query_adds_group_by_advisory_and_data():
    client = AsyncMock()
    client.query.return_value = '✅ Query successful\n\n[{"host": "h"}]'

    result = await metrics.query_influxdb(
        "SELECT count(*) FROM cpu GROUP BY host",
        None,
        config={"influxdb": {"enabled": True, "database": "db"}},
        security=_Security(),
        audit=_audit,
        get_client=lambda: client,
    )

    assert isinstance(result, ToolOutput)
    assert result.data["database"] == "db"
    assert result.data["row_count"] == 1
    assert "advisory" in result.data
    assert "💡" in result.text


async def test_influx_schema_validates_table_and_reports_rows():
    client = AsyncMock()
    client.schema.return_value = '✅ Query successful\n\n[{"name": "cpu"}]'

    invalid = await metrics.get_influxdb_schema(
        'cpu"; DROP',
        None,
        config={"influxdb": {"enabled": True, "database": "db"}},
        security=_Security(table=None),
        audit=_audit,
        get_client=lambda: client,
    )
    assert isinstance(invalid, str)
    assert "Invalid table name" in invalid

    result = await metrics.get_influxdb_schema(
        "cpu",
        "other",
        config={"influxdb": {"enabled": True, "database": "db"}},
        security=_Security(table="cpu"),
        audit=_audit,
        get_client=lambda: client,
    )

    assert isinstance(result, ToolOutput)
    assert result.data == {
        "database": "other",
        "table": "cpu",
        "rows": [{"name": "cpu"}],
        "row_count": 1,
    }


async def test_prometheus_handlers_cover_disabled_invalid_and_success():
    client = AsyncMock()
    client.query.return_value = '✅ Query successful\n\n{"result": 1}'
    client.get_targets.return_value = "✅ Query successful\n\n[]"

    disabled = await metrics.query_prometheus(
        "up",
        None,
        config={"prometheus": {"enabled": False}},
        security=_Security(),
        audit=_audit,
        get_client=lambda: client,
    )
    assert isinstance(disabled, str)
    assert "not enabled" in disabled

    invalid = await metrics.query_prometheus(
        "up\x00",
        None,
        config={"prometheus": {"enabled": True}},
        security=_Security(query=None),
        audit=_audit,
        get_client=lambda: client,
    )
    assert isinstance(invalid, str)
    assert "Invalid query" in invalid

    result = await metrics.query_prometheus(
        "up",
        "123",
        config={"prometheus": {"enabled": True}},
        security=_Security(),
        audit=_audit,
        get_client=lambda: client,
    )
    assert isinstance(result, ToolOutput)
    assert result.data == {"result": {"result": 1}}

    targets = await metrics.get_prometheus_targets(
        config={"prometheus": {"enabled": True}},
        get_client=lambda: client,
    )
    assert isinstance(targets, ToolOutput)
    assert targets.data == {"rows": [], "row_count": 0}


async def test_missing_influx_database_is_reported():
    result = await metrics.query_influxdb(
        "SELECT 1",
        None,
        config={"influxdb": {"enabled": True}},
        security=_Security(),
        audit=_audit,
        get_client=AsyncMock,
    )
    assert isinstance(result, str)
    assert "No database specified" in result


@pytest.mark.parametrize("enabled", [False])
async def test_all_influx_paths_share_the_disabled_message(enabled):
    result = await metrics.get_influxdb_schema(
        None,
        None,
        config={"influxdb": {"enabled": enabled}},
        security=_Security(),
        audit=_audit,
        get_client=AsyncMock,
    )
    assert result == metrics._influxdb_disabled()
