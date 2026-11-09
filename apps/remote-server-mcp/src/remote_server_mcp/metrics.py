"""Metrics-domain handlers for the remote-server MCP.

The InfluxDB and Prometheus tools share validation rules, client lookup and a
structured-output shape, so they live together instead of inside the large
server module. The server keeps only the registration wrappers and passes the
current config, security validator, audit sink and client factory in explicitly;
that keeps tests able to swap server state without importing this module's
internals.
"""

import json
from collections.abc import Callable
from typing import Any

from server_management_lib import (
    InfluxDBClient,
    PrometheusClient,
    SecurityValidator,
    ToolOutput,
    influxdb_group_by_advisory,
)

QUERY_SUCCESS_PREFIX = "✅ Query successful"


def query_data(result: str) -> dict:
    """Extract the JSON payload from a query response, when there is one."""
    if not result.startswith(QUERY_SUCCESS_PREFIX):
        return {}
    try:
        payload = json.loads(result.split("\n\n", 1)[1])
    except (json.JSONDecodeError, IndexError):
        return {}
    if isinstance(payload, list):
        return {"rows": payload, "row_count": len(payload)}
    return {"result": payload}


def _influxdb_disabled() -> str:
    return (
        "❌ InfluxDB queries are not enabled.\n"
        "Set 'influxdb.enabled: true' in config.yaml and configure host/port."
    )


def _prometheus_disabled() -> str:
    return (
        "❌ Prometheus queries are not enabled.\n"
        "Set 'prometheus.enabled: true' in config.yaml and configure host/port."
    )


async def query_influxdb(
    query: str,
    database: str | None,
    *,
    config: dict[str, Any],
    security: SecurityValidator,
    audit: Callable[..., None],
    get_client: Callable[[], InfluxDBClient],
) -> str | ToolOutput:
    influxdb_config = config.get("influxdb", {})
    if not influxdb_config.get("enabled", False):
        return _influxdb_disabled()

    validated_query = security.validate_influxdb_query(query)
    if validated_query is None:
        audit("query_blocked", kind="influxdb", query_length=len(query))
        return (
            "❌ Invalid query. Queries must:\n"
            "- Be a single SELECT (read-only only)\n"
            "- Not contain SQL comments (-- or /* */)\n"
            "- Not contain control characters"
        )

    db = database or influxdb_config.get("database")
    if not db:
        return (
            "❌ No database specified. Provide 'database' parameter or set "
            "'influxdb.database' in config.yaml."
        )

    client = get_client()
    result = await client.query(validated_query, database=db)
    advisory = influxdb_group_by_advisory(validated_query)
    text = result if advisory is None else f"{result}\n\n💡 {advisory}"
    data: dict = {"database": db, **query_data(result)}
    if advisory is not None:
        data["advisory"] = advisory
    return ToolOutput(text, data=data)


async def get_influxdb_schema(
    table: str | None,
    database: str | None,
    *,
    config: dict[str, Any],
    security: SecurityValidator,
    audit: Callable[..., None],
    get_client: Callable[[], InfluxDBClient],
) -> str | ToolOutput:
    influxdb_config = config.get("influxdb", {})
    if not influxdb_config.get("enabled", False):
        return _influxdb_disabled()

    validated_table: str | None = None
    if table is not None:
        validated_table = security.validate_influxdb_table_name(table)
        if validated_table is None:
            audit("schema_blocked", kind="influxdb", table=table)
            return (
                f"❌ Invalid table name: {table}\n"
                "Use a plain name or schema.table (letters, digits, underscore, "
                "and one dot). No quotes or spaces."
            )

    db = database or influxdb_config.get("database")
    if not db:
        return (
            "❌ No database specified. Provide 'database' parameter or set "
            "'influxdb.database' in config.yaml."
        )

    client = get_client()
    result = await client.schema(validated_table, database=db)
    data: dict = {
        "database": db,
        "table": validated_table,
        **query_data(result),
    }
    return ToolOutput(result, data=data)


async def query_prometheus(
    query: str,
    time: str | None,
    *,
    config: dict[str, Any],
    security: SecurityValidator,
    audit: Callable[..., None],
    get_client: Callable[[], PrometheusClient],
) -> str | ToolOutput:
    prometheus_config = config.get("prometheus", {})
    if not prometheus_config.get("enabled", False):
        return _prometheus_disabled()

    validated_query = security.validate_prometheus_query(query)
    if validated_query is None:
        audit("query_blocked", kind="prometheus", query_length=len(query))
        return (
            "❌ Invalid query. Queries must:\n"
            "- Not contain null bytes or control characters other than newline/tab\n"
            "- Be at most 5000 characters\n"
            "- Be a single PromQL expression"
        )

    client = get_client()
    result = await client.query(validated_query, time)
    return ToolOutput(result, data=query_data(result))


async def get_prometheus_targets(
    *,
    config: dict[str, Any],
    get_client: Callable[[], PrometheusClient],
) -> str | ToolOutput:
    prometheus_config = config.get("prometheus", {})
    if not prometheus_config.get("enabled", False):
        return _prometheus_disabled()

    client = get_client()
    result = await client.get_targets()
    return ToolOutput(result, data=query_data(result))
