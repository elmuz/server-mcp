"""
Tests for server_management_lib.http_clients module.

Covers:
- InfluxDBClient: queries, error handling, timeouts, auth
- PrometheusClient: queries, targets, error handling, timeouts, auth

All HTTP operations are mocked - no real network calls.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from server_management_lib.http_clients import (
    InfluxDBClient,
    PrometheusClient,
    influxdb_group_by_advisory,
)

# ============================================================================
# InfluxDBClient Tests
# ============================================================================


class TestInfluxDBClientBasic:
    """Test InfluxDBClient basic functionality."""

    def test_no_database_error(self):
        client = InfluxDBClient(host="localhost", database=None)

        async def run():
            result = await client.query("SELECT * FROM cpu")
            assert "No database" in result

        asyncio.run(run())

    def test_query_limit_capped(self):
        """Query limit should be capped at 10000."""
        client = InfluxDBClient(host="localhost", database="testdb", query_limit=50000)
        assert client.query_limit == 10000

    def test_query_limit_respected(self):
        """Query limit should respect the provided value."""
        client = InfluxDBClient(host="localhost", database="testdb", query_limit=500)
        assert client.query_limit == 500

    def test_https_scheme(self):
        client = InfluxDBClient(host="localhost", database="testdb", use_https=True)
        assert client.scheme == "https"

    def test_with_token_auth(self):
        client = InfluxDBClient(host="localhost", database="testdb", token="test-token")
        assert client.token == "test-token"


class TestInfluxDBGroupByAdvisory:
    """InfluxDB v3 SQL drops GROUP BY keys that are not projected."""

    def test_missing_group_key_is_reported(self):
        advisory = influxdb_group_by_advisory(
            "SELECT count(*) FROM smart_device GROUP BY device"
        )

        assert advisory is not None
        assert "device" in advisory
        assert "add" in advisory

    def test_projected_group_key_is_not_reported(self):
        assert (
            influxdb_group_by_advisory(
                "SELECT device, count(*) FROM smart_device GROUP BY device"
            )
            is None
        )

    def test_star_and_non_sql_queries_are_ignored(self):
        assert influxdb_group_by_advisory("SELECT * FROM cpu GROUP BY host") is None
        assert influxdb_group_by_advisory("SELECT count(*) FROM cpu") is None
        assert influxdb_group_by_advisory("not sql") is None

    def test_multiple_columns_and_limit(self):
        advisory = influxdb_group_by_advisory(
            "SELECT count(*) FROM cpu GROUP BY host, region LIMIT 10"
        )

        assert advisory is not None
        assert "host, region" in advisory


class TestInfluxDBClientQueries:
    """Test InfluxDBClient query execution."""

    def test_query_success(self):
        client = InfluxDBClient(host="localhost", database="testdb", token="fake-token")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=[{"time": "2024-01-01"}])

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu LIMIT 1")
                assert "Query successful" in result

        asyncio.run(run())

    def test_query_http_error_with_time_filter_hint(self):
        """HTTP errors should not show time filter hint if query has time filter."""
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal error")

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query(
                    "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour'"
                )
                assert "Tip: InfluxDB 3 Core" not in result

        asyncio.run(run())

    def test_query_http_error_without_time_filter(self):
        """HTTP errors should show time filter hint if query lacks time filter."""
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal error")

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu")
                assert "Tip: InfluxDB 3 Core" in result

        asyncio.run(run())

    def test_query_connection_error(self):
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_session = MagicMock()
            mock_session.post.side_effect = aiohttp.ClientError("Connection refused")
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu")
                assert "Connection error" in result

        asyncio.run(run())

    def test_query_timeout(self):
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_session = MagicMock()
            mock_session.post.side_effect = TimeoutError()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu")
                assert "timed out" in result

        asyncio.run(run())


# ============================================================================
# PrometheusClient Tests
# ============================================================================


class TestPrometheusClientBasic:
    """Test PrometheusClient basic functionality."""

    def test_https_scheme(self):
        client = PrometheusClient(host="localhost", port=9090, use_https=True)
        assert client.scheme == "https"

    def test_with_token(self):
        client = PrometheusClient(host="localhost", port=9090, token="test-token")
        assert client.token == "test-token"


class TestPrometheusClientQueries:
    """Test PrometheusClient query execution."""

    def test_query_success(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"resultType": "vector"}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "Query successful" in result

        asyncio.run(run())

    def test_query_with_time_parameter(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"resultType": "vector"}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up", time="2024-01-01T00:00:00Z")
                assert "Query successful" in result

        asyncio.run(run())

    def test_query_error_response(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "error",
                    "errorType": "bad_data",
                    "error": "Invalid query",
                }
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("invalid{")
                assert "PromQL query error" in result
                assert "bad_data" in result

        asyncio.run(run())

    def test_query_http_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal server error")

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "HTTP 500" in result

        asyncio.run(run())

    def test_query_connection_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = aiohttp.ClientError("Connection refused")
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "Connection error" in result

        asyncio.run(run())

    def test_query_timeout(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = TimeoutError()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "timed out" in result

        asyncio.run(run())

    def test_query_with_token_header(self):
        """Token should be added to the Authorization header."""
        client = PrometheusClient(host="localhost", port=9090, token="test-token")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"resultType": "vector"}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "Query successful" in result
                # Verify headers were set
                call_args = mock_session.get.call_args
                assert call_args is not None
                headers = call_args[1].get("headers", {})
                assert headers.get("Authorization") == "Bearer test-token"

        asyncio.run(run())


class TestPrometheusClientTargets:
    """Test PrometheusClient target inspection."""

    def test_get_targets_success(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {
                                "labels": {"job": "node", "instance": "localhost:9100"},
                                "health": "up",
                                "lastError": "",
                            }
                        ]
                    },
                }
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "Found 1 active targets" in result
                assert "node/localhost:9100: up" in result

        asyncio.run(run())

    def test_get_targets_empty(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"activeTargets": []}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "No active targets" in result

        asyncio.run(run())

    def test_get_targets_with_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {
                                "labels": {"job": "node", "instance": "localhost:9100"},
                                "health": "down",
                                "lastError": "connection refused",
                            }
                        ]
                    },
                }
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "connection refused" in result

        asyncio.run(run())

    def test_get_targets_http_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Server error")

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "HTTP 500" in result

        asyncio.run(run())

    def test_get_targets_connection_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = aiohttp.ClientError("Connection refused")
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "Connection error" in result

        asyncio.run(run())

    def test_get_targets_timeout(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = TimeoutError()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "timed out" in result

        asyncio.run(run())

    def test_get_targets_with_token_header(self):
        """Token should be added to the Authorization header."""
        client = PrometheusClient(host="localhost", port=9090, token="test-token")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {"activeTargets": []},
                }
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "No active targets" in result
                # Verify headers were set
                call_args = mock_session.get.call_args
                assert call_args is not None
                headers = call_args[1].get("headers", {})
                assert headers.get("Authorization") == "Bearer test-token"

        asyncio.run(run())

    def test_get_targets_unexpected_response(self):
        """Should handle unexpected JSON responses gracefully."""
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"status": "error", "data": {}})

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "Unexpected response" in result

        asyncio.run(run())


class TestQueryAudit:
    """HTTP query metadata is audited without persisting the query text."""

    def test_influxdb_query_audit_metadata(self, tmp_path):
        from server_management_lib import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path, enabled=True)
        client = InfluxDBClient(host="localhost", database="testdb", audit=audit)
        query = "SELECT * FROM cpu WHERE note = 'supersecret'"

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=[{"time": "2024-01-01"}])

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                await client.query(query)

        asyncio.run(run())

        raw = log_path.read_text(encoding="utf-8")
        record = json.loads(raw.splitlines()[0])
        assert record["event"] == "influxdb_query"
        assert record["database"] == "testdb"
        assert record["status"] == 200
        assert record["query_length"] == len(query + "\nLIMIT 1000")
        assert len(record["query_sha256"]) == 64
        assert "duration_ms" in record
        assert "SELECT" not in raw
        assert "supersecret" not in raw

    def test_prometheus_query_audit_metadata(self, tmp_path):
        from server_management_lib import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path, enabled=True)
        client = PrometheusClient(host="localhost", audit=audit)
        query = 'up{instance="topsecret"}'

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"resultType": "vector"}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                await client.query(query)

        asyncio.run(run())

        raw = log_path.read_text(encoding="utf-8")
        record = json.loads(raw.splitlines()[0])
        assert record["event"] == "prometheus_query"
        assert record["status"] == 200
        assert record["query_length"] == len(query)
        assert len(record["query_sha256"]) == 64
        assert "topsecret" not in raw


class TestQueryHelpers:
    def test_ensure_limit_appends_when_missing(self):
        from server_management_lib.http_clients import _ensure_limit

        assert _ensure_limit("SELECT * FROM cpu", 10) == ("SELECT * FROM cpu\nLIMIT 10")

    def test_ensure_limit_keeps_existing_limit(self):
        from server_management_lib.http_clients import _ensure_limit

        query = "SELECT * FROM cpu LIMIT 5"
        assert _ensure_limit(query, 10) == query

    def test_ensure_limit_after_line_comment(self):
        from server_management_lib.http_clients import _ensure_limit

        result = _ensure_limit("SELECT * FROM cpu -- note", 10)
        assert result.endswith("\nLIMIT 10")
        assert "-- note" in result

    def test_parse_duration(self):
        from server_management_lib.http_clients import parse_duration

        assert parse_duration("30s") == 30
        assert parse_duration("1m") == 60
        assert parse_duration("500ms") == 0.5
        assert parse_duration("15") == 15
        assert parse_duration("bogus") == 30


class TestLimitHardening:
    """A LIMIT token must be a real top-level clause, not a literal (P1-12)."""

    def test_limit_inside_string_literal_is_ignored(self):
        from server_management_lib.http_clients import _ensure_limit

        query = "SELECT * FROM cpu WHERE note = 'LIMIT 5'"

        assert _ensure_limit(query, 10) == f"{query}\nLIMIT 10"

    def test_limit_inside_subquery_is_ignored_for_the_outer_query(self):
        from server_management_lib.http_clients import _ensure_limit

        query = "SELECT * FROM cpu WHERE id IN (SELECT id FROM x LIMIT 5)"

        assert _ensure_limit(query, 10) == f"{query}\nLIMIT 10"

    def test_oversized_limit_is_clamped(self):
        from server_management_lib.http_clients import _ensure_limit

        assert (
            _ensure_limit("SELECT * FROM cpu LIMIT 10000000", 10)
            == "SELECT * FROM cpu LIMIT 10"
        )

    def test_limit_word_in_a_column_name_is_not_a_clause(self):
        from server_management_lib.http_clients import _ensure_limit

        query = "SELECT limit FROM cpu"

        assert _ensure_limit(query, 10) == f"{query}\nLIMIT 10"


class TestSessionReuse:
    """Each client owns one HTTP session instead of opening one per query."""

    def test_influxdb_reuses_one_session_and_closes_it(self):
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=[{"time": "2024-01-01"}])

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post.return_value = mock_cm
            mock_session.close = AsyncMock()

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ) as session_cls:
                await client.query("SELECT * FROM cpu")
                await client.query("SELECT * FROM cpu")
                assert session_cls.call_count == 1

                await client.close()
                mock_session.close.assert_awaited_once()
                await client.close()
                mock_session.close.assert_awaited_once()

        asyncio.run(run())

    def test_prometheus_reuses_one_session(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"resultType": "vector"}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.close = AsyncMock()

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ) as session_cls:
                await client.query("up")
                await client.query("up")
                assert session_cls.call_count == 1
                await client.close()

        asyncio.run(run())


class TestTargetsAudit:
    def test_get_targets_is_audited(self, tmp_path):
        from server_management_lib import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path, enabled=True)
        client = PrometheusClient(host="localhost", audit=audit)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {"activeTargets": []},
                }
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                await client.get_targets()

        asyncio.run(run())

        record = json.loads(log_path.read_text().splitlines()[0])
        assert record["event"] == "prometheus_targets"
        assert record["status"] == 200
        assert "duration_ms" in record


# ============================================================================
# Proxy / gateway error page handling
# ============================================================================

SWAG_ERROR_PAGE = (
    "<!DOCTYPE html>\n"
    '<html lang="en">\n'
    "<head><title>Service Unavailable</title></head>\n"
    "<body>\n"
    "<h1>Service Unavailable</h1>\n"
    '<div class="footer">catafal.co</div>\n'
    + ("padding " * 1000)
    + "UNIQUE-PAGE-TAIL\n"
    "</body>\n</html>"
)


def _make_mock_response(
    status,
    *,
    text="",
    content_type="application/json",
    json_payload=None,
    json_error=None,
):
    """Build a mocked aiohttp response and its session for one request."""
    response = MagicMock()
    response.status = status
    response.content_type = content_type
    response.text = AsyncMock(return_value=text)
    if json_error is not None:
        response.json = AsyncMock(side_effect=json_error)
    else:
        response.json = AsyncMock(return_value=json_payload)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.post.return_value = mock_cm
    session.get.return_value = mock_cm
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return response, session


def _content_type_error():
    """The error aiohttp raises for ``response.json()`` on non-JSON bodies."""
    return aiohttp.ContentTypeError(MagicMock(), (), message="unexpected mimetype")


class TestInfluxDBProxyErrors:
    """InfluxDB client distinguishes API errors from proxy/gateway pages."""

    def _query(self, status, query="SELECT * FROM cpu WHERE time > '2024-01-01'", **kw):
        client = InfluxDBClient(
            host="influxdb.catafal.co", port=443, use_https=True, database="testdb"
        )
        _, session = _make_mock_response(status, **kw)
        with patch(
            "server_management_lib.http_clients.aiohttp.ClientSession",
            return_value=session,
        ):
            return asyncio.run(client.query(query))

    def test_json_error_body_is_passed_through(self):
        body = '{"error": "Schema error: No field named healthy."}'
        result = self._query(500, text=body, content_type="application/json")

        assert "InfluxDB query failed (HTTP 500)" in result
        assert "Schema error: No field named healthy." in result
        assert "reverse proxy" not in result

    def test_html_500_is_reported_as_proxy_page(self):
        result = self._query(500, text=SWAG_ERROR_PAGE, content_type="text/html")

        assert "InfluxDB query failed" not in result
        assert "Received an HTML page" in result
        assert "https://influxdb.catafal.co:443/api/v3/query_sql" in result
        assert "HTTP 500" in result
        assert "reverse proxy" in result
        assert "proxy_intercept_errors" in result
        # The themed page must not be dumped verbatim.
        assert "UNIQUE-PAGE-TAIL" not in result
        assert len(result) < 2000

    def test_html_502_is_reported_as_proxy_page(self):
        result = self._query(502, text=SWAG_ERROR_PAGE, content_type="text/html")

        assert "InfluxDB query failed" not in result
        assert "Received an HTML page" in result
        assert "HTTP 502" in result
        assert "reverse proxy" in result

    def test_html_detected_without_content_type(self):
        result = self._query(503, text=SWAG_ERROR_PAGE, content_type="")

        assert "Received an HTML page" in result
        assert "HTTP 503" in result

    def test_200_html_is_caught_instead_of_raising(self):
        result = self._query(
            200,
            text=SWAG_ERROR_PAGE,
            content_type="text/html",
            json_error=_content_type_error(),
        )

        assert "Received an HTML page" in result
        assert "HTTP 200" in result
        assert "InfluxDB query failed" not in result
        assert "UNIQUE-PAGE-TAIL" not in result

    def test_200_malformed_json_is_reported_as_decode_error(self):
        result = self._query(
            200,
            text="{not json",
            content_type="application/json",
            json_error=json.JSONDecodeError("Expecting value", "", 0),
        )

        assert "not valid JSON" in result
        assert "InfluxDB" in result
        assert "Query successful" not in result


class TestPrometheusProxyErrors:
    """Prometheus client distinguishes API errors from proxy/gateway pages."""

    def _request(self, method, status, *, time=None, **kw):
        client = PrometheusClient(
            host="prometheus.catafal.co", port=443, use_https=True
        )
        _, session = _make_mock_response(status, **kw)
        with patch(
            "server_management_lib.http_clients.aiohttp.ClientSession",
            return_value=session,
        ):
            if method == "query":
                return asyncio.run(client.query("up", time))
            return asyncio.run(client.get_targets())

    @pytest.mark.parametrize("method", ["query", "targets"])
    def test_html_http_error_is_reported_as_proxy_page(self, method):
        result = self._request(
            method, 502, text=SWAG_ERROR_PAGE, content_type="text/html"
        )

        assert "Received an HTML page" in result
        assert "HTTP 502" in result
        assert "reverse proxy" in result
        assert "UNIQUE-PAGE-TAIL" not in result
        assert "query failed" not in result
        assert "Failed to get targets" not in result

    @pytest.mark.parametrize("method", ["query", "targets"])
    def test_200_html_is_caught_instead_of_raising(self, method):
        result = self._request(
            method,
            200,
            text=SWAG_ERROR_PAGE,
            content_type="text/html",
            json_error=_content_type_error(),
        )

        assert "Received an HTML page" in result
        assert "HTTP 200" in result
        assert "Query successful" not in result
        assert "UNIQUE-PAGE-TAIL" not in result

    @pytest.mark.parametrize("method", ["query", "targets"])
    def test_200_malformed_json_is_reported_as_decode_error(self, method):
        result = self._request(
            method,
            200,
            text="{not json",
            content_type="application/json",
            json_error=json.JSONDecodeError("Expecting value", "", 0),
        )

        assert "not valid JSON" in result
        assert "Prometheus" in result

    def test_json_http_error_is_passed_through(self):
        result = self._request(
            "targets",
            500,
            text="Internal server error",
            content_type="text/plain",
        )

        assert "Failed to get targets (HTTP 500)" in result
        assert "Received an HTML page" not in result


class TestTimeFilterHintAccuracy:
    """The file-scan hint must follow the actual WHERE clause."""

    def _query(self, query):
        client = InfluxDBClient(host="localhost", database="testdb")
        _, session = _make_mock_response(
            500, text="Internal error", content_type="text/plain"
        )
        with patch(
            "server_management_lib.http_clients.aiohttp.ClientSession",
            return_value=session,
        ):
            return asyncio.run(client.query(query))

    def test_select_time_without_where_still_gets_hint(self):
        from server_management_lib.http_clients import _has_time_predicate

        assert _has_time_predicate("SELECT time FROM cpu") is False
        assert "Tip: InfluxDB 3 Core" in self._query("SELECT time FROM cpu")

    def test_where_time_predicate_suppresses_hint(self):
        from server_management_lib.http_clients import _has_time_predicate

        query = "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour'"
        assert _has_time_predicate(query) is True
        assert "Tip: InfluxDB 3 Core" not in self._query(query)

    def test_time_in_a_string_literal_is_not_a_predicate(self):
        from server_management_lib.http_clients import _has_time_predicate

        query = "SELECT * FROM cpu WHERE note = 'time'"
        assert _has_time_predicate(query) is False
        assert "Tip: InfluxDB 3 Core" in self._query(query)

    def test_group_by_time_is_not_a_where_predicate(self):
        from server_management_lib.http_clients import _has_time_predicate

        query = "SELECT count(*) FROM cpu WHERE host = 'x' GROUP BY time"
        assert _has_time_predicate(query) is False

    def test_scan_limit_error_still_hints_with_time_filter(self):
        from server_management_lib.http_clients import _should_show_scan_hint

        assert (
            _should_show_scan_hint(
                "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour'",
                "error: query exceeded the file scan limit",
            )
            is True
        )
