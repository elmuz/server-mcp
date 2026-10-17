"""
Tests for server_management_lib.http_clients module.

Covers:
- InfluxDBClient: queries, error handling, timeouts, auth
- PrometheusClient: queries, targets, error handling, timeouts, auth

All HTTP operations are mocked - no real network calls.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

from server_management_lib.http_clients import InfluxDBClient, PrometheusClient

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
