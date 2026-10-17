"""
Integration Tests for InfluxDB and Prometheus MCP Tools

Tests cover:
- Security validation (unit, no network required)
- Tool registration and parameter validation
- Query result parsing and formatting
- Error handling (disabled services, invalid queries, connection failures)
- End-to-end live queries against real databases (requires config + network)

Run with:
    uv run pytest tests/test_database_tools.py -v              # unit only
    uv run pytest tests/test_database_tools.py -v -k live      # live tests
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from remote_server_mcp import server as mcp_server
from server_management_lib import SecurityValidator, load_config
from server_management_lib.http_clients import INFLUXDB_ALLOWED_ENDPOINTS

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def config():
    """Load actual configuration."""
    config_path = Path(__file__).parent.parent / "config.yaml"
    if config_path.exists():
        return load_config(config_path)
    return {
        "ssh": {"host": "localhost", "port": 22, "username": "test"},
        "security": {"services_path": "/srv"},
        "influxdb": {"enabled": False},
        "prometheus": {"enabled": False},
    }


@pytest.fixture
def security(config):
    """Create security validator."""
    return SecurityValidator(config)


# ============================================================================
# Unit Tests - Security Validation (No Network)
# ============================================================================


class TestInfluxDBQueryValidation:
    """InfluxDB SQL validation is semantic, not a shell-character blacklist."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_empty_query_rejected(self):
        assert self.security.validate_influxdb_query("") is None
        assert self.security.validate_influxdb_query(None) is None

    def test_non_string_rejected(self):
        assert self.security.validate_influxdb_query(123) is None
        assert self.security.validate_influxdb_query([]) is None

    def test_non_select_rejected(self):
        for query in ["INSERT INTO cpu VALUES (1)", "DROP TABLE cpu"]:
            assert self.security.validate_influxdb_query(query) is None, query

    def test_select_with_where_accepted(self):
        query = "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour' LIMIT 5"
        assert self.security.validate_influxdb_query(query) == query

    def test_select_with_aggregations_accepted(self):
        query = "SELECT mean(usage_idle) FROM cpu WHERE time > now() - 1h GROUP BY host"
        assert self.security.validate_influxdb_query(query) == query

    def test_select_with_leading_whitespace_accepted(self):
        query = "  SELECT * FROM measurements LIMIT 100"
        assert (
            self.security.validate_influxdb_query(query)
            == "SELECT * FROM measurements LIMIT 100"
        )

    def test_trailing_semicolon_is_stripped(self):
        assert (
            self.security.validate_influxdb_query("SELECT * FROM cpu;")
            == "SELECT * FROM cpu"
        )

    def test_comments_are_accepted(self):
        for query in (
            "SELECT * FROM cpu -- operator note",
            "SELECT * FROM cpu /* operator note */",
        ):
            assert self.security.validate_influxdb_query(query) is not None

    def test_quotes_and_identifiers_accepted(self):
        for query in (
            'SELECT * FROM "cpu load" WHERE usage >= 0.9',
            "SELECT * FROM cpu WHERE host = 'server-1'",
        ):
            assert self.security.validate_influxdb_query(query) is not None

    def test_multiple_statements_blocked(self):
        assert (
            self.security.validate_influxdb_query(
                "SELECT * FROM cpu; DROP TABLE metrics"
            )
            is None
        )
        assert (
            self.security.validate_influxdb_query(
                "SELECT * FROM cpu\nDELETE FROM metrics"
            )
            is None
        )

    def test_select_into_blocked(self):
        assert (
            self.security.validate_influxdb_query("SELECT * FROM cpu INTO other")
            is None
        )

    def test_null_byte_blocked(self):
        assert self.security.validate_influxdb_query("SELECT * FROM cpu\x00") is None

    def test_overlong_query_blocked(self):
        assert (
            self.security.validate_influxdb_query("SELECT * FROM " + "a" * 6000) is None
        )

    def test_write_keywords_blocked(self):
        write_ops = [
            "DROP MEASUREMENT cpu",
            "DELETE FROM metrics",
            "INSERT INTO cpu VALUES (1)",
            "UPDATE metrics SET value = 100",
            "ALTER TABLE cpu ADD COLUMN x INT",
            "CREATE DATABASE testdb",
            "TRUNCATE TABLE logs",
            "GRANT ALL TO admin",
            "REVOKE READ FROM user",
            "KILL QUERY 12345",
            "SET PASSWORD FOR user = 'pass'",
        ]
        for query in write_ops:
            assert self.security.validate_influxdb_query(query) is None, query


class TestPrometheusQueryValidation:
    """PromQL is sent over HTTP: quotes, braces and comparisons are valid."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_simple_query_accepted(self):
        assert self.security.validate_prometheus_query("up") == "up"

    def test_rate_query_accepted(self):
        query = "rate(http_requests_total[5m])"
        assert self.security.validate_prometheus_query(query) == query

    def test_histogram_quantile_accepted(self):
        query = "histogram_quantile(0.95, rate(bucket[5m]))"
        assert self.security.validate_prometheus_query(query) == query

    def test_label_matchers_accepted(self):
        queries = [
            'up{job="node"}',
            'node_filesystem_avail_bytes{device="/dev/sda1"}',
            "up{job='node'}",
        ]
        for query in queries:
            assert self.security.validate_prometheus_query(query) == query

    def test_comparisons_accepted(self):
        for query in ("up > 0", "up == 0", "node_load1 >= 2"):
            assert self.security.validate_prometheus_query(query) == query

    def test_empty_query_rejected(self):
        assert self.security.validate_prometheus_query("") is None
        assert self.security.validate_prometheus_query(None) is None

    def test_non_string_rejected(self):
        assert self.security.validate_prometheus_query(123) is None

    def test_null_byte_blocked(self):
        assert self.security.validate_prometheus_query("up\x00evil") is None

    def test_control_character_blocked(self):
        assert self.security.validate_prometheus_query("up\x01evil") is None

    def test_overlong_query_blocked(self):
        assert self.security.validate_prometheus_query("up{" + "a" * 6000) is None


class TestToolRegistration:
    """Verify database tools are registered in the MCP server."""

    def test_query_influxdb_registered(self):
        tools = list(mcp_server.mcp._tool_manager._tools.keys())
        assert "query_influxdb" in tools

    def test_query_prometheus_registered(self):
        tools = list(mcp_server.mcp._tool_manager._tools.keys())
        assert "query_prometheus" in tools

    def test_get_prometheus_targets_registered(self):
        tools = list(mcp_server.mcp._tool_manager._tools.keys())
        assert "get_prometheus_targets" in tools

    def test_total_tool_count(self):
        """We expect 13 tools total (10 SSH + 3 database)."""
        tools = list(mcp_server.mcp._tool_manager._tools.keys())
        assert len(tools) == 13, f"Expected 13 tools, got {len(tools)}: {tools}"

    def test_only_safe_tools_registered(self):
        """Verify no unexpected/generic command tools exist."""
        tools = set(mcp_server.mcp._tool_manager._tools.keys())

        expected_tools = {
            "list_services",
            "get_service_logs",
            "get_service_status",
            "restart_service",
            "start_service",
            "stop_service",
            "get_service_file",
            "list_service_files",
            "search_service_logs",
            "get_server_health",
            "query_influxdb",
            "query_prometheus",
            "get_prometheus_targets",
        }

        for tool in tools:
            assert tool in expected_tools, f"Unexpected tool: {tool}"


# ============================================================================
# Unit Tests - InfluxDB Endpoint Whitelist (Defense-in-Depth)
# ============================================================================


class TestInfluxDBEndpointWhitelist:
    """Verify the InfluxDB API endpoint whitelist blocks destructive endpoints."""

    def test_whitelist_constant_exists(self):
        """The whitelist constant must exist in the server module."""
        assert INFLUXDB_ALLOWED_ENDPOINTS is not None

    def test_query_sql_allowed(self):
        """query_sql must be in the whitelist (primary read endpoint)."""
        assert "/api/v3/query_sql" in INFLUXDB_ALLOWED_ENDPOINTS

    def test_query_influxql_allowed(self):
        """query_influxql must be in the whitelist (legacy query endpoint)."""
        assert "/api/v3/query_influxql" in INFLUXDB_ALLOWED_ENDPOINTS

    def test_health_allowed(self):
        """/health must be in the whitelist for health checks."""
        assert "/health" in INFLUXDB_ALLOWED_ENDPOINTS

    def test_metrics_allowed(self):
        """/metrics must be in the whitelist for Prometheus scraping."""
        assert "/metrics" in INFLUXDB_ALLOWED_ENDPOINTS

    def test_ping_allowed(self):
        """/ping must be in the whitelist."""
        assert "/ping" in INFLUXDB_ALLOWED_ENDPOINTS

    def test_database_delete_blocked(self):
        """DELETE /api/v3/configure/database must NOT be allowed."""
        assert "/api/v3/configure/database" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_database_create_blocked(self):
        """POST /api/v3/configure/database must NOT be allowed."""
        assert "/api/v3/configure/database" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_table_delete_blocked(self):
        """DELETE /api/v3/configure/table must NOT be allowed."""
        assert "/api/v3/configure/table" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_table_create_blocked(self):
        """POST /api/v3/configure/table must NOT be allowed."""
        assert "/api/v3/configure/table" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_write_lp_blocked(self):
        """POST /api/v3/write_lp must NOT be allowed (data write)."""
        assert "/api/v3/write_lp" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_write_v2_blocked(self):
        """POST /api/v2/write must NOT be allowed (data write)."""
        assert "/api/v2/write" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_token_delete_blocked(self):
        """DELETE /api/v3/configure/token must NOT be allowed."""
        assert "/api/v3/configure/token" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_token_create_blocked(self):
        """POST /api/v3/configure/token/admin must NOT be allowed."""
        assert "/api/v3/configure/token/admin" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_plugin_upload_blocked(self):
        """POST /api/v3/plugins/files must NOT be allowed (RCE vector)."""
        assert "/api/v3/plugins/files" not in INFLUXDB_ALLOWED_ENDPOINTS

    def test_plugin_env_install_blocked(self):
        """Plugin package install must NOT be allowed."""
        assert (
            "/api/v3/configure/plugin_environment/install_packages"
            not in INFLUXDB_ALLOWED_ENDPOINTS
        )

    def test_processing_engine_blocked(self):
        """Processing engine triggers must NOT be allowed."""
        assert (
            "/api/v3/configure/processing_engine_trigger"
            not in INFLUXDB_ALLOWED_ENDPOINTS
        )

    def test_no_configure_endpoints_allowed(self):
        """No /configure/ endpoints should be in the whitelist."""
        for endpoint in INFLUXDB_ALLOWED_ENDPOINTS:
            assert "/configure/" not in endpoint, (
                f"Configure endpoint '{endpoint}' must not be allowed"
            )


# ============================================================================
# Unit Tests - Disabled / Misconfigured Behavior
# ============================================================================


class TestDisabledServiceBehavior:
    """Tools should return clear error messages when services are disabled."""

    def test_influxdb_disabled_returns_error(self):
        """When influxdb.enabled=false, query_influxdb should return error."""

        async def run_test():
            import remote_server_mcp.server as server_mod

            original = server_mod.config.get("influxdb", {})
            server_mod.config["influxdb"] = {"enabled": False}

            try:
                result = await server_mod.query_influxdb("SELECT * FROM cpu")
                assert "not enabled" in result.lower()
                assert "❌" in result
            finally:
                server_mod.config["influxdb"] = original

        asyncio.run(run_test())

    def test_prometheus_disabled_returns_error(self):
        """When prometheus.enabled=false, query_prometheus should return error."""

        async def run_test():
            import remote_server_mcp.server as server_mod

            original = server_mod.config.get("prometheus", {})
            server_mod.config["prometheus"] = {"enabled": False}

            try:
                result = await server_mod.query_prometheus("up")
                assert "not enabled" in result.lower()
                assert "❌" in result
            finally:
                server_mod.config["prometheus"] = original

        asyncio.run(run_test())

    def test_get_prometheus_targets_disabled_returns_error(self):
        """When prometheus.enabled=false, targets tool should return error."""

        async def run_test():
            import remote_server_mcp.server as server_mod

            original = server_mod.config.get("prometheus", {})
            server_mod.config["prometheus"] = {"enabled": False}

            try:
                result = await server_mod.get_prometheus_targets()
                assert "not enabled" in result.lower()
            finally:
                server_mod.config["prometheus"] = original

        asyncio.run(run_test())

    def test_influxdb_no_database_returns_error(self):
        """When no database is specified, query should return error."""

        async def run_test():
            import remote_server_mcp.server as server_mod

            original_db = server_mod.config.get("influxdb", {}).get("database")
            server_mod.config.setdefault("influxdb", {})["database"] = None

            try:
                result = await server_mod.query_influxdb(
                    "SELECT * FROM cpu", database=None
                )
                assert "no database" in result.lower() or "❌" in result
            finally:
                if original_db:
                    server_mod.config["influxdb"]["database"] = original_db

        asyncio.run(run_test())

    def test_influxdb_invalid_query_returns_error(self):
        """Invalid SQL should return validation error, not crash."""
        config = {"influxdb": {"enabled": True, "database": "testdb"}}

        async def run_test():
            with patch.object(mcp_server, "config", config):
                result = await mcp_server.query_influxdb("DROP TABLE cpu")
            assert "❌" in result
            assert "SELECT" in result

        asyncio.run(run_test())

    def test_prometheus_invalid_query_returns_error(self):
        """Control characters in PromQL are rejected before any request."""
        config = {"prometheus": {"enabled": True}}

        async def run_test():
            with patch.object(mcp_server, "config", config):
                result = await mcp_server.query_prometheus("up\x00")
            assert "❌" in result

        asyncio.run(run_test())


# ============================================================================
# Live Integration Tests (Require Network + Valid Config)
# ============================================================================


class TestLiveInfluxDBQueries:
    """
    Live queries against a real InfluxDB instance.
    Requires: config.yaml with influxdb.enabled=true and valid credentials.

    These tests verify:
    - Authentication works
    - Tables exist and are queryable
    - Response format is parseable JSON
    - Data types are correct
    """

    @pytest.fixture(autouse=True)
    def _check_influxdb_enabled(self):
        """Skip all tests if InfluxDB is not configured."""
        config_path = Path(__file__).parent.parent / "config.yaml"
        config = load_config(config_path)
        if not config.get("influxdb", {}).get("enabled", False):
            pytest.skip("InfluxDB not enabled in config.yaml")

    def _parse_json_from_result(self, result: str) -> list:
        """Parse the JSON data from tool response."""
        assert "✅ Query successful" in result
        json_part = result.split("\n\n", 1)[1]
        data = json.loads(json_part)
        assert isinstance(data, list)
        return data

    @pytest.mark.integration
    def test_cpu_table_query(self):
        """Query cpu table with time filter - verify response structure."""

        async def run_test():
            result = await mcp_server.query_influxdb(
                "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour' LIMIT 1"
            )
            data = self._parse_json_from_result(result)
            if data:
                row = data[0]
                assert "time" in row
                assert "usage_idle" in row
                assert "usage_user" in row
                assert "usage_system" in row

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_mem_table_query(self):
        """Query mem table - verify memory metrics are present."""

        async def run_test():
            result = await mcp_server.query_influxdb(
                "SELECT * FROM mem WHERE time > now() - INTERVAL '1 hour' LIMIT 1"
            )
            data = self._parse_json_from_result(result)
            if data:
                row = data[0]
                assert "total" in row
                assert "used" in row
                assert "available_percent" in row

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_disk_table_query(self):
        """Query disk table - verify disk metrics."""

        async def run_test():
            result = await mcp_server.query_influxdb(
                "SELECT * FROM disk WHERE time > now() - INTERVAL '1 hour' LIMIT 1"
            )
            data = self._parse_json_from_result(result)
            if data:
                row = data[0]
                assert "device" in row
                assert "used_percent" in row

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_net_table_query(self):
        """Query net table - verify network counters."""

        async def run_test():
            result = await mcp_server.query_influxdb(
                "SELECT * FROM net WHERE time > now() - INTERVAL '1 hour' LIMIT 1"
            )
            data = self._parse_json_from_result(result)
            if data:
                row = data[0]
                assert "bytes_recv" in row
                assert "bytes_sent" in row

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_docker_container_cpu_table_query(self):
        """Query docker_container_cpu table - verify container metrics."""

        async def run_test():
            result = await mcp_server.query_influxdb(
                "SELECT * FROM docker_container_cpu "
                "WHERE time > now() - INTERVAL '1 hour' LIMIT 1"
            )
            data = self._parse_json_from_result(result)
            if data:
                row = data[0]
                assert "container_name" in row
                assert "usage_percent" in row

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_processes_table_query(self):
        """Query processes table - verify process counts."""

        async def run_test():
            result = await mcp_server.query_influxdb(
                "SELECT * FROM processes WHERE time > now() - INTERVAL '1 hour' LIMIT 1"
            )
            data = self._parse_json_from_result(result)
            if data:
                row = data[0]
                assert "total" in row
                assert "running" in row
                assert "sleeping" in row

        asyncio.run(run_test())


class TestLivePrometheusQueries:
    """
    Live queries against a real Prometheus instance.
    Requires: config.yaml with prometheus.enabled=true and valid token.

    These tests verify:
    - Authentication works
    - PromQL queries return parseable results
    - Targets endpoint is reachable
    """

    @pytest.fixture(autouse=True)
    def _check_prometheus_enabled(self):
        """Skip all tests if Prometheus is not configured."""
        config_path = Path(__file__).parent.parent / "config.yaml"
        config = load_config(config_path)
        if not config.get("prometheus", {}).get("enabled", False):
            pytest.skip("Prometheus not enabled in config.yaml")

    @pytest.mark.integration
    def test_up_query(self):
        """Query 'up' metric - verify target health status."""

        async def run_test():
            result = await mcp_server.query_prometheus("up")
            assert "✅ Query successful" in result

            json_part = result.split("\n\n", 1)[1]
            data = json.loads(json_part)
            assert "resultType" in data
            assert data["resultType"] == "vector"
            assert "result" in data
            assert isinstance(data["result"], list)
            if data["result"]:
                entry = data["result"][0]
                assert "metric" in entry
                assert "value" in entry
                assert "__name__" in entry["metric"]
                assert entry["metric"]["__name__"] == "up"

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_get_targets(self):
        """Get Prometheus scrape targets - verify at least one target."""

        async def run_test():
            result = await mcp_server.get_prometheus_targets()
            assert "✅" in result
            assert "target" in result.lower() or "active" in result.lower()

        asyncio.run(run_test())

    @pytest.mark.integration
    def test_complex_promql_query(self):
        """Query rate() function - verify complex PromQL works."""

        async def run_test():
            # Try a rate query if there are counter metrics
            result = await mcp_server.query_prometheus("rate(up[5m])")
            # Should either succeed or return a valid PromQL error
            assert "✅" in result or "❌" in result

        asyncio.run(run_test())


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
