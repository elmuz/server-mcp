"""
HTTP Clients for InfluxDB and Prometheus

Provides read-only query clients for both time-series databases
with built-in security validation.
"""

import hashlib
import json
import logging
import re
from time import monotonic

import aiohttp

from .audit import AuditLogger
from .output import DEFAULT_MAX_OUTPUT_BYTES, sanitize_output

logger = logging.getLogger(__name__)

# Defense-in-depth: whitelist the InfluxDB endpoints so even if
# the path construction changes, requests to admin/write endpoints are blocked.
INFLUXDB_ALLOWED_ENDPOINTS: frozenset[str] = frozenset(
    {
        "/api/v3/query_sql",
        "/api/v3/query_influxql",
        "/health",
        "/metrics",
        "/ping",
    }
)


class InfluxDBClient:
    """Client for InfluxDB v3 HTTP API (read-only)."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8181,
        use_https: bool = False,
        database: str | None = None,
        token: str | None = None,
        query_limit: int = 1000,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        timeout: float = 30,
        audit: AuditLogger | None = None,
    ):
        self.host = host
        self.port = port
        self.use_https = use_https
        self.database = database
        self.token = token
        self.query_limit = min(query_limit, 10000)
        self.max_output_bytes = max_output_bytes
        self.timeout = timeout
        self.audit = audit
        self.scheme = "https" if use_https else "http"

    def _log_audit(
        self,
        query: str,
        database: str | None,
        status: str | int,
        started: float,
        *,
        error: str | None = None,
    ) -> None:
        """Record query metadata without storing the query text.

        SQL and PromQL may contain literal values that the model should not
        persist in a local log. Length plus SHA-256 keeps queries correlatable
        without copying their contents.
        """
        if self.audit is None:
            return
        fields: dict[str, object] = {
            "database": database,
            "status": status,
            "duration_ms": round((monotonic() - started) * 1000, 1),
            "query_length": len(query),
            "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        }
        if error is not None:
            fields["error"] = error
        self.audit.log("influxdb_query", **fields)

    async def query(self, sql_query: str, database: str | None = None) -> str:
        """
        Execute a SELECT query against the InfluxDB v3 HTTP API.

        Args:
            sql_query: SQL query (must start with SELECT)
            database: Database name (overrides constructor default)

        Returns:
            Query results in JSON format
        """
        started = monotonic()
        db = database or self.database
        if not db:
            self._log_audit(sql_query, db, "no_database", started)
            return (
                "❌ No database specified. Provide 'database' parameter or set "
                "'influxdb.database' in config.yaml."
            )

        path = "/api/v3/query_sql"
        url = f"{self.scheme}://{self.host}:{self.port}{path}"

        # InfluxDB v3 has no server-side row limit parameter; enforce it in SQL.
        sql_query = _ensure_limit(sql_query, self.query_limit)

        if path not in INFLUXDB_ALLOWED_ENDPOINTS:
            return f"❌ Blocked: endpoint '{path}' is not in the allowed whitelist"

        params = {
            "db": db,
            "q": sql_query,
        }

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=params,
                    headers=headers,
                    timeout=self.timeout,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        formatted = json.dumps(data, indent=2)
                        formatted = sanitize_output(
                            formatted, self.max_output_bytes, label="InfluxDB result"
                        )
                        self._log_audit(sql_query, db, response.status, started)
                        return f"✅ Query successful\n\n{formatted}"
                    else:
                        error_body = sanitize_output(
                            await response.text(),
                            self.max_output_bytes,
                            label="InfluxDB error",
                        )

                        hint = ""
                        query_lower = sql_query.lower()
                        has_time_filter = (
                            "where" in query_lower and "time" in query_lower
                        )
                        if not has_time_filter:
                            hint = (
                                "💡 Tip: InfluxDB 3 Core has a file-scan limit. "
                                "Queries without a `WHERE time` clause may fail "
                                "with HTTP 500. Add a time range like:\n"
                                "   WHERE time > now() - INTERVAL '1 hour'\n\n"
                            )

                        self._log_audit(sql_query, db, response.status, started)
                        return (
                            f"{hint}"
                            f"❌ InfluxDB query failed (HTTP {response.status})\n"
                            f"{error_body}"
                        )
        except aiohttp.ClientError as e:
            self._log_audit(
                sql_query, db, "connection_error", started, error=type(e).__name__
            )
            return f"❌ Connection error: {e}"
        except TimeoutError:
            self._log_audit(sql_query, db, "timeout", started)
            return f"❌ Query timed out after {self.timeout} seconds"


class PrometheusClient:
    """Client for Prometheus HTTP API (read-only)."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 9090,
        use_https: bool = False,
        token: str | None = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        timeout: float = 30,
        audit: AuditLogger | None = None,
    ):
        self.host = host
        self.port = port
        self.use_https = use_https
        self.token = token
        self.max_output_bytes = max_output_bytes
        self.timeout = timeout
        self.audit = audit
        self.scheme = "https" if use_https else "http"

    def _log_audit(
        self,
        query: str,
        status: str | int,
        started: float,
        *,
        error: str | None = None,
    ) -> None:
        """Record query metadata without storing the PromQL text."""
        if self.audit is None:
            return
        fields: dict[str, object] = {
            "status": status,
            "duration_ms": round((monotonic() - started) * 1000, 1),
            "query_length": len(query),
            "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        }
        if error is not None:
            fields["error"] = error
        self.audit.log("prometheus_query", **fields)

    async def query(self, promql: str, time: str | None = None) -> str:
        """
        Execute an instant query against the Prometheus HTTP API.

        Args:
            promql: PromQL expression
            time: Optional RFC3339 timestamp or Unix timestamp (defaults to now)

        Returns:
            Query results in JSON format
        """
        started = monotonic()
        url = f"{self.scheme}://{self.host}:{self.port}/api/v1/query"

        params: dict[str, str] = {"query": promql}
        if time:
            params["time"] = time

        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            formatted = json.dumps(data["data"], indent=2)
                            formatted = sanitize_output(
                                formatted,
                                self.max_output_bytes,
                                label="Prometheus result",
                            )
                            self._log_audit(promql, response.status, started)
                            return f"✅ Query successful\n\n{formatted}"
                        else:
                            error_type = data.get("errorType", "unknown")
                            error_msg = data.get("error", "Unknown error")
                            self._log_audit(
                                promql, f"promql_error:{error_type}", started
                            )
                            return (
                                f"❌ PromQL query error\n"
                                f"Type: {error_type}\n"
                                f"Error: {error_msg}"
                            )
                    else:
                        error_body = sanitize_output(
                            await response.text(),
                            self.max_output_bytes,
                            label="Prometheus error",
                        )
                        self._log_audit(promql, response.status, started)
                        return (
                            f"❌ Prometheus query failed (HTTP {response.status})\n"
                            f"{error_body}"
                        )
        except aiohttp.ClientError as e:
            self._log_audit(promql, "connection_error", started, error=type(e).__name__)
            return f"❌ Connection error: {e}"
        except TimeoutError:
            self._log_audit(promql, "timeout", started)
            return f"❌ Query timed out after {self.timeout} seconds"

    async def get_targets(self) -> str:
        """Get scrape targets from Prometheus."""
        url = f"{self.scheme}://{self.host}:{self.port}/api/v1/targets"

        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers, timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            targets = data.get("data", {}).get("activeTargets", [])
                            if not targets:
                                return "No active targets configured in Prometheus."

                            lines = [f"✅ Found {len(targets)} active targets:\n"]
                            for target in targets:
                                labels = target.get("labels", {})
                                job = labels.get("job", "unknown")
                                instance = labels.get("instance", "unknown")
                                health = target.get("health", "unknown")
                                last_error = target.get("lastError", "")
                                lines.append(
                                    f"  • {job}/{instance}: {health}"
                                    + (f" ({last_error})" if last_error else "")
                                )
                            return "\n".join(lines)
                        else:
                            return (
                                f"❌ Unexpected response: {json.dumps(data, indent=2)}"
                            )
                    else:
                        error_body = sanitize_output(
                            await response.text(),
                            self.max_output_bytes,
                            label="Prometheus error",
                        )
                        return (
                            f"❌ Failed to get targets (HTTP {response.status})\n"
                            f"{error_body}"
                        )
        except aiohttp.ClientError as e:
            return f"❌ Connection error: {e}"
        except TimeoutError:
            return f"❌ Request timed out after {self.timeout} seconds"


def _ensure_limit(sql_query: str, limit: int) -> str:
    """Append a LIMIT clause when the query does not already constrain rows."""
    query = sql_query.strip().rstrip(";").rstrip()
    if re.search(r"\blimit\b", query, re.IGNORECASE):
        return query
    # Use a newline so a trailing line comment cannot swallow the LIMIT clause.
    return f"{query}\nLIMIT {int(limit)}"


def parse_duration(value: str | int | float, default: float = 30) -> float:
    """Parse ``30``, ``"30s"``, ``"1m"`` or ``"500ms"`` into seconds."""
    if isinstance(value, int | float):
        return float(value)
    text = str(value).strip().lower()
    units = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    for suffix, factor in units.items():
        if text.endswith(suffix):
            try:
                return float(text[: -len(suffix)]) * factor
            except ValueError:
                return default
    try:
        return float(text)
    except ValueError:
        return default
