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
import sqlparse
from sqlparse import tokens as sql_tokens

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
        self._session: aiohttp.ClientSession | None = None

    def _get_session(self) -> aiohttp.ClientSession:
        """Return the client's shared HTTP session, creating it on demand."""
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the shared HTTP session (idempotent)."""
        session = self._session
        self._session = None
        if session is not None:
            await session.close()

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
            session = self._get_session()
            async with session.post(
                url,
                json=params,
                headers=headers,
                timeout=self.timeout,
            ) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError):
                        body = await response.text()
                        if _looks_like_html(response, body):
                            self._log_audit(
                                sql_query,
                                db,
                                response.status,
                                started,
                                error="html_response",
                            )
                            return _html_response_message(
                                "InfluxDB", url, response.status, body
                            )
                        self._log_audit(
                            sql_query,
                            db,
                            response.status,
                            started,
                            error="json_decode_error",
                        )
                        return _json_decode_message(
                            "InfluxDB", url, response.status, body
                        )
                    formatted = json.dumps(data, indent=2)
                    formatted = sanitize_output(
                        formatted, self.max_output_bytes, label="InfluxDB result"
                    )
                    self._log_audit(sql_query, db, response.status, started)
                    return f"✅ Query successful\n\n{formatted}"
                else:
                    body = await response.text()
                    if _looks_like_html(response, body):
                        self._log_audit(
                            sql_query,
                            db,
                            response.status,
                            started,
                            error="html_response",
                        )
                        return _html_response_message(
                            "InfluxDB", url, response.status, body
                        )

                    error_body = sanitize_output(
                        body,
                        self.max_output_bytes,
                        label="InfluxDB error",
                    )

                    hint = ""
                    if _should_show_scan_hint(sql_query, error_body):
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
        self._session: aiohttp.ClientSession | None = None

    def _get_session(self) -> aiohttp.ClientSession:
        """Return the client's shared HTTP session, creating it on demand."""
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the shared HTTP session (idempotent)."""
        session = self._session
        self._session = None
        if session is not None:
            await session.close()

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
            session = self._get_session()
            async with session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            ) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError):
                        body = await response.text()
                        if _looks_like_html(response, body):
                            self._log_audit(
                                promql, response.status, started, error="html_response"
                            )
                            return _html_response_message(
                                "Prometheus", url, response.status, body
                            )
                        self._log_audit(
                            promql,
                            response.status,
                            started,
                            error="json_decode_error",
                        )
                        return _json_decode_message(
                            "Prometheus", url, response.status, body
                        )
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
                        self._log_audit(promql, f"promql_error:{error_type}", started)
                        return (
                            f"❌ PromQL query error\n"
                            f"Type: {error_type}\n"
                            f"Error: {error_msg}"
                        )
                else:
                    body = await response.text()
                    if _looks_like_html(response, body):
                        self._log_audit(
                            promql, response.status, started, error="html_response"
                        )
                        return _html_response_message(
                            "Prometheus", url, response.status, body
                        )
                    error_body = sanitize_output(
                        body,
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

    def _log_targets(
        self,
        status: str | int,
        started: float,
        *,
        error: str | None = None,
    ) -> None:
        """Record a targets request without storing response bodies."""
        if self.audit is None:
            return
        fields: dict[str, object] = {
            "status": status,
            "duration_ms": round((monotonic() - started) * 1000, 1),
        }
        if error is not None:
            fields["error"] = error
        self.audit.log("prometheus_targets", **fields)

    async def get_targets(self) -> str:
        """Get scrape targets from Prometheus."""
        started = monotonic()
        url = f"{self.scheme}://{self.host}:{self.port}/api/v1/targets"

        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            session = self._get_session()
            async with session.get(
                url, headers=headers, timeout=self.timeout
            ) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError):
                        body = await response.text()
                        if _looks_like_html(response, body):
                            self._log_targets(
                                response.status, started, error="html_response"
                            )
                            return _html_response_message(
                                "Prometheus", url, response.status, body
                            )
                        self._log_targets(
                            response.status, started, error="json_decode_error"
                        )
                        return _json_decode_message(
                            "Prometheus", url, response.status, body
                        )
                    if data.get("status") == "success":
                        targets = data.get("data", {}).get("activeTargets", [])
                        if not targets:
                            self._log_targets(response.status, started)
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
                        self._log_targets(response.status, started)
                        return "\n".join(lines)

                    self._log_targets("unexpected_response", started)
                    return f"❌ Unexpected response: {json.dumps(data, indent=2)}"

                body = await response.text()
                if _looks_like_html(response, body):
                    self._log_targets(response.status, started, error="html_response")
                    return _html_response_message(
                        "Prometheus", url, response.status, body
                    )
                error_body = sanitize_output(
                    body,
                    self.max_output_bytes,
                    label="Prometheus error",
                )
                self._log_targets(response.status, started)
                return (
                    f"❌ Failed to get targets (HTTP {response.status})\n{error_body}"
                )
        except aiohttp.ClientError as e:
            self._log_targets("connection_error", started, error=type(e).__name__)
            return f"❌ Connection error: {e}"
        except TimeoutError:
            self._log_targets("timeout", started)
            return f"❌ Request timed out after {self.timeout} seconds"


# An error page is diagnostic context, not a query result: keep the excerpt
# short so a themed proxy page cannot flood the model context.
_HTML_EXCERPT_BYTES = 400

_HTML_START_PATTERN = re.compile(
    r"^\s*<(?:!doctype\s+html|html|head|body)\b", re.IGNORECASE
)

_SCAN_LIMIT_PATTERN = re.compile(r"(?:file[ -]scan|scan[ -]limit)", re.IGNORECASE)

_TIME_PREDICATE_PATTERN = re.compile(r"\btime\b", re.IGNORECASE)

_WHERE_END_KEYWORDS = frozenset(
    {"GROUP BY", "ORDER BY", "LIMIT", "HAVING", "UNION", "WINDOW", "OFFSET"}
)


def _content_type(response: object) -> str:
    """Return the declared content type when the response exposes one."""
    value = getattr(response, "content_type", None)
    return value if isinstance(value, str) else ""


def _looks_like_html(response: object, body: str) -> bool:
    """Detect a proxy/gateway HTML page rather than an API response."""
    if "html" in _content_type(response).lower():
        return True
    return bool(_HTML_START_PATTERN.match(body[:512]))


def _excerpt(body: str, label: str) -> str:
    """Collapse whitespace and cap a body to a short, readable excerpt."""
    collapsed = " ".join(body.split())
    return sanitize_output(collapsed, _HTML_EXCERPT_BYTES, label=label)


def _html_response_message(service: str, url: str, status: int, body: str) -> str:
    """Build the diagnostic for an HTML page served instead of the API."""
    excerpt = _excerpt(body, "HTML page excerpt")
    return (
        f"❌ Received an HTML page from {url} (HTTP {status}), "
        f"not a {service} response.\n"
        "This is usually a reverse proxy / gateway error, not a query error.\n"
        "Check that the upstream is reachable and that the vhost disables\n"
        "`proxy_intercept_errors` for /api paths.\n"
        f"\nHTML excerpt: {excerpt}"
    )


def _json_decode_message(service: str, url: str, status: int, body: str) -> str:
    """Build the diagnostic for a body that is not decodable JSON."""
    excerpt = _excerpt(body, f"{service} response excerpt")
    return (
        f"❌ {service} returned a {status} response from {url} that is not "
        "valid JSON.\n"
        "This is usually a reverse proxy, captcha or login page instead of the "
        f"{service} API.\n"
        f"\nResponse excerpt: {excerpt}"
    )


def _has_time_predicate(sql_query: str) -> bool:
    """Return True when the WHERE clause filters on a ``time`` column.

    ``SELECT time ...`` is not a time filter, so the hint must not be
    suppressed for it. The check walks the flattened token stream, ignores
    string literals and stops at the end of the WHERE clause.
    """
    try:
        statements = sqlparse.parse(sql_query)
    except Exception:  # pragma: no cover - sqlparse is defensive
        return False

    for statement in statements:
        in_where = False
        for token in statement.flatten():
            if token.ttype in sql_tokens.Keyword:
                keyword = " ".join(token.value.upper().split())
                if keyword == "WHERE":
                    in_where = True
                    continue
                if keyword in _WHERE_END_KEYWORDS:
                    in_where = False
                    continue
            if not in_where or token.is_whitespace:
                continue
            if token.ttype in sql_tokens.String:
                continue
            if _TIME_PREDICATE_PATTERN.search(token.value):
                return True
    return False


def _should_show_scan_hint(sql_query: str, error_body: str) -> bool:
    """Only hint at the file-scan limit when it can be the actual cause."""
    if _SCAN_LIMIT_PATTERN.search(error_body):
        return True
    return not _has_time_predicate(sql_query)


def _ensure_limit(sql_query: str, limit: int) -> str:
    """Bound the result set of a SELECT query.

    A top-level ``LIMIT <n>`` is clamped to ``limit``; a ``LIMIT`` inside a
    string literal, an identifier or a nested subquery is ignored. When the
    outermost query has no numeric LIMIT clause, one is appended. Comments are
    rejected by :meth:`SecurityValidator.validate_influxdb_query` before the
    query reaches this helper.
    """
    query = sql_query.strip().rstrip(";").rstrip()
    maximum = int(limit)

    try:
        statements = sqlparse.parse(query)
    except Exception:  # pragma: no cover - sqlparse is defensive
        return f"{query}\nLIMIT {maximum}"

    if len(statements) != 1:
        return f"{query}\nLIMIT {maximum}"

    statement = statements[0]
    tokens = statement.tokens
    for index, token in enumerate(tokens):
        if token.ttype not in sql_tokens.Keyword or token.value.upper() != "LIMIT":
            continue

        next_index = index + 1
        while next_index < len(tokens) and (
            tokens[next_index].is_whitespace
            or tokens[next_index].ttype in sql_tokens.Comment
        ):
            next_index += 1

        if next_index >= len(tokens):
            continue
        value_token = tokens[next_index]
        if value_token.ttype not in sql_tokens.Number.Integer:
            continue

        if int(value_token.value) > maximum:
            value_token.value = str(maximum)
        return str(statement).strip()

    return f"{query}\nLIMIT {maximum}"


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
