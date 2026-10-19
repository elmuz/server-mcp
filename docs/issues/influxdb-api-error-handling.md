# Issue: InfluxDB tool errors are masked by reverse-proxy HTML

**Status:** Open — deferred to the MCP maintainer
**Reported:** 2026-10-20
**Affects:** `disk-health-mcp` (`query_influxdb_disk`, and every InfluxDB-first
disk tool), `remote-server-mcp` (`query_influxdb`, `query_prometheus`),
`server-management-lib` (`InfluxDBClient`, `PrometheusClient`)
**Environment:** `catafalco` deployment; InfluxDB reached at
`https://influxdb.catafal.co:443/api/v3/query_sql` through SWAG

## Symptom

A failing InfluxDB query returned a themed HTML error page instead of the
InfluxDB JSON error:

```text
❌ InfluxDB query failed (HTTP 500)
<!DOCTYPE html>
<html lang="en">
...
<title>Service Unavailable</title>
...
<div class="footer">catafal.co</div>
```

The tool therefore reported a *transport-looking* failure. The actual cause
was a plain SQL schema error produced by InfluxDB. This made the failure look
like a proxy outage and hid the fix (the query referenced `healthy`; the field
is `health_ok`).

## Investigation findings

### 1. The query did reach InfluxDB

`influxdb` container logs at the moment of the failure show the request with
`client_ip=192.168.178.135` and a real query-planning error:

```text
ERROR influxdb3_server::http: Error while handling request error=query error:
error while planning query: Schema error: No field named healthy.
Valid fields are smart_device.available_spare, ... smart_device.health_ok, ...
method=POST path=/api/v3/query_sql content_length=Some("143")
```

So InfluxDB answered `500` with a descriptive JSON body.

### 2. Both MCP servers behaved identically

Both configs point at the same URL:

```yaml
influxdb:
  enabled: true
  host: "influxdb.catafal.co"
  port: 443
  use_https: true
  database: "system-monitor"
```

Running the same invalid query through `mcp__remote_server__query_influxdb`
and `mcp__disk_health__query_influxdb_disk` returned the same HTML 500, and
valid queries succeed on both. The reported asymmetry
("disk-health fails, remote-server works") is **not** a per-server bug; it is
query-dependent. Both servers route through the same shared client
(`packages/server-management-lib/src/server_management_lib/http_clients.py`)
and the same proxy.

### 3. Root cause split

**Infrastructure (fixed in `catafalco`, not this repo).** SWAG deploys
`errors.conf` for every vhost:

```nginx
proxy_intercept_errors on;
error_page 404 /pages/404.html;
error_page 403 /pages/403.html;
error_page 500 502 503 504 /pages/5xx.html;
```

`proxy_intercept_errors on` replaces any upstream 500 (including the InfluxDB
JSON body) with the themed page, while preserving the `500` status. The fix
added `proxy_intercept_errors off;` to the InfluxDB and Prometheus API
locations in the Ansible templates:

- `catafalco/roles/influxdb/templates/influxdb.subdomain.conf.j2`
- `catafalco/roles/prometheus/templates/prometheus.subdomain.conf.j2`

After deploying and restarting SWAG, the same invalid query now returns the
real message:

```text
❌ InfluxDB query failed (HTTP 500)
Schema error: No field named healthy. Valid fields are ...
```

**MCP client (this repo, still open).** `InfluxDBClient.query()` treats every
non-200 body as if it came from InfluxDB. It has no content-type check and no
HTML detection, so a proxy/gateway page is rendered verbatim and labelled
"InfluxDB query failed". The only remediation hint it emits is about the
InfluxDB 3 file-scan limit, which is unrelated to this failure. The reverse
proxy can still produce HTML for 502/503/504 (SWAG down, cert reload, DNS
failure inside Docker) even with the API interception disabled, so this class
of failure will recur.

## Proposed changes

### A. Detect non-JSON error bodies (required)

In `InfluxDBClient.query()`:

1. Check `response.content_type` (aiohttp exposes
   `response.content_type`, e.g. `text/html`) and inspect the first bytes of
   the body for `<!doctype html` / `<html`.
2. When the body is HTML, return a distinct, actionable message instead of
   `"InfluxDB query failed"`:

   ```text
   ❌ Received an HTML page from https://influxdb.catafal.co:443 (HTTP 500),
   not an InfluxDB response.
   This is usually a reverse proxy / gateway error, not a query error.
   Check that the upstream is reachable and that the vhost disables
   `proxy_intercept_errors` for /api paths.
   ```

   Include the final URL and status. Do **not** dump the whole HTML page; cap
   it to a short excerpt (the existing `sanitize_output` cap is far too large
   for an error page).
3. Keep the existing behavior for non-HTML bodies so JSON schema errors still
   pass through unchanged.

### B. Harden the success path (required)

A `200` response is parsed with `await response.json()` without checking the
content type. If a proxy, hotspot, or login portal returns `200 text/html`
(e.g. SWAG default page, Authelia login), `json()` raises a `ContentTypeError`
that is not caught by the current `except aiohttp.ClientError` / `TimeoutError`
blocks and escapes as an unhandled tool exception. Wrap the decode and return
the same "HTML instead of JSON" diagnostic. Apply the same treatment to
`PrometheusClient` (`query` and `get_targets`), which shares the failure mode.

### C. Make the time-filter hint accurate (required, small)

The hint currently fires when the *text* contains `where` and `time`:

```python
has_time_filter = "where" in query_lower and "time" in query_lower
```

This is wrong for `SELECT time ...` (matches `time` in the projection), so
the hint is suppressed for queries that genuinely lack a time filter, and can
fire on comments/identifiers. Prefer a small parse (the module already imports
`sqlparse`) or a conservative regex against a `WHERE` clause. Only emit the
file-scan hint when the error text indicates the scan limit, or when there is
no `WHERE ... time` predicate.

### D. Query over SSH/loopback instead of public ingress (optional, design)

The MCP already holds an SSH executor, and InfluxDB is published as
`127.0.0.1:8181` only. Sending DB queries and bearer tokens through the public
SWAG vhost is unnecessary and adds a dependency on nginx/cert/DNS for a
diagnostic tool. Options, in order of preference:

1. New config `influxdb.transport: ssh` that runs the HTTP request inside the
   SSH session (for example via a small Python/curl invocation) or opens a
   short-lived local forward. This keeps the library's query validation and
   output handling, but removes the proxy from the data path.
2. Keep `proxy` as the default for backward compatibility and document
   `127.0.0.1` + SSH tunnel (the sample config already mentions the tunnel
   alternative).

Do not implement this before A–C; it is a separate behavioral change and
needs a decision on the executor API.

### E. Structured metadata fix (nice-to-have)

`disk-health` reports `data.database: null` when the caller omits the
argument, while `remote-server` reports the resolved default
(`system-monitor`):

```python
# apps/disk-health-mcp/.../server.py
data={"database": database, **_query_data(result)}
# apps/remote-server-mcp/.../server.py
data={"database": db, **_query_data(result)}
```

Resolve `database or influx_config.get("database")` before constructing the
`ToolOutput` so both servers are consistent.

## Tests to add

In `packages/server-management-lib/tests/test_http_clients.py`, using the
existing mocked-response pattern:

1. `500` + `Content-Type: application/json` body → returned verbatim, message
   still says `InfluxDB query failed (HTTP 500)`.
2. `500` + `Content-Type: text/html` body (use a trimmed SWAG page) → message
   says HTML/proxy, does not say "query failed", HTML is truncated.
3. `502` + HTML (gateway down) → same diagnostic.
4. `200` + `Content-Type: text/html` → JSON decode failure is caught and
   reported as HTML, no exception escapes.
5. `200` + malformed JSON (`application/json`) → caught, reported as a decode
   error.
6. Equivalent cases for `PrometheusClient.query()` and `get_targets()`.
7. Test for C: `SELECT time FROM cpu` without a `WHERE` time predicate still
   gets the hint; a query with `WHERE time > ...` does not.

Also add one tool-level test per server asserting that a proxy/HTML failure is
surfaced with `ok: false` and the new message (structured output stays
readable).

## Acceptance criteria

- An HTML response from the InfluxDB URL never produces the text
  `InfluxDB query failed` and never prints the full themed page.
- The message names the URL, the HTTP status, and states that this is likely a
  proxy/gateway problem rather than a query problem.
- Valid queries and genuine InfluxDB JSON errors behave exactly as today.
- No unhandled exception on `200 text/html`, malformed JSON, `500` HTML, or
  `502` HTML for InfluxDB and Prometheus clients.
- Time-filter hint only appears when applicable.
- Tests above pass; `ruff`, `ty`, and the per-package pytest gates stay green.

## Out of scope

- Changing the `catafalco` SWAG templates (already fixed there).
- Reworking the security validator or the SQL allowlist.
- Retrying failed queries (a 500 schema error is deterministic; retrying is
  harmful).

## References

- `packages/server-management-lib/src/server_management_lib/http_clients.py`
  (`InfluxDBClient.query`, `PrometheusClient.query`)
- `apps/disk-health-mcp/src/disk_health_mcp/server.py`
  (`query_influxdb_disk`, `_query_data`)
- `apps/remote-server-mcp/src/remote_server_mcp/server.py`
  (`query_influxdb`, `get_prometheus_targets`)
- `packages/server-management-lib/tests/test_http_clients.py`
- `catafalco/roles/swag/files/errors.conf`,
  `catafalco/roles/influxdb/templates/influxdb.subdomain.conf.j2`
