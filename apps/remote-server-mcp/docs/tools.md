# Available Tools

All tools validate inputs against the security policy before execution. See [security-model.md](security-model.md) for details.

## SSH / Docker Tools

| Tool | Description | Safety Notes |
|------|-------------|--------------|
| `list_services` | List all service directories in `/srv/` and their Docker status | No input parameters |
| `get_service_logs` | Get Docker container logs for a service | Service validated; max 1000 lines |
| `get_service_status` | Get service status, resource usage, and exposed ports | Service validated; multiple Docker queries |
| `restart_service` | Restart a Docker container | Service validated |
| `start_service` | Start a stopped Docker container | Service validated |
| `stop_service` | Stop a running Docker container | Service validated |
| `get_service_file` | Read a file within `/srv/{service}/` | Path validated; sensitive files blocked |
| `list_service_files` | List files in a service directory | Subdirectory path validated |
| `search_service_logs` | Search logs for a plain-text pattern | Pattern sanitized; max 5000 lines |
| `get_server_health` | Get CPU, memory, disk metrics | No sensitive data exposed |

## Database Query Tools

These tools query external databases over HTTP(S) — **no SSH involved**. They are read-only and validate all inputs against injection attacks.

| Tool | Description | Safety Notes |
|------|-------------|--------------|
| `query_influxdb` | Query InfluxDB v3 using SQL | Read-only (SELECT only); SQL/shell injection blocked; configurable query limit |
| `query_prometheus` | Query Prometheus using PromQL | Read-only API; shell injection blocked; instant query endpoint |
| `get_prometheus_targets` | List Prometheus scrape targets and health | Read-only API; no query parameters |

## Tool Details

### `list_services()`

Returns a list of directories under `/srv/` and the status of Docker containers. No parameters required.

### `get_service_logs(service, lines=100)`

- **service**: Validated service name
- **lines**: Capped at 1000

Command: `docker logs --tail {lines} -- {service}`

### `get_service_status(service)`

Runs three Docker queries:
1. `docker inspect` for container state
2. `docker stats` for CPU/memory/network
3. `docker port` for exposed ports

### `restart_service(service)` / `start_service(service)` / `stop_service(service)`

Simple Docker lifecycle commands with service validation.

### `get_service_file(service, file_path)`

- Validates `file_path` is relative and within `/srv/{service}/`
- Blocks sensitive file patterns (`.env`, `.git/`, `*.key`, etc.)
- Resolves path to prevent traversal escapes

### `list_service_files(service, subdirectory="")`

- Lists files in `/srv/{service}/` or a validated subdirectory
- Subdirectory goes through full path validation

### `search_service_logs(service, pattern, lines=1000)`

- **pattern**: Stripped of shell-special characters; must not be empty after sanitization
- **lines**: Capped at 5000
- Uses `grep -F` (fixed strings, no regex)

### `get_server_health()`

Returns:
- System uptime
- Memory usage (`free -h`)
- Disk usage for `/srv` (`df -h`)
- Running Docker services

No sensitive data is included in the output.

### Database Query Tools

These tools connect to external databases over HTTP(S) using credentials from `config.yaml`. They do **not** use SSH.

#### `query_influxdb(query, database=None)`

Query InfluxDB v3 using SQL via the `/api/v3/query_sql` endpoint.

- **query**: SQL query string. Must start with `SELECT` (read-only enforced).
- **database**: Optional database name override (defaults to `influxdb.database` in config).

**Configuration** (`config.yaml`):

```yaml
influxdb:
  enabled: true
  host: "influxdb.example.com"
  port: 443
  use_https: true
  database: "system-monitor"
  token: "apiv3_..."         # Optional Bearer token
  query_limit: 1000           # Max rows returned (capped at 10000)
```

**Security**:
- Only `SELECT` queries allowed (write operations blocked)
- SQL injection characters rejected (`;`, `--`, `/*`, etc.)
- Shell injection characters rejected (backticks, `$`, `|`, etc.)
- Results capped at `query_limit` rows

**Example**:

```
query_influxdb("SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour' LIMIT 5")
```

> **Note**: InfluxDB 3 Core has a default file-scan limit. Use `WHERE time` clauses to narrow the time range for better performance.

#### `query_prometheus(query, time=None)`

Query Prometheus using PromQL via the `/api/v1/query` instant query endpoint.

- **query**: PromQL expression.
- **time**: Optional RFC3339 or Unix timestamp (defaults to current time).

**Configuration** (`config.yaml`):

```yaml
prometheus:
  enabled: true
  host: "prometheus.example.com"
  port: 443
  use_https: true             # Boolean, not a string
  token: "your-api-token"     # Optional Bearer token
  query_timeout: "30s"
```

**Security**:
- Shell injection characters rejected (`;`, backticks, `$`, `|`, `&`, etc.)
- Quote characters rejected (prevents shell escaping)
- Query length capped at 5000 characters

**Example**:

```
query_prometheus("up")
query_prometheus("rate(http_requests_total[5m])")
```

#### `get_prometheus_targets()`

List all configured Prometheus scrape targets and their health status.

No parameters required. Returns a summary of each target's job, instance, and health state.

**Example output**:

```
✅ Found 3 active targets:

  • node-exporter/server1:9100: up
  • vllm/vllm.catafal.co: up
  • cadvisor/cadvisor:8080: down (connection refused)
```
