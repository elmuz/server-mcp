# Server MCP

[![CI](https://github.com/elmuz/server-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/elmuz/server-mcp/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**Security-first MCP servers for managing a home or remote Linux server.**

An autonomous agent with shell access is one bad command away from a very bad day. Server MCP
puts a narrow, auditable proxy between the model and the machine: a fixed catalog of Docker
and disk-diagnostics operations, strict path confinement, verified SSH host keys, output
limits and an optional audit log. No generic command execution, no shell string
concatenation, no accidental `rm -rf /`.

The suite contains two independent MCP servers built on one shared core:

| Package | Purpose |
|---|---|
| [`remote-server-mcp`](apps/remote-server-mcp) | Docker and host-service operations over SSH or on the local host |
| [`disk-health-mcp`](apps/disk-health-mcp) | SMART, NVMe, ZFS, mdadm, SnapRAID/mergerFS and I/O diagnostics |
| [`server-management-lib`](packages/server-management-lib) | Security policy, executors, config and HTTP clients |

Any MCP-capable client works: pi, Claude Code, Codex, Cursor, opencode, Claude Desktop and
anything else that speaks stdio MCP. See [docs/harnesses.md](docs/harnesses.md).

## Why this exists

Most "server management" agents are given a shell and a prayer. This project takes the
opposite approach:

- **No generic execution.** Tools are a fixed catalog; commands are typed argument vectors,
  never concatenated shell strings.
- **Least privilege.** The service tools can list, inspect, start, stop and restart Docker
  containers tied to a configured directory (or an explicit container allowlist). They
  cannot `docker run`, `docker exec`, read `/etc/shadow`, or download files.
- **Verified transport.** SSH host keys are checked by default. The legacy known_hosts
  entries that modern crypto cannot parse are skipped individually, not the whole file.
- **Bounded output.** ANSI escapes and control characters are stripped and every response is
  capped (64 KiB by default), including composite listings, so a noisy container cannot
  flood the model context.
- **Auditable.** Enable the JSONL audit log and every command, blocked operation, file read
  and database query is recorded with timing and status. Query text is fingerprinted rather
  than stored.
- **Read-only data access.** InfluxDB SQL must be a single `SELECT`; Prometheus is queried
  through its read-only HTTP API. Credentials never go to the model.
- **Explicit safety metadata.** Read-only and destructive tools are annotated with MCP
  `ToolAnnotations`, so clients can auto-approve reads and gate destructive actions.

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/elmuz/server-mcp.git
cd server-mcp
uv sync --all-packages --all-extras
```

Create a config for the server you want to run:

```bash
cp apps/remote-server-mcp/config.example.yaml apps/remote-server-mcp/config.yaml
$EDITOR apps/remote-server-mcp/config.yaml
```

Run it directly:

```bash
uv run --directory apps/remote-server-mcp remote-server-mcp
```

Or point your MCP client at it:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": [
        "run",
        "--project", "/path/to/server-mcp",
        "--package", "remote-server-mcp",
        "remote-server-mcp"
      ]
    }
  }
}
```

Add `"env": {"REMOTE_SERVER_MCP_CONFIG": "/path/to/config.yaml"}` if you keep the config
elsewhere. Disk diagnostics work the same way with `disk-health-mcp` and
`DISK_HEALTH_MCP_CONFIG`.

## What the agents can do

`remote-server-mcp` (17 tools):

| Tool | Access |
|---|---|
| `list_services`, `list_containers` | read-only |
| `get_service_logs`, `search_service_logs` | read-only |
| `get_service_status`, `get_container_health` | read-only |
| `get_host_service_status`, `get_host_service_logs` | read-only, systemd units from an allowlist |
| `get_service_file`, `list_service_files` | read-only, confined to the service directory; `.env` values are masked and key/credential files are refused |
| `get_server_health` | read-only |
| `query_influxdb`, `query_prometheus`, `get_prometheus_targets` | read-only |
| `start_service` | write |
| `restart_service`, `stop_service` | destructive |

A service directory resolves to its containers through the
`com.docker.compose.project` label, so `/srv/immich` covers `immich-server` and
`immich-postgres`. Individual container names work too when the container belongs to a
directory under `services_path` or is listed in `security.allowed_containers`. The log
tools always include Docker timestamps, accept optional `since`/`until` windows and a
`container` filter, and search for the exact literal pattern.

Host infrastructure services are not Docker containers. `get_host_service_status` and
`get_host_service_logs` read systemd units through `systemctl`/`journalctl`, but only units
listed in `security.host_units` (default: `telegraf`, `smartd`, `docker`, `snapraid`,
`mergerfs`, `smbd`). Arbitrary unit names are rejected before any command runs.

`disk-health-mcp` (13 tools): disk listing, full health report, SMART attributes, NVMe
health, SMART self-tests, ZFS/RAID/SnapRAID status, mergerFS and mount summaries, I/O
statistics and read-only InfluxDB/Prometheus queries. SnapRAID and mergerFS tools cover
mergerFS + SnapRAID hosts; `get_zfs_status` and `get_raid_status` cover ZFS and mdadm
stacks. SMART reports use the last successful InfluxDB sample in the last 24 hours and
report its age, so a sleeping disk no longer appears as `Unknown` / `0°C`. `run_smart_test`
pre-flights `smartctl` and skips a sleeping disk instead of spinning it up. Full tables are
in [docs/tools.md](docs/tools.md).

## How it is put together

```text
MCP client (pi, Claude Code, Codex, Cursor, opencode, ...)
        │ stdio MCP
        ▼
remote-server-mcp / disk-health-mcp     tool layer: schemas + annotations
        │
        ▼
server-management-lib                   security policy + executor + clients
        │
        ├── SSH executor ──► remote host (asyncssh, host keys verified, SFTP)
        └── local executor ─► same host (argv execution, no shell)
```

The executor is selected with one config key:

```yaml
executor: ssh    # default: connect to a remote host
# executor: local  # run the MCP server on the target host itself
```

See [docs/architecture.md](docs/architecture.md) for the full design.

## Configuration at a glance

```yaml
executor: ssh

ssh:
  host: "server.example.com"
  username: "admin"
  key_path: "~/.ssh/id_ed25519"
  known_hosts: "~/.ssh/known_hosts"

security:
  services_path: "/srv"

output:
  max_bytes: 64000

audit:
  enabled: true
  path: "~/.local/state/remote-server-mcp/audit.jsonl"

influxdb:
  enabled: false
  # host: "influxdb.example.com"  # hostname/IP only; no scheme or path
  # port: 443
  # use_https: true
```

Telegraf's smart plugin writing to InfluxDB is the primary disk-health source. Prometheus
is optional: the `smartmon_*` examples require `node_exporter`, and disk health does not
depend on it. A loopback-only metric service can be reached through an HTTPS reverse proxy
(`use_https: true`) or through an `ssh_tunnel` block that the MCP opens itself; see
[the endpoint guide](docs/configuration.md#database-endpoints).

Config resolution order: `--config`, then `$REMOTE_SERVER_MCP_CONFIG` /
`$DISK_HEALTH_MCP_CONFIG`, then `$XDG_CONFIG_HOME/<app>/config.yaml`, then `./config.yaml`.
Environment variables override YAML and a `.env` next to the config is loaded automatically.
The full reference is in [docs/configuration.md](docs/configuration.md).

## Security model

The short version: the model can only call the tools that exist, those tools build argv
vectors from validated inputs, file access is confined with remote `realpath` checks, and
all output is sanitized and capped. The long version, including known limitations, is in
[docs/security-model.md](docs/security-model.md).

Please do not report security issues in public issues; see [SECURITY.md](SECURITY.md).

## Development

```bash
uv sync --all-packages --all-extras
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q
env -u VIRTUAL_ENV pre-commit run --all-files
```

Integration tests that talk to a real host or database are opt-in:
`uv run --directory apps/remote-server-mcp pytest -m integration`.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md).
The current backlog and release checklist live in
[docs/modernization-plan.md](docs/modernization-plan.md).

## Project layout

```text
server-mcp/
├── apps/
│   ├── remote-server-mcp/
│   └── disk-health-mcp/
├── packages/
│   └── server-management-lib/
├── docs/
├── examples/
└── scripts/
```

## License

MIT. See [LICENSE](LICENSE).
