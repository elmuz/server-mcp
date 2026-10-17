# Configuration Reference

Both MCP servers share one configuration schema. Each server reads its own file.

## Resolution order

1. `--config PATH`
2. `$REMOTE_SERVER_MCP_CONFIG` or `$DISK_HEALTH_MCP_CONFIG`
3. `$XDG_CONFIG_HOME/<app>/config.yaml` (`~/.config/<app>/config.yaml` by default)
4. `./config.yaml`

The server exits with status 2 if no file is found. Environment variables override YAML
values. If a `.env` file exists next to the resolved config, it is loaded first.

## Full example

```yaml
# ssh (default) or local
executor: ssh

ssh:
  host: "server.example.com"
  port: 22
  username: "admin"          # omit to use the current user / ~/.ssh/config
  password: null             # prefer keys or ssh-agent
  key_path: "~/.ssh/id_ed25519"
  known_hosts: "~/.ssh/known_hosts"   # "none" disables verification (insecure)
  connect_timeout: 10

security:
  services_path: "/srv"

host:
  enabled: true              # disk-health: allow smartctl/nvme/zfs/raid/iostat tools

influxdb:
  enabled: false
  host: "localhost"
  port: 8181
  use_https: false
  database: "system-monitor"
  token: "read-only-token"
  query_limit: 1000          # applied as a SQL LIMIT when missing

prometheus:
  enabled: false
  host: "localhost"
  port: 9090
  use_https: false
  token: "read-only-token"
  query_timeout: "30s"

output:
  max_bytes: 64000           # cap for command output, files and query results

audit:
  enabled: false
  path: "~/.local/state/remote-server-mcp/audit.jsonl"
```

## Executor

| Value | Behaviour |
|---|---|
| `ssh` (default) | Connects to `ssh.host`; files are read over SFTP; host keys are verified |
| `local` | Runs commands on the host where the MCP server runs, as that user; no shell |

Both executors use the same validated operation catalog. The local executor rejects shell
operators (`|`, `&&`, `;`, redirects) instead of interpreting them.

## SSH

| Key | Default | Notes |
|---|---|---|
| `host` | `localhost` | Hostname or a `~/.ssh/config` alias |
| `port` | `22` | |
| `username` | current user | Omit to let asyncssh/ssh-config decide |
| `password` | none | Prefer keys or an agent |
| `key_path` | none | `~` is expanded |
| `known_hosts` | `~/.ssh/known_hosts` | `none` disables verification and logs a warning |
| `connect_timeout` | `10` | Seconds |

Host key verification is on by default. If a known_hosts file contains legacy or malformed
entries that modern cryptography cannot parse, only those lines are skipped and the rest of
the file is still enforced.

## Security

`services_path` is the only directory the service tools may touch. Every service is a
directory below it (`/srv/<service>`), and every file path is resolved on the target and
checked against that service directory.

`host.enabled` gates the disk-health tools that need direct host access
(`smartctl`, `nvme`, `lsblk`, `zpool`, `mdadm`, `iostat`).

## Databases

InfluxDB queries must be a single `SELECT`. A `LIMIT` is appended when the query has none.
Prometheus uses the read-only instant-query API. Use read-only tokens for both.

## Output and audit

- `output.max_bytes` caps every command result, file read and query response. ANSI escapes
  and control characters are stripped before truncation.
- `audit.enabled` writes one JSON object per line. Records include timestamps, commands,
  paths, exit codes, durations and truncation flags. Password/token/secret fields are
  redacted. Audit logging is best effort and never blocks an operation.

## Environment variables

Environment variables override the YAML file.

| Variable | Config key |
|---|---|
| `EXECUTOR` | `executor` |
| `SSH_HOST` | `ssh.host` |
| `SSH_PORT` | `ssh.port` |
| `SSH_USERNAME` | `ssh.username` |
| `SSH_PASSWORD` | `ssh.password` |
| `SSH_KEY_PATH` | `ssh.key_path` |
| `SSH_KNOWN_HOSTS` | `ssh.known_hosts` |
| `INFLUXDB_HOST` | `influxdb.host` |
| `INFLUXDB_PORT` | `influxdb.port` |
| `INFLUXDB_USE_HTTPS` | `influxdb.use_https` |
| `INFLUXDB_DATABASE` | `influxdb.database` |
| `INFLUXDB_TOKEN` | `influxdb.token` |
| `PROMETHEUS_HOST` | `prometheus.host` |
| `PROMETHEUS_PORT` | `prometheus.port` |
| `PROMETHEUS_USE_HTTPS` | `prometheus.use_https` |
| `PROMETHEUS_TOKEN` | `prometheus.token` |
| `OUTPUT_MAX_BYTES` | `output.max_bytes` |
| `AUDIT_ENABLED` | `audit.enabled` |
| `AUDIT_LOG_PATH` | `audit.path` |

`MCP_LOG_LEVEL` controls logging (`DEBUG`, `INFO`, `WARNING`, ...).

## Secrets

Do not commit `config.yaml`, `.env` or key material. Prefer environment variables from your
MCP client's `env` block, an SSH agent, or a dedicated read-only token for InfluxDB and
Prometheus.
