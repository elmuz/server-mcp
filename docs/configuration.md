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
  allowed_containers: []      # containers manageable without a service directory
  host_units:                # systemd units get_host_service_* may inspect
    - telegraf
    - smartd
    - docker
    - snapraid
    - mergerfs
    - smbd

host:
  enabled: true              # disk-health: allow smartctl/nvme/zfs/raid/snapraid/mount tools

health:
  disk_paths:                # remote-server-mcp get_server_health: mount points to report
    - "/"
    - "/mnt/storage"

influxdb:
  enabled: false
  host: "influxdb.example.com"   # hostname/IP only, no scheme or path
  port: 443
  use_https: true
  database: "my-db"
  token: "read-only-token"
  query_limit: 1000          # applied as a SQL LIMIT when missing
  # Optional loopback-only mode: let the MCP open the tunnel at startup.
  # ssh_tunnel:
  #   enabled: true
  #   remote_host: "127.0.0.1"   # from the SSH server's point of view
  #   remote_port: 8181          # defaults to influxdb.port
  #   local_host: "127.0.0.1"    # loopback only
  #   local_port: 0              # 0 = ephemeral local port

prometheus:
  enabled: false
  host: "prometheus.example.com"  # hostname/IP only, no scheme or path
  port: 443
  use_https: true
  token: "read-only-token"
  query_timeout: "30s"
  # ssh_tunnel:
  #   enabled: true
  #   remote_host: "127.0.0.1"
  #   remote_port: 9090          # defaults to prometheus.port
  #   local_host: "127.0.0.1"    # loopback only
  #   local_port: 0              # 0 = ephemeral local port

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
checked against that service directory. A directory resolves to its containers through
the `com.docker.compose.project` label; containers without a matching directory (for
example a standalone `watchtower`) are only accepted when their name is listed in
`security.allowed_containers`.

`host.enabled` gates the disk-health tools that need direct host access
(`smartctl`, `nvme`, `lsblk`, `zpool`, `mdadm`, `snapraid`, `findmnt`, `df`, `iostat`).
SnapRAID and mergerFS hosts use `get_snapraid_status` and `get_mount_status`; ZFS and
mdadm hosts use `get_zfs_status` and `get_raid_status`.

`health.disk_paths` is the list of absolute mount points `remote-server-mcp` reports in
`get_server_health` (default `["/"]`). NAS pools and parity disks are separate mounts, so
list each one explicitly; entries are validated, normalised and deduplicated. Invalid
entries are ignored, and `["/"]` is used when no valid path remains. This setting has no
effect on `disk-health-mcp`.

`security.host_units` is the allowlist for `get_host_service_status` and
`get_host_service_logs`. The default is `telegraf`, `smartd`, `docker`, `snapraid`,
`mergerfs` and `smbd`. The tools build `systemctl status` and `journalctl -u` argv vectors
only for names in this list; arbitrary units are rejected. Set an empty list (or `null`) to
disable host-service inspection entirely.

The command allowlist is built into the library and cannot be extended from configuration.
`security.allow_generic_commands` is accepted for backwards compatibility but has no
effect: there is no path that enables arbitrary command execution.

## Database endpoints

`influxdb.host` and `prometheus.host` are a hostname or IP address only. Do not include a
scheme (`https://`) or a path: `use_https: true` selects the scheme and the clients use the
fixed API paths (`/api/v3/query_sql` for InfluxDB, `/api/v1/query` and `/api/v1/targets`
for Prometheus). Tokens are sent as a `Bearer` header.

### Mode A: HTTPS reverse proxy (recommended)

Put the database behind a reverse proxy such as SWAG, Caddy or nginx and give the MCP a
read-only token. The proxy terminates TLS; the MCP connects directly over HTTPS.

```yaml
influxdb:
  enabled: true
  host: "influxdb.example.com"
  port: 443
  use_https: true
  database: "my-db"
  token: "read-only-token"
```

This is the mode used by the reference `catafalco` deployment. The proxy must expose the
InfluxDB v3 query API; the MCP never needs the InfluxDB UI or write endpoints.

### Mode B: local SSH tunnel (loopback-only services)

The service may listen only on `127.0.0.1` on the target host. Either keep a tunnel open
yourself:

```bash
ssh -N -L 8181:127.0.0.1:8181 user@server.example.com
```

and point the MCP at the local side:

```yaml
influxdb:
  enabled: true
  host: "127.0.0.1"
  port: 8181
  use_https: false
  database: "my-db"
  token: "read-only-token"
```

or let the MCP create and close the tunnel itself with `ssh_tunnel`. It listens on a
loopback address only and uses the same `ssh` settings (host key verification, key or
agent) as the executor:

```yaml
influxdb:
  enabled: true
  use_https: false
  database: "my-db"
  token: "read-only-token"
  ssh_tunnel:
    enabled: true
    remote_host: "127.0.0.1"   # from the SSH server's point of view
    remote_port: 8181          # defaults to influxdb.port
    local_host: "127.0.0.1"    # must be loopback
    local_port: 0              # 0 = ephemeral local port
```

When `ssh_tunnel.enabled` is true, `influxdb.host`/`influxdb.port` are replaced at startup
by the local tunnel endpoint, so leave `use_https` false unless the service itself serves
TLS. The same block is available under `prometheus` (default remote port `9090`). The
tunnel uses the `ssh` section even when `executor: local`; if it cannot be opened, the
server exits with status 2 instead of starting with an unreachable endpoint.

A tunnel forwards to an address that is reachable from the target host, normally
`127.0.0.1`. It cannot create a Prometheus that was retired; on `catafalco` Prometheus is
disabled and there is no `node_exporter`.

## Databases

InfluxDB queries must be a single `SELECT`. A `LIMIT` is appended when the query has none.
Prometheus uses the read-only instant-query API. Use read-only tokens for both.

Prometheus is optional and is not a prerequisite for disk health. Telegraf's smart plugin
writing to InfluxDB (`smart_device`, `smart_attribute`) is the recommended SMART source.
The `smartmon_*` metric family named in the Prometheus examples exists only when
`node_exporter` runs with its smartmon collector; a host without `node_exporter` will return
an empty result for those queries, not an MCP error.

## Output and audit

- `output.max_bytes` caps every command result, file read and query response, and is also
  applied to the complete response of composite and listing tools. ANSI escapes and control
  characters are stripped before truncation; truncation is idempotent, so a response carries
  at most one marker.
- `audit.enabled` writes one JSON object per line. Records include timestamps, commands,
  paths, exit codes, durations and truncation flags. InfluxDB and Prometheus query records
  contain a query length and SHA-256 fingerprint, database/status and duration, never the
  query text. Password/token/secret fields are redacted. Audit logging is best effort and
  never blocks an operation.

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
