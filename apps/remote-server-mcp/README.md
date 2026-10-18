# remote-server-mcp

Security-first MCP server for Docker service management over SSH or on the local host.

Part of the [Server MCP suite](../../README.md). It exposes a fixed catalog of 17 tools
(directory and container discovery, container and host-service logs, status and health,
start/stop/restart, confined file reads, server health and read-only InfluxDB/Prometheus
queries). No generic command execution.

Host infrastructure services such as `telegraf`, `smartd` and `docker` are systemd units,
not containers. `get_host_service_status` and `get_host_service_logs` read them with
`systemctl`/`journalctl` and only accept units listed in `security.host_units`.

Container logs always include timestamps. A log request can add a `since`/`until` window
and target one container in a compose project; search matches the exact literal pattern.
Composite and listing responses receive a final `output.max_bytes` cap. When the audit log
is enabled, InfluxDB and Prometheus queries are recorded by length/SHA-256 fingerprint
rather than by query text.

Prometheus is optional. Its metric endpoints can be reached through an HTTPS reverse proxy
or a loopback-only `ssh_tunnel` created by the MCP; see
[configuration](../../docs/configuration.md#database-endpoints).

- [Tools](../../docs/tools.md)
- [Configuration](../../docs/configuration.md)
- [Security model](../../docs/security-model.md)
- [Getting started](../../docs/getting-started.md)

```bash
uv run --directory apps/remote-server-mcp remote-server-mcp
```

Requires a config file; see `config.example.yaml` in this directory.
