# remote-server-mcp

Security-first MCP server for Docker service management over SSH or on the local host.

Part of the [Server MCP suite](../../README.md). It exposes a fixed catalog of 13 tools
(logs, status, start/stop/restart, confined file reads, server health and read-only
InfluxDB/Prometheus queries). No generic command execution.

- [Tools](../../docs/tools.md)
- [Configuration](../../docs/configuration.md)
- [Security model](../../docs/security-model.md)
- [Getting started](../../docs/getting-started.md)

```bash
uv run --directory apps/remote-server-mcp remote-server-mcp
```

Requires a config file; see `config.example.yaml` in this directory.
