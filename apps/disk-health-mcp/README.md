# disk-health-mcp

MCP server for disk health diagnostics: SMART, NVMe, ZFS, RAID and I/O metrics, with
manufacturer-aware severity assessment.

Part of the [Server MCP suite](../../README.md). It exposes 11 read-mostly tools and can use
InfluxDB/Telegraf data before falling back to `smartctl`/`nvme-cli` over SSH or locally.

- [Tools](../../docs/tools.md)
- [Configuration](../../docs/configuration.md)
- [Security model](../../docs/security-model.md)
- [Getting started](../../docs/getting-started.md)

```bash
uv run --directory apps/disk-health-mcp disk-health-mcp
```

Requires a config file; see `config.example.yaml` in this directory. The SMART attribute
database is generated offline with `scripts/generate_smartdb.py`.
