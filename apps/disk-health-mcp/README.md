# disk-health-mcp

MCP server for disk health diagnostics: SMART, NVMe, ZFS, RAID and I/O metrics, with
manufacturer-aware severity assessment.

Part of the [Server MCP suite](../../README.md). It exposes 13 read-mostly tools and can
use InfluxDB/Telegraf data before falling back to `smartctl`/`nvme-cli` over SSH or
locally. Every tool publishes a structured `ToolResponse` next to the readable text.
Streamable HTTP is available with `--transport streamable-http` (loopback by default,
bearer token for other addresses).

Storage coverage includes ZFS, mdadm and mergerFS + SnapRAID (SnapRAID status and a mount
summary), so the same server can diagnose NAS stacks that do not use ZFS or RAID.

InfluxDB lookups use only successful SMART samples (`exit_status = 0`) from the last 24
hours and ignore standby rows instead of presenting them as zeroed health data. Reports
show the sample timestamp, model and serial, plus the live `lsblk` identity when it can be
resolved. A sample older than two 5-minute poll intervals (10 minutes) is marked stale, and
recent non-success polls are reported instead of hidden. A serial that does not match the
live device is named as a mismatch and is never rendered as the requested disk's health.
`run_smart_test` pre-flights `smartctl` and uses `-n standby`, so it reports an unavailable
tool or a sleeping disk instead of starting a test blindly. Telegraf -> InfluxDB is the
supported SMART source; Prometheus is optional and
the `smartmon_*` metrics require `node_exporter` with its smartmon collector. A
loopback-only InfluxDB can be reached with the optional `ssh_tunnel` block (or a manual
`ssh -N -L`); see [configuration](../../docs/configuration.md#database-endpoints).

- [Tools](../../docs/tools.md)
- [Configuration](../../docs/configuration.md)
- [Security model](../../docs/security-model.md)
- [Getting started](../../docs/getting-started.md)

```bash
uv run --directory apps/disk-health-mcp disk-health-mcp
```

Requires a config file; see `config.example.yaml` in this directory. The SMART attribute
database is generated offline with `scripts/generate_smartdb.py`.
