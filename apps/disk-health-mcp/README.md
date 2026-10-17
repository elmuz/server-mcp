# Disk Health MCP

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A disk health diagnostics MCP server. Analyzes SMART, NVMe, ZFS, RAID, and I/O metrics with manufacturer-aware severity assessment.

**Design principle:** Whitelist diagnostic operations, normalize across manufacturers, provide actionable health insights.

```text
┌───────────────┐    ┌────────────────────────┐    ┌───────────────────────┐    ┌──────────────┐
│  AI Assistant │───▶│    disk-health-mcp     │───▶│ server-management-lib │───▶│  SSH to Host │
│  (Qwen Code)  │◀───│  • SMART parser        │    │  • SecurityValidator  │    │              │
└───────────────┘    │  • Severity assessment │    │  • SSHManager         │    │  • smartctl  │
                     │  • Health scoring      │    │  • InfluxDBClient     │    │  • nvme-cli  │
                     │  • InfluxDB-first prio │    │  • PrometheusClient   │    │  • zpool     │
                     │  • MCP tool handlers   │    │  • config loader      │    │  • mdadm     │
                     └────────────────────────┘    └───────────────────────┘    │  • iostat    │
                                                                                └──────────────┘
```

## Quick Start

```bash
uv pip install -e . --python .venv
cp config.example.yaml config.yaml   # edit with your SSH details
uv run pytest tests/ -v
```

See [Getting Started](docs/getting-started.md) for full setup.

## Why This Exists

SMART data is notoriously hard to interpret:

- **Seagate** uses 48-bit composite raw values that look catastrophic on other brands
- **"Pre-fail"** doesn't mean "about to fail" — it means "tracked since manufacturing"
- **Thresholds vary** by manufacturer — a `Raw_Read_Error_Rate` of 15000 is normal on Seagate but fatal on WD
- **Single snapshots** miss trends — 5 reallocated sectors growing to 12 is more concerning than a static 20

This MCP normalizes all of that and gives you a **health score (0-100)** with clear severity flags.

## Available Tools

| Tool | Purpose |
|------|---------|
| `list_disks` | List all storage devices |
| `get_disk_health` | Full health analysis with severity |
| `get_smart_attributes` | Raw SMART attributes table |
| `get_nvme_health` | NVMe SMART health log |
| `run_smart_test` | Trigger SMART self-test (short/long/conveyance) |
| `get_zfs_status` | ZFS pool health and capacity |
| `get_raid_status` | mdadm RAID status |
| `get_io_stats` | I/O utilization and latency |
| `query_prometheus_disk` | Query Prometheus for disk metrics |
| `query_influxdb_disk` | Query InfluxDB for historical trends |
| `get_full_disk_report` | Comprehensive report for all disks |

See [Tools](docs/tools.md) for detailed descriptions.

## Architecture

This project depends on [server-management-lib](https://github.com/elmuz/server-management-lib), which provides:

| Component | Purpose |
|-----------|---------|
| `SecurityValidator` | Device name validation, command whitelist, query validation |
| `SSHManager` | Secure SSH connection management with whitelisted commands |
| `InfluxDBClient` | Read-only InfluxDB v3 SQL queries |
| `PrometheusClient` | Read-only Prometheus PromQL queries |
| `load_config` | YAML configuration loading with defaults |

disk-health-mcp contributes the disk-specific logic: SMART parsing, manufacturer detection, health scoring, and MCP tool handlers.

## Development

```bash
uv run ruff check . && uv run ruff format --check . && uv run ty check && uv run pymarkdown -c .pymarkdown scan . && uv run python scripts/check_md_links.py && uv run pytest tests/ --cov=disk_health_mcp --cov-report=term-missing --tb=short
```

See [Development](docs/development.md) for project structure and how to add new tools safely.

## License

MIT
