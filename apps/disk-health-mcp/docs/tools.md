# Available Tools

All tools validate inputs against the security policy before execution. See [security-model.md](security-model.md) for details.

## Host-Based Tools (SSH)

| Tool | Description | Safety Notes |
|------|-------------|--------------|
| `list_disks` | List all storage devices on host | No input parameters |
| `get_disk_health` | Full health analysis with manufacturer normalization | Device validated; JSON + text parsing |
| `get_smart_attributes` | Raw SMART attributes table | Device validated; severity assessed |
| `get_nvme_health` | NVMe SMART health log | Device validated |
| `run_smart_test` | Trigger SMART self-test | Device + test type validated |
| `get_zfs_status` | ZFS pool health and capacity | No input parameters |
| `get_raid_status` | mdadm RAID status | No input parameters |
| `get_io_stats` | I/O utilization and latency | No input parameters |

## Database Tools (HTTP API)

| Tool | Description | Safety Notes |
|------|-------------|--------------|
| `query_prometheus_disk` | Query Prometheus for disk metrics | Shell injection blocked |
| `query_influxdb_disk` | Query InfluxDB for historical trends | SELECT only; SQL injection blocked |

## Analysis Tools

| Tool | Description | Safety Notes |
|------|-------------|--------------|
| `get_full_disk_report` | Comprehensive health overview | Aggregates host-based data; device validated |

## Tool Details

### `list_disks()`

Lists all block devices with name, model, serial, size, type, and transport.

Command: `lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json`

### `get_disk_health(device)`

The primary health analysis tool. **Data source priority:**
1. **InfluxDB** (Telegraf smart plugin) — no root required
2. **smartctl via SSH** — fallback when InfluxDB unavailable

Parses SMART data with:

- **Manufacturer detection** — Identifies Seagate, WD, Samsung, Toshiba, Intel
- **Seagate normalization** — Decodes 48-bit composite raw values
- **Severity assessment** — ok, warning, or critical per attribute
- **Health score** — 0-100 normalized score
- **Human-readable summary** — Flags issues with emoji indicators

Primary command: `smartctl -j -a /dev/{device}` (falls back to text parsing)

### `get_smart_attributes(device)`

Returns a formatted table of all SMART attributes with severity annotations.

**Data source priority:** InfluxDB → smartctl fallback

Command: `smartctl -j -a /dev/{device}`

### `get_nvme_health(device)`

Gets NVMe SMART health information.

**Data source priority:** InfluxDB → nvme-cli fallback

Command: `nvme smart-log /dev/{device}`

### `run_smart_test(device, test_type="short")`

Triggers a SMART self-test. Tests are safe — they scan the media for errors without modifying data.

Test types:
- **short** (~2 min): Electrical/mechanical check + short media scan
- **long** (hours): Full media scan
- **conveyance** (~5 min): Checks for transport/shipping damage

Command: `smartctl -t {type} /dev/{device}`

Results appear in the SMART self-test log (visible in `get_disk_health`).

### `get_zfs_status()`

Reports ZFS pool names, sizes, allocation, dedup ratio, and health.

Commands: `zpool status -x` and `zpool list`

### `get_raid_status()`

Reports mdadm software RAID status including array health, device state, and sync progress.

Commands: `cat /proc/mdstat` and `mdadm --detail --scan --verbose`

### `get_io_stats()`

Reports per-device I/O utilization, latency, throughput, and queue depth.

Command: `iostat -x 1 1`

### `query_prometheus_disk(query)`

Queries Prometheus for disk-related metrics. Useful with:

- `smartmon_health_ok` — SMART pass/fail status
- `smartmon_temperature_celsius` — Drive temperatures
- `node_disk_io_time_seconds_total` — I/O utilization
- `node_md_disks` — RAID disk status

### `query_influxdb_disk(query, database=None)`

Queries InfluxDB for historical disk metrics. Useful for trend analysis:

```sql
-- SMART reallocated sectors over time
SELECT mean(value) FROM smart
WHERE time > now() - INTERVAL '7 days'
  AND attribute_name = 'reallocated_sector_ct'
GROUP BY host, device
```

### `get_full_disk_report(device=None)`

Comprehensive health report. If `device` is specified, returns detailed analysis of that device. If omitted, returns an overview of all disks with severity summary.

This is the recommended entry point for overall disk health assessment.
