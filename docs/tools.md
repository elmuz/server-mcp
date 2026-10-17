# Tools

Both servers expose a fixed catalog. Tools marked **read-only** are annotated with
`readOnlyHint`; **destructive** tools set `destructiveHint`. Output is sanitized and capped
at `output.max_bytes` (64 KiB by default).

## remote-server-mcp

| Tool | Arguments | Access | What it does |
|---|---|---|---|
| `list_services` | — | read-only | Lists directories under `services_path` and Docker containers |
| `get_service_logs` | `service`, `lines` (1–1000) | read-only | Returns recent container logs |
| `search_service_logs` | `service`, `pattern`, `lines` (1–5000) | read-only | Filters recent logs for plain text (no regex) |
| `get_service_status` | `service` | read-only | `docker inspect`, `docker stats` and exposed ports |
| `get_service_file` | `service`, `file_path` | read-only | Reads a file inside the service directory over SFTP |
| `list_service_files` | `service`, `subdirectory` | read-only | Lists files inside the service directory |
| `get_server_health` | — | read-only | Uptime, memory, disk usage and running containers |
| `query_influxdb` | `query`, `database` | read-only | Single `SELECT` against InfluxDB v3 |
| `query_prometheus` | `query`, `time` | read-only | Instant PromQL query |
| `get_prometheus_targets` | — | read-only | Prometheus scrape targets and health |
| `start_service` | `service` | write | `docker start` |
| `restart_service` | `service` | destructive | `docker restart` |
| `stop_service` | `service` | destructive | `docker stop` |

### Examples

```text
list_services()
get_service_logs("grafana", lines=200)
search_service_logs("grafana", "error", lines=5000)
get_service_status("grafana")
get_service_file("grafana", "docker-compose.yml")
query_prometheus('up{job="node"} > 0')
query_influxdb("SELECT * FROM smart_device WHERE time > now() - INTERVAL '1 hour' LIMIT 100")
```

## disk-health-mcp

| Tool | Arguments | Access | What it does |
|---|---|---|---|
| `list_disks` | — | read-only | `lsblk` JSON: names, models, serials, sizes |
| `get_disk_health` | `device` | read-only | Full health report, preferring InfluxDB then `smartctl` |
| `get_smart_attributes` | `device` | read-only | SMART attribute table with severity notes |
| `get_nvme_health` | `device` | read-only | NVMe SMART log (InfluxDB first, then `nvme-cli`) |
| `get_full_disk_report` | `device` (optional) | read-only | Overview of all disks or a detailed report |
| `get_zfs_status` | — | read-only | ZFS pool status, capacity and scrub state |
| `get_raid_status` | — | read-only | `/proc/mdstat` and `mdadm --detail` |
| `get_io_stats` | — | read-only | `iostat -x` |
| `query_influxdb_disk` | `query`, `database` | read-only | Historical disk metrics as SQL |
| `query_prometheus_disk` | `query` | read-only | Disk metrics as PromQL |
| `run_smart_test` | `device`, `test_type` | write | Starts a short/long/conveyance self-test |

### Examples

```text
list_disks()
get_disk_health("sda")
get_smart_attributes("nvme0n1")
get_full_disk_report()
run_smart_test("sda", "short")
query_prometheus_disk('smartmon_temperature_celsius > 55')
```

## Device names

Block devices must match `sda`, `nvme0n1`, `vda`, `hda`, `mmcblk0p1` or `dm-0`. Partitions
are accepted where the pattern allows them; pass the whole disk for SMART operations.

## Service names

Service names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`. The directory under `services_path`
is the service; the Docker container is assumed to have the same name.

## Notes

- InfluxDB 3 Core has a file-scan limit. Queries without a `WHERE time` clause may fail with
  HTTP 500; add `WHERE time > now() - INTERVAL '1 hour'`.
- `docker port` exits non-zero when no ports are published; the tool reports the exit code.
- `run_smart_test` requires device access. On most systems that means running the MCP as a
  user with the appropriate permissions or configuring passwordless sudo for `smartctl`.
- The disk-health tools that touch the host require `host.enabled: true`; InfluxDB-only
  diagnostics work with it disabled.
