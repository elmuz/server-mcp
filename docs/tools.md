# Tools

Both servers expose a fixed catalog. Tools marked **read-only** are annotated with
`readOnlyHint`; **destructive** tools set `destructiveHint`. Output is sanitized and capped
at `output.max_bytes` (64 KiB by default).

Every tool also returns MCP `structuredContent`: a `ToolResponse` object with `ok`, `tool`,
`summary`, `text` and a `data` payload (container lists, query rows, file metadata and so
on). Text-only clients keep receiving the same readable block as before. The config schema
and the tool catalog are available as MCP resources; see [architecture.md](architecture.md).

## remote-server-mcp

| Tool | Arguments | Access | What it does |
|---|---|---|---|
| `list_services` | — | read-only | Lists directories under `services_path` and running Docker containers |
| `list_containers` | — | read-only | Lists every container (`docker ps -a`), including stopped and crashed ones, with compose project and service mapping |
| `get_service_logs` | `service`, `lines` (1–1000), `since`, `until`, `container` | read-only | Returns timestamped container logs with optional time window and per-container targeting; multi-container services are labelled per container |
| `search_service_logs` | `service`, `pattern`, `lines` (1–5000), `since`, `until`, `container` | read-only | Filters timestamped logs for an exact literal string (no regex); punctuation is preserved |
| `get_service_status` | `service` | read-only | `docker inspect` (state, health, failing streak, exit code), `docker stats` and exposed ports for every resolved container; stopped containers report that resource usage is unavailable instead of `0B / 0B` |
| `get_container_health` | `service`, `entries` (1–20) | read-only | Healthcheck status and recent probe output for every resolved container |
| `get_host_service_status` | `unit` | read-only | `systemctl status` for a unit in `security.host_units` |
| `get_host_service_logs` | `unit`, `lines` (1–1000) | read-only | `journalctl -u` for a unit in `security.host_units` |
| `get_service_file` | `service`, `file_path` | read-only | Reads a file inside the service directory over SFTP; `.env` values and recognized secrets in compose/config files are masked, and key/credential files are refused |
| `list_service_files` | `service`, `subdirectory` | read-only | Lists files inside the service directory |
| `get_server_health` | — | read-only | Uptime, memory, disk usage for every `health.disk_paths` mount, running containers and unhealthy containers |
| `query_influxdb` | `query`, `database` | read-only | Single `SELECT` against InfluxDB v3 |
| `query_prometheus` | `query`, `time` | read-only | Instant PromQL query (Prometheus is optional) |
| `get_prometheus_targets` | — | read-only | Prometheus scrape targets and health (optional) |
| `compose_ps` | `service` | read-only | `docker compose --project-directory <service> ps` |
| `start_service` | `service` | write | `docker start` |
| `compose_pull` | `service`, `confirm` | write | `docker compose ... pull` after confirmation |
| `compose_up` | `service`, `confirm` | write | `docker compose ... up -d --remove-orphans` after confirmation |
| `restart_service` | `service`, `confirm` | destructive | `docker restart` after confirmation |
| `stop_service` | `service`, `confirm` | destructive | `docker stop` after confirmation |
| `compose_down` | `service`, `confirm` | destructive | `docker compose ... down --remove-orphans` after confirmation |

### Examples

```text
list_services()
list_containers()
get_service_logs("grafana", lines=200)
get_service_logs("immich", lines=500, since="2h")
get_service_logs("immich", container="immich-server", since="2026-10-18T20:00:00Z")
search_service_logs("grafana", "error", lines=5000)
search_service_logs("immich", "connection refused", since="30m", until="10m")
get_service_status("grafana")
get_service_status("vllm")             # stopped: resource usage is unavailable
get_service_status("immich")           # resolves to immich-server, immich-postgres, ...
get_service_status("immich-server")    # container name, via its compose project
get_container_health("deluge", entries=5)
compose_ps("immich")
compose_pull("immich", confirm=True)
compose_up("immich", confirm=True)
compose_down("immich", confirm=True)
restart_service("immich", confirm=True)
get_host_service_status("telegraf")   # systemd unit, not a container
get_host_service_logs("telegraf", lines=200)
get_service_file("grafana", "provisioning/datasources/influxdb.yml")
get_service_file("cypht", ".env")       # values masked as KEY=***
get_service_file("cypht", "compose.yml") # inline passwords/tokens masked
query_prometheus('up{job="node"} > 0')  # optional; any Prometheus target
query_influxdb("SELECT * FROM smart_device WHERE time > now() - INTERVAL '1 hour' LIMIT 100")
```

## disk-health-mcp

| Tool | Arguments | Access | What it does |
|---|---|---|---|
| `list_disks` | — | read-only | `lsblk` JSON: names, models, serials, sizes |
| `get_disk_health` | `device` | read-only | Full health report from the latest valid InfluxDB sample (successful rows in the last 24 hours) with freshness, serial/live-device identity and failed-poll evidence, or `smartctl` |
| `get_smart_attributes` | `device` | read-only | SMART attribute table with severity notes, ignoring standby rows |
| `get_nvme_health` | `device` | read-only | NVMe SMART log (latest valid InfluxDB sample first, then `nvme-cli`) with the same freshness and identity checks |
| `get_full_disk_report` | `device` (optional) | read-only | Overview of all disks with sample age, freshness, identity and failed polls, or a detailed report |
| `get_zfs_status` | — | read-only | ZFS pool status, capacity and scrub state |
| `get_raid_status` | — | read-only | `/proc/mdstat` and `mdadm --detail` |
| `get_snapraid_status` | — | read-only | `snapraid status`: parity age, sync state and disk errors |
| `get_mount_status` | — | read-only | `findmnt` mounts, mergerFS pools and `df` usage |
| `get_io_stats` | — | read-only | `iostat -x` |
| `query_influxdb_disk` | `query`, `database` | read-only | Historical disk metrics as SQL |
| `query_prometheus_disk` | `query` | read-only | Disk metrics as PromQL (optional; see note) |
| `run_smart_test` | `device`, `test_type` | write | Starts a short/long/conveyance self-test after a `smartctl` pre-flight; skips a sleeping disk |

### Examples

```text
list_disks()
get_disk_health("sda")
get_smart_attributes("nvme0n1")
get_full_disk_report()
get_snapraid_status()
get_mount_status()
run_smart_test("sda", "short")
query_influxdb_disk("SELECT * FROM smart_device WHERE time > now() - INTERVAL '1 hour'")
query_prometheus_disk('node_disk_io_time_seconds_total{device="sda"}')
```

Prometheus is optional. The `smartmon_*` metric family used in some SMART examples exists
only when `node_exporter` runs with its smartmon collector. A host without `node_exporter`
returns an empty result for those queries; use `query_influxdb_disk` and the Telegraf
`smart_device`/`smart_attribute` measurements instead. Prometheus is not a prerequisite
for `get_disk_health`, `get_smart_attributes`, `get_nvme_health` or `get_full_disk_report`.

### Which storage tool applies to which stack

| Storage stack | Tools |
|---|---|
| ZFS | `get_zfs_status`, plus `list_disks`/`get_disk_health` for the underlying devices |
| mdadm software RAID | `get_raid_status`, plus the SMART tools |
| mergerFS + SnapRAID | `get_snapraid_status`, `get_mount_status`, plus the SMART tools |
| Single disks / NVMe | `list_disks`, `get_disk_health`, `get_smart_attributes`, `get_nvme_health` |

`get_zfs_status` and `get_raid_status` are kept for ZFS and mdadm hosts. A mergerFS +
SnapRAID host will report a missing `zpool`/`mdadm` command, which is expected; use
`get_snapraid_status` and `get_mount_status` instead. All three host tools require
`host.enabled: true`.

Container health comes from Docker's own healthcheck state. `get_service_status` reports
`Health`, `FailingStreak` and `ExitCode` from `docker inspect`; `get_container_health`
returns the last probe outputs so a failing check can be diagnosed. For a stopped
container, `get_service_status` reports that resource usage is unavailable rather than
printing Docker's zeroed `0B / 0B` stats.

## Logs, timestamps and search

`get_service_logs` and `search_service_logs` always pass `--timestamps` to `docker logs`,
so lines can be correlated with host events. Both accept an optional `since`/`until` window
and a `container` argument to target one container inside a compose project.

Time filters accept an RFC3339 timestamp (`2026-10-18T21:00:00Z`), a date (`2026-10-18`) or
a relative duration (`30m`, `2h`, `1h30m`). Any other value is rejected before a command is
built. Docker combines the time window with `--tail`, which still bounds the response size.

Search patterns are matched locally in Python. They are **not** rewritten: quotes, `!`,
`#`, `~`, backslashes and other punctuation keep their literal meaning. Only empty, overlong
(over 200 characters) or control-character patterns are rejected. No shell or `grep` is
involved, so a pattern that looks like shell syntax is just text.

## Confirmation and rate limiting

`restart_service`, `stop_service`, `compose_pull`, `compose_up` and `compose_down` accept a
`confirm` argument that defaults to `false`. Without it, the tool returns the exact command
it would run and executes nothing. Call the tool again with `confirm=true` after checking
the target. `start_service` and `compose_ps` do not need confirmation.

State-changing calls pass through a sliding-window limiter (`rate_limit` in the config:
`enabled`, `max_calls`, `window_seconds`; default 10 calls per 60 seconds). That includes
`start_service`, `restart_service`, `stop_service`, `compose_pull`, `compose_up` and
`compose_down`, plus `disk-health-mcp`'s `run_smart_test`. When the window is exhausted the
tool returns a rate-limit error and no command runs. The limiter is per server process, so
it bounds runaway retries rather than providing multi-user quotas.

The container CLI for all Docker/Compose tools is selected by `container_runtime`
(`docker`, `podman` or `nerdctl`). The command allowlist is identical for all three.

All responses are capped at `output.max_bytes` (64 KiB by default). Per-command output is
capped by the executor and composite/listing responses (service files, server health,
host-service logs, storage summaries and the full disk report) receive a final cap over the
complete response. A response is truncated at most once with the standard marker.

## Host service units

`get_host_service_status` and `get_host_service_logs` accept only units listed in
`security.host_units` (default: `telegraf`, `smartd`, `docker`, `snapraid`, `mergerfs`,
`smbd`). Pass the base unit name (`telegraf`), not `telegraf.service` or a path. An empty
allowlist disables both tools. The command policy additionally checks the complete argument
shape (`systemctl status --no-pager --full <unit>` and
`journalctl -u <unit> -n <int> --no-pager --output short-iso`), so extra flags or targets
are rejected before execution.

The executor user must be able to read the journal (`systemd-journal` or `adm` group).
Without that, `journalctl` exits 0 with "No entries" and a permission hint on stderr, so
`get_host_service_logs` looks empty rather than failing.

## SnapRAID privileges

`get_snapraid_status` runs `sudo -n /usr/local/bin/snapraid status`. SnapRAID creates the
content file and its `<content>.lock` as `root:root 0600`, so an unprivileged SSH user
cannot read either one. ACLs are not a fix: SnapRAID writes a `0600` temporary file and
renames it over the content file, and the `0600` mode masks inherited default-ACL entries
so they never take effect.

The target host therefore needs a sudoers rule for exactly this command, for example:

```text
funkysloth ALL=(root) NOPASSWD: /usr/local/bin/snapraid status
```

A host that already grants the executor blanket passwordless sudo needs no extra rule;
catafalco does (`security_sudoers_passwordless`), so the dedicated entry there only
documents the requirement. On a host with narrower sudo, the entry above is required and
its exact-argument match keeps `snapraid status <extra>` from running without a password.
`sudo --non-interactive` (`-n`) fails instead of prompting on a non-interactive SSH
session.

What the MCP can request is bounded by the command policy in `server-management-lib`: it
accepts only this exact argv and keeps `sudo` a blocked pattern for every other command,
regardless of what the sudoers file would allow. Install snapraid outside `/usr/local/bin`
and both the sudoers rule and `SNAPRAID_STATUS_SUDO_ARGV` must change.

## Device names

Block devices must match `sda`, `sdaa`–`sdzz`, `nvme0n1`, `vda`, `hda`, `mmcblk0p1` or
`dm-0`. The two-letter SATA/SAS form supports hosts with more than 26 disks. Partitions are
accepted where the pattern allows them (`mmcblk0p1`), but SMART tools expect a whole-disk
name. `get_full_disk_report` filters `lsblk` to `type: disk` and validates every name, so
`loop0`, `sr0`, `zram0` and partition rows never reach `smartctl`.

Telegraf stores NVMe devices without the namespace suffix (`nvme0`, not `nvme0n1`). The
disk-health tools normalize `nvmeXnY` to `nvmeX` for InfluxDB lookups; pass the kernel name
that `list_disks` returns.

A sleeping disk still produces a Telegraf `smart_device` row every poll interval. That row
has `exit_status=2` and no `health_ok`, `temp_c` or wear fields. The disk-health tools only
use rows with `exit_status = 0`, look back 24 hours for the last valid sample and report its
age. If no valid sample exists, they return an explicit "no recent valid sample" error
instead of rendering `Unknown`, `0°C` or `0 hours`.

Freshness and identity are assessed before a sample can be called healthy. Telegraf polls
SMART every five minutes, so a successful sample older than two poll intervals (10 minutes)
is marked **STALE** and is not rendered green. Recent non-success polls (`exit_status != 0`,
including standby/skipped polls) are listed with their latest timestamp and exit status.
The report echoes the stored model and serial and, when `host.enabled` allows `lsblk`, the
live device name/model/serial. If the live serial does not match the sample serial, the
report names both identities, refuses to use the sample for the requested disk and returns
an `UNKNOWN`/mismatch status. If the live device or serial cannot be resolved, the identity
is marked unverified rather than healthy. This applies to `get_disk_health`,
`get_nvme_health` and the no-device overview in `get_full_disk_report`; passing a device to
`get_full_disk_report` uses `get_disk_health`.

## Service and container names

Targets must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`. A service directory is no longer assumed
to have a container with the same name:

1. If `<services_path>/<target>` exists, it is a service directory. Its containers are the
   ones whose `com.docker.compose.project` label equals the target. When no container
   carries that label, a container with exactly the target name is used (legacy
   deployments).
2. Otherwise the target must be a container name. The container is accepted when its
   compose project maps to a directory under `services_path`, or when it is listed in
   `security.allowed_containers` (for standalone containers such as `watchtower`).

Containers started with explicit `docker run` do not carry a compose project label. A
single container whose name matches its service directory still works through rule 1, but
a multi-container stack (application plus database) is not grouped under one service
target. Address each container individually with `security.allowed_containers`, or add the
label explicitly with `--label com.docker.compose.project=<service>`.

`get_service_status`, `get_container_health`, `get_service_logs`, `search_service_logs`,
`start_service`, `restart_service` and `stop_service` accept either form. For a
multi-container project they act on every container and label the output per container;
this is why `restart_service` on a project restarts all of its containers.
`compose_ps`, `compose_pull`, `compose_up` and `compose_down` only accept a service
directory and run Compose with `--project-directory <services_path>/<service>`.
`get_service_file` and `list_service_files` still require a directory. Use
`list_containers()` to discover stopped or crashed containers and their compose projects;
a container whose `SERVICE` column is `-` is not addressable until you create the matching
directory or add its name to `security.allowed_containers`.

## Notes

- InfluxDB 3 Core has a file-scan limit. Queries without a `WHERE time` clause may fail with
  HTTP 500; add `WHERE time > now() - INTERVAL '1 hour'`.
- InfluxDB and Prometheus may be reached through an HTTPS reverse proxy or a loopback SSH
  tunnel. For a loopback-only service, use `ssh_tunnel` in the database section (the MCP
  opens it at startup) or keep `ssh -N -L` running yourself; see
  [configuration.md](configuration.md#database-endpoints).
- `docker port` exits non-zero when no ports are published; the tool reports the exit code.
- Direct `smartctl`/`nvme-cli` access requires the executor user to be able to open the
  block device (typically membership in the `disk` group or a matching udev rule). The MCP
  deliberately does not run commands through `sudo`; use InfluxDB as the preferred source
  when the executor has no device access.
- `run_smart_test` is a write operation and therefore needs real device access. It first
  runs `/usr/sbin/smartctl --version` (which never opens a block device) and returns a clear
  "no test was started" error when smartctl is unavailable. The test itself uses
  `-n standby`, so a sleeping disk is skipped instead of being spun up; wake the disk
  explicitly and retry if the test is required. Other failures return a permission/device
  error rather than claiming the test started.
- The disk-health tools that touch the host require `host.enabled: true`; InfluxDB-only
  diagnostics work with it disabled.
- `get_service_file` masks the values of `.env` files (`KEY=***`) and refuses private keys,
  credential stores and secret-named paths with a specific sensitive-file error. Matching
  is per path component and extension, so `monkey.txt` and `tokenizer.json` are readable.
  Other readable config files (YAML/JSON/INI/command-line shapes) are passed through a
  secret redactor: password/secret/token/API-key/authorization values (including short
  spellings such as `pass`, `pw`, `passphrase` and `db_pass`), bearer headers, JWTs and
  URL passwords are replaced with `***` while keys and structure stay readable.
  `get_host_service_status` and `get_host_service_logs` apply the same redaction because
  `systemctl status --full` and journal tails can contain command-line tokens.
