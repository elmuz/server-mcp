# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic
versioning.

## [0.4.0] - 2026-10-22

### Changed

- Disk tools accept one device vocabulary and resolve it serial-first. `get_disk_health`,
  `get_smart_attributes`, `get_nvme_health`, `run_smart_test` and `get_full_disk_report`
  now accept a kernel name (`sda`, `nvme0n1`), a bare NVMe controller (`nvme0`), a
  `/dev/<name>` path, a `/dev/disk/by-id/` path, a disk serial or a Telegraf role label
  (`Cache1`, `Parity1`), and resolve every spelling to the same physical disk. `nvme0` and
  `nvme0n1` return the same report and attribute set, and `run_smart_test("nvme0")` renders
  `/dev/nvme0n1`. Only the resolved canonical kernel name (still matched by
  `DEVICE_NAME_PATTERN`) is rendered into a command; the caller's string never is.
  Partition-shaped names (`sda1`, `nvme0n1p1`) are rejected.
- `get_nvme_health` refuses a non-NVMe disk instead of returning a report. The protocol is
  detected from `lsblk`'s `tran`, the field set of the stored Telegraf sample
  (`percentage_used`/`available_spare`/... for NVMe,
  `reallocated_sectors_count`/`wwn`/... for ATA) or `smartctl -j`, and a mismatch returns
  the detected type, the detection source and no `nvme-cli` command.
- The default host-unit allowlist is now `telegraf`, `smartmontools`, `docker` and `smbd`.
  `smartmontools` is the real unit (`smartd` is an alias that `journalctl -u` does not
  follow), and SnapRAID/mergerFS have no service to inspect. Host status and logs also
  publish structured entries.

### Fixed

- `run_smart_test` no longer reports "standby" for every exit status 2. A read-only
  `smartctl -i` probe classifies permission, standby, unsupported and generic errors,
  reports the raw output and exit status, omits `-n standby` for NVMe and points at the
  `smartctl -l selftest` log. `start_service` now requires `confirm=true`, checks state
  first and reports already-running containers without calling `docker start`.
- SnapRAID status is parsed into per-disk/total rows, sync state, scrub ages, errors and the
  zero-timestamp count while keeping the raw text. `list_disks` returns a readable table,
  `list_service_files` errors name the full path and base directory, `.env` redaction now
  masks only credential keys (and lists them in `data.redacted_keys`), and NVMe
  error-information counters are labelled as cumulative warnings rather than media errors.
- Container tools point a host systemd unit at the host-service tools, file-logging services
  at their mounted log directory, and Compose tools refuse an Ansible-managed or
  file-less directory without invoking Docker. Host journals accept `since`, and
  `search_host_service_logs` filters them locally. A bare relative duration is normalized
  to journalctl's `-2h` form (`2h` and `-2h` both work), while RFC3339 timestamps and dates
  are passed through unchanged. InfluxDB queries warn when a `GROUP BY` key is missing from
  the `SELECT` list.
- `get_nvme_health("sda")` used to return the same green generic SMART report as
  `get_disk_health` with no NVMe metrics, and a by-id path, serial or role label was
  rejected even though the serial is the documented disk identity. A non-NVMe request is
  now refused explicitly, and those spellings resolve to the live kernel name.

## [0.3.0] - 2026-10-22

### Fixed

- `get_full_disk_report` no longer loses failed-poll evidence after a disk label change.
  The overview keys standby/failed rows by `serial_no`, falling back to the `device` label
  only for rows that carry no serial, so a sleeping disk's stale sample keeps its
  explanation when the tag is rewritten.
- `get_smart_attributes` works again for NVMe disks. Its InfluxDB query filtered on
  `exit_status = 0`, but Telegraf writes that field only on the SATA `smartctl` rows, never
  on the NVMe ones, so every NVMe attribute was discarded and the tool fell through to an
  unprivileged `smartctl` that cannot open the device. Standby rows carry no attribute rows
  at all, so no filter is needed.
- Disk sample ages are pluralized (`1 minute ago`, not `1 minutes ago`).
- `get_service_file` no longer masks benign diagnostics whose only sensitive word is
  `auth`: `AUTH_TYPE`, `AUTH_USERNAME` and `AUTH_MODE` stay readable, while a bare `AUTH`,
  `BASIC_AUTH`, `PROXY_AUTH`, `AUTH_TOKEN` and `AUTH_PASSWORD` are still masked.

### Changed

- Disk reports show the role label next to the live kernel device —
  `🟢 Data1 (/dev/sda) - ST18000NT001` — instead of only one of the two. A legacy tag that
  still holds a kernel name is not presented as a label, and a sample whose serial does not
  match the requested device is named by the requested device alone.
- `disk-health-mcp` selects SMART samples by serial number instead of the `device` tag.
  `get_disk_health`, `get_smart_attributes` and `get_nvme_health` resolve the live disk with
  `lsblk` and query `serial_no = '<serial>'`; the `device` tag is only a fallback when the
  live serial cannot be resolved. The overview in `get_full_disk_report` partitions by
  `serial_no`, so one physical disk stays one line even if its label changes, and its
  structured payload reports `devices` (kernel names a per-disk tool accepts, empty when the
  disk has no live match), `labels` (the static role label, empty for a legacy tag) and
  `serials`, aligned by index. Failed polls are keyed by `serial_no` when the poller records
  one (the current Telegraf deployment stamps it on every poll, standby rows included) and
  fall back to the `device` label only for rows without it. This keeps a report attached to
  the same disk across a reboot that re-enumerates controllers; the deployment side
  publishes a static label (`Data1`, `Parity1`, ...) in the tag instead of a kernel name.
- The requested kernel name stays the reference for the identity check: when it no longer
  resolves, the report names the disk the sample actually belongs to and marks the identity
  unverified instead of verified. Failed polls are matched on the exact serial when a
  poller records one, plus the label the newest sample reported as a fallback, never on a
  kernel name that another disk may have used. Serials and tags are allowlisted before they are quoted into a
  query, and the failed-poll summary counts statuses instead of repeating each one.

## [0.2.1] - 2026-10-21

### Fixed

- `get_service_file` masks short credential keys it previously returned verbatim. Key names
  are normalized (quotes and leading CLI dashes removed) and matched as a whole word or word
  suffix, so `pass`, `pw`, `pwd`, `passphrase`, `db_pass`, `apikey`, `authToken`,
  `client_secret` and `Proxy-Authorization` are redacted while `tokenizer`, `keyboard`,
  `user`, `host` and `mode` stay readable. An INI file with `pass = …` is now masked.
- `disk-health-mcp` no longer presents stale or mismatched InfluxDB SMART data as current
  health. Samples older than two 5-minute poll intervals are marked stale instead of green,
  recent non-success polls are reported, and the stored serial/model/sample time are echoed
  alongside the live `lsblk` identity when available. A serial mismatch names both disks and
  refuses to call the requested device healthy. `get_nvme_health` and the overview in
  `get_full_disk_report` apply the same rules.

## [0.2.0] - 2026-10-20

This is the first published release. `0.2.0` was never tagged or published when the monorepo
consolidation landed, so the remediation work that followed it (P0/P1/P2 in
[docs/modernization-plan.md](docs/modernization-plan.md)) is part of the same release
instead of a separate version.

### Added

- Monorepo with a uv workspace: `apps/remote-server-mcp`, `apps/disk-health-mcp` and
  `packages/server-management-lib`, one lockfile and shared tooling.
- Local executor (`executor: local`) that runs validated argv vectors without a shell.
- SFTP-based file reads and listings, confined with remote `realpath` checks.
- Operation catalog for Docker commands, rendered with `shlex.join`; the shared `Operation`
  template is now used by both MCP servers, so `disk-health-mcp` also builds every host
  command from a typed argv-vector catalog.
- Output sanitization (ANSI/control characters) and a configurable 64 KiB cap.
- Opt-in JSONL audit log with secret redaction. The log also records InfluxDB and Prometheus
  queries, `prometheus_targets` calls and policy refusals (`file_blocked_sensitive`,
  `host_unit_blocked`, `query_blocked`, `rate_limited`) that happen before the executor.
  Query records contain a length and SHA-256 fingerprint, database, HTTP status and
  duration, never the query text or its literal values.
- MCP `ToolAnnotations` for read-only and destructive tools.
- CI workflows for Python 3.11-3.14, `py.typed` markers and coverage gates.
- Harness-agnostic documentation and examples for pi, Claude Code, Codex, Cursor and
  opencode.
- Every tool now returns MCP `structuredContent` as a `ToolResponse` (`ok`, `tool`,
  `summary`, `text`, `data`) alongside the existing readable text block.
- `remote-server-mcp` exposes `list_containers` (`docker ps -a`), so stopped and crashed
  containers are discoverable, and `get_container_health`, which returns Docker healthcheck
  status, failing streak and recent probe output.
- Service tools accept a service directory or a container name. Directories resolve to
  their containers through the `com.docker.compose.project` label; container names are
  accepted when their project maps to a directory under `services_path` or when they are
  listed in the new `security.allowed_containers` option.
- `remote-server-mcp` exposes `get_host_service_status` and `get_host_service_logs` for
  host infrastructure services that are systemd units rather than containers. Units are
  restricted to the new `security.host_units` allowlist (default: `telegraf`, `smartd`,
  `docker`, `snapraid`, `mergerfs`, `smbd`).
- `disk-health-mcp` exposes `get_snapraid_status` and `get_mount_status` (`findmnt` plus
  `df`) for mergerFS + SnapRAID hosts, alongside the existing ZFS and mdadm tools.
- `get_server_health` reports disk usage for every mount point in the new
  `health.disk_paths` option (default `["/"]`) and lists unhealthy containers. NAS pools
  such as `/mnt/storage` are visible without relying on the root filesystem.
- `get_service_logs` and `search_service_logs` accept optional `since`/`until` time windows
  and a `container` argument to target one container in a compose project. Docker logs
  always include timestamps for correlation with host events.
- `disk-health-mcp` reports the age of the InfluxDB sample behind a health report and the
  disk overview. The last valid sample is looked up over a 24-hour window.
- Optional `ssh_tunnel` block for `influxdb` and `prometheus`. For a loopback-only metric
  service, the MCP opens a local port forward over the configured SSH connection at
  startup, uses the local endpoint for queries and closes the tunnel on shutdown. The
  listener is restricted to a loopback address.
- Both servers expose MCP resources: `server-mcp://config/schema` (defaults with secrets
  masked), `server-mcp://tools/catalog` and a `server-mcp://tools/{name}` template.
- Opt-in Streamable HTTP transport (`--transport streamable-http`, `transport.*`). It binds
  to loopback by default and requires a bearer token for any non-loopback address.
- `container_runtime` selects `docker` (default), `podman` or `nerdctl` for the
  remote-server operation catalog.
- `remote-server-mcp` exposes `compose_ps`, `compose_pull`, `compose_up` and `compose_down`,
  scoped to `services_path/<service>` and validated by the command policy.
- Destructive and state-changing tools accept `confirm`; without `confirm=true` they return
  a dry-run command preview and execute nothing.
- Per-process sliding-window rate limiting for state-changing tools (`rate_limit`).
- General secret redaction for readable service files (YAML/JSON/INI/command-line shapes,
  bearer headers, JWTs and URL passwords) and for `systemctl status` / `journalctl` output,
  in addition to the existing `.env` masking. Keys and structure stay readable; credential
  stores and key material are still refused outright.
- `[project.urls]`, authors, keywords and classifiers in the published package metadata.
- CI runs `pymarkdown` and the markdown link check, and the repository ships issue/PR
  templates, `CODEOWNERS` and a code of conduct.

### Changed

- Migrated to MCP SDK 2.x (`mcp.server.mcpserver.MCPServer`).
- Configuration is resolved from `--config`, environment, XDG paths or the working
  directory; the server exits with status 2 when no config is found.
- Host key verification is enabled by default; unparseable known_hosts entries are skipped
  individually.
- InfluxDB validation parses SQL instead of blacklisting shell characters; PromQL accepts
  label matchers, quotes and comparison operators.
- `services_path` is honored by every tool and the SSH executor.
- Disk-health reuses one SSH connection instead of reconnecting per call.
- SMART parsing uses `smart_support`/`smart_status` and no longer reports missing status as
  `FAILED`.
- Console entry points now work (`remote-server-mcp` / `disk-health-mcp`).
- Concurrent SSH tool calls are serialized while connecting, so they share one connection
  instead of racing and leaking connections. Metric SSH tunnels detect a dropped connection,
  re-open the forward on the same local port with backoff and report `down`/`last_error`
  while reconnecting.
- `InfluxDBClient` and `PrometheusClient` keep one `aiohttp.ClientSession` per client; both
  servers cache one client per metric service and close the sessions on shutdown.
  `get_full_disk_report` now issues one window-function query instead of `1 + N` queries.
- `get_service_status` skips `docker stats` and `docker port` for a stopped container, which
  removes a 1–2 second delay per stopped container. It also reports `Health`, `FailingStreak`
  and `ExitCode` instead of only `State: running`.
- All `disk-health-mcp` tools now publish structured `data` on success, including SMART/NVMe
  attributes, self-test status, ZFS/RAID/SnapRAID/mount/I/O output and decoded query rows.
- The PromQL validation error now describes the actual policy (no null/control bytes, at
  most 5000 characters) instead of claiming quotes and newlines are rejected.
- `restart_service`, `stop_service`, `compose_pull`, `compose_up` and `compose_down` now
  require `confirm=true`.
- A skipped known_hosts entry is reported in one aggregated warning per file instead of one
  warning per line.
- `get_service_status`, `get_container_health`, `get_service_logs`, `search_service_logs`,
  `start_service`, `restart_service` and `stop_service` now resolve compose projects to
  all of their containers and label the output per container.
- `SecurityValidator.is_command_safe()` is now a strict argv allowlist. Unknown executables,
  shell operators and hand-built command strings are rejected; the permissive fall-through
  is gone. `security.allow_generic_commands` is accepted but has no effect.
- The same policy validates the complete argument shape for sensitive command families
  (containers, `systemctl`, `journalctl`, `smartctl`, `nvme`, `ls`, `test`, `df`, `lsblk`,
  `zpool`, `zfs`, `mdadm`, `cat`, `snapraid`, `findmnt`) and rejects control characters in
  every token. A safe prefix alone no longer passes, and `docker inspect --format` strings
  that reference `.Config`, `.Args`, `.Mounts`, `.HostConfig` or `.NetworkSettings` are
  rejected.
- InfluxDB validation now rejects SQL comments and treats a `LIMIT` inside a string literal,
  identifier or nested subquery as absent. An outermost numeric `LIMIT` is clamped to
  `query_limit`, and disk-health query tools send the validated query text to the client.
- `start_service` and `disk-health-mcp`'s `run_smart_test` are rate-limited. Bearer auth
  accepts the scheme case-insensitively while comparing the token in constant time.
- `search_service_logs` now matches the literal pattern. Shell punctuation (`!`, `#`, `~`,
  quotes, backslashes) is no longer stripped; only length and control characters are
  validated. The old `sanitize_search_pattern()` is replaced by
  `validate_search_pattern()`.
- Sample configs and the configuration docs show the two supported metric endpoint modes:
  an HTTPS reverse proxy (hostname/IP, `use_https: true`, bearer token) or a loopback SSH
  tunnel. Database names in examples are generic, and the Prometheus examples state that
  `smartmon_*` metrics require `node_exporter`; Prometheus is optional for disk health.
- `docker logs --since/--until` values are validated as RFC3339 timestamps, dates or
  relative durations before a command is built.
- Composite and listing tool responses (service files, server health, host-service logs,
  ZFS/RAID/SnapRAID/mount summaries and the full disk report) receive a final
  `output.max_bytes` cap in addition to the per-command cap. Truncation is idempotent, so
  nested caps append only one marker.
- `run_smart_test` pre-flights `/usr/sbin/smartctl --version` before the write operation and
  reports a clear "no test was started" error when smartctl is unavailable. The test command
  uses `-n standby`, so a sleeping disk is skipped (exit status 2) instead of being spun up.
- The `disk-health-mcp` coverage gate is 65% (raised from 55%).

### Fixed

- The InfluxDB and Prometheus clients detect HTML response bodies (reverse-proxy error
  pages, gateway down, login portals) before labelling a failure as a query error. The
  diagnostic names the URL and HTTP status, caps the page to a short excerpt, and a
  `200 text/html` or malformed JSON body is reported instead of escaping as an unhandled
  exception. The InfluxDB file-scan hint now follows the actual `WHERE ... time`
  predicate, and `disk-health` publishes the resolved database name in structured output.
- `get_service_status` renders the inspect fields on separate lines again. `docker inspect`
  does not expand `\n` in the literal part of a `--format` string (unlike `docker ps` and
  `docker stats`), so the previous format produced one line with literal `\n` sequences.
  `_container_running` could therefore never read `State.Running`, which also disabled the
  "skip `docker stats`/`docker port` for a stopped container" fast path. The newlines are
  now emitted by a template action (`{{"\n"}}`), keeping the argv free of control
  characters for the command policy.
- Removed the runtime SMART database self-rewrite that dropped `SEAGATE_COMPOSITE`.
- Fixed `docker stats` argument ordering.
- Validate NVMe devices before any database query.
- Removed the dead asyncssh ML-KEM patch and bounded `asyncssh<3`.
- Dropped the unused `pydantic` dependency.
- `disk-health-mcp` no longer fabricates a `100/100` healthy report when InfluxDB and the
  `smartctl` fallback both fail; command failures and unusable text output are rejected.
- NVMe devices are normalized from kernel names (`nvme0n1`) to Telegraf tags (`nvme0`) for
  InfluxDB lookups.
- Host-tool fallbacks use absolute `/usr/sbin/smartctl` and `/usr/sbin/nvme` paths, so
  non-interactive SSH sessions no longer fail with `command not found`.
- Disk-health tools ignore Telegraf standby rows (`exit_status != 0`) that have no
  `health_ok` or temperature. A sleeping disk now produces an explicit "no recent valid
  sample" error instead of `Unknown` / `0°C` / `0 hours`. The InfluxDB lookback is 24 hours
  instead of 10 minutes, covering a 5-minute poll plus sleep cycles.
- `get_full_disk_report` filters `lsblk` to whole disks (`type: disk`) and validates each
  name, so `loop`, `rom`, `zram` and partition entries never reach `smartctl`. The device
  pattern now accepts `sdaa`–`sdzz` for hosts with more than 26 disks.
- Unhealthy containers are visible: `docker inspect` reports health fields and
  `get_container_health` returns the failing probe output.
- Compose projects no longer require a container with the same name as the `/srv`
  directory (`immich` now resolves to `immich-server`, `immich-postgres`, ...).
- `get_service_status` reports "Container is not running; resource usage is unavailable"
  for stopped containers instead of Docker's zeroed `0B / 0B` statistics.
- `EXECUTOR` and `CONTAINER_RUNTIME` environment variables now set the top-level config
  values instead of creating malformed nested sections. Environment overrides also apply
  when no config file is found, rather than being silently skipped.
- SSH file reads and directory listings resolve both the requested path and the allowed
  base with the remote `realpath`, so a symlinked `/srv` works and the confinement check
  compares canonical paths.
- File reads reject FIFOs, device nodes and other non-regular files. SFTP operations are
  time-bounded and local file reads run in a worker thread, so a special file cannot hang
  the MCP server or block the event loop.
- `get_service_file` no longer rejects `.env` files. Dotenv contents are returned with
  their values masked (`KEY=***`), while private keys, credential stores and secret-named
  paths are still refused with an explicit sensitive-file error.
- Sensitive-file matching is per path component and extension instead of a substring of
  the whole path, so `monkey.txt` and `tokenizer.json` are readable. The invalid-path error
  no longer claims a valid path is outside the service directory.
- Service file paths are built lexically with `PurePosixPath` instead of resolving them on
  the MCP host. A local `/srv` symlink can no longer change the remote path; the executor's
  target-side `realpath` check remains authoritative.
- Direct SMART access keeps the global `sudo` block and now returns clear permission errors;
  documentation recommends block-device access for the executor user and InfluxDB as the
  preferred source.
- The audit directory and file are created with `0700`/`0600` permissions, and an existing
  world-readable `audit.jsonl` is tightened on the next write.
- The `query_prometheus_disk` documentation no longer implies that Prometheus or
  `node_exporter` is required for disk health; the Telegraf/InfluxDB path is documented as
  the primary SMART source.

### Removed

- Qwen Code and vLLM-specific configuration, docs and ignore files.
- Per-repository lockfiles, CI workflows and duplicated markdown tooling.

## [0.1.0] - 2026-04-14

- Initial `remote-server-mcp`, `disk-health-mcp` and `server-management-lib` releases.
