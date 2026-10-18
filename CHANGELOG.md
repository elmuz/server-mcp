# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic
versioning.

## [Unreleased]

### Added

- Every tool now returns MCP `structuredContent` as a `ToolResponse` (`ok`, `tool`,
  `summary`, `text`, `data`) alongside the existing readable text block.
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
- `[project.urls]`, authors, keywords and classifiers in the published package metadata.
- CI runs the markdown checks and Python 3.14, and the repository ships issue/PR templates,
  `CODEOWNERS` and a code of conduct.
- `remote-server-mcp` exposes `get_container_health`, returning Docker healthcheck status,
  failing streak and recent probe output. `get_service_status` now includes `Health`,
  `FailingStreak` and `ExitCode`.
- `remote-server-mcp` exposes `list_containers`, backed by `docker ps -a`, so stopped and
  crashed containers are discoverable.
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
- Shared `Operation` template in `server-management-lib`; both MCP servers use argv-vector
  operation catalogs.
- Optional `ssh_tunnel` block for `influxdb` and `prometheus`. For a loopback-only metric
  service, the MCP opens a local port forward over the configured SSH connection at
  startup, uses the local endpoint for queries and closes the tunnel on shutdown. The
  listener is restricted to a loopback address.
- The audit log now records InfluxDB and Prometheus queries. Records contain a query
  length and SHA-256 fingerprint, database, HTTP status and duration, never the query text
  or its literal values.

### Changed

- `restart_service`, `stop_service`, `compose_pull`, `compose_up` and `compose_down` now
  require `confirm=true`.
- A skipped known_hosts entry is reported in one aggregated warning per file instead of one
  warning per line.
- `get_service_status`, `get_container_health`, `get_service_logs`, `search_service_logs`,
  `start_service`, `restart_service` and `stop_service` now resolve compose projects to
  all of their containers and label the output per container.
- `disk-health-mcp` builds every host command from a typed operation catalog instead of
  concatenating command strings. The ZFS and RAID checks run separate argv operations
  rather than shell chains.
- `SecurityValidator.is_command_safe()` is now a strict argv allowlist. Unknown executables,
  shell operators and hand-built command strings are rejected; the permissive fall-through
  is gone. `security.allow_generic_commands` is accepted but has no effect.
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

### Fixed

- `disk-health-mcp` no longer fabricates a `100/100` healthy report when InfluxDB and the
  `smartctl` fallback both fail; command failures and unusable text output are rejected.
- NVMe devices are normalized from kernel names (`nvme0n1`) to Telegraf tags (`nvme0`) for
  InfluxDB lookups.
- Host-tool fallbacks use absolute `/usr/sbin/smartctl` and `/usr/sbin/nvme` paths, so
  non-interactive SSH sessions no longer fail with `command not found`.
- `get_service_file` no longer rejects `.env` files. Dotenv contents are returned with
  their values masked (`KEY=***`), while private keys, credential stores and secret-named
  paths are still refused with an explicit sensitive-file error.
- The `query_prometheus_disk` documentation no longer implies that Prometheus or
  `node_exporter` is required for disk health; the Telegraf/InfluxDB path is documented as
  the primary SMART source.
- Sensitive-file matching is per path component and extension instead of a substring of
  the whole path, so `monkey.txt` and `tokenizer.json` are readable. The invalid-path error
  no longer claims a valid path is outside the service directory.
- Service file paths are built lexically with `PurePosixPath` instead of resolving them on
  the MCP host. A local `/srv` symlink can no longer change the remote path; the executor's
  target-side `realpath` check remains authoritative.
- Direct SMART access keeps the global `sudo` block and now returns clear permission errors;
  documentation recommends block-device access for the executor user and InfluxDB as the
  preferred source.
- Raised the `disk-health-mcp` coverage gate from 55% to 65%.
- Unhealthy containers are visible: `docker inspect` reports health fields and the new
  `get_container_health` tool returns the failing probe output.
- Compose projects no longer require a container with the same name as the `/srv`
  directory (`immich` now resolves to `immich-server`, `immich-postgres`, ...).
- `get_service_status` reports "Container is not running; resource usage is unavailable"
  for stopped containers instead of Docker's zeroed `0B / 0B` statistics.
- Disk-health tools ignore Telegraf standby rows (`exit_status != 0`) that have no
  `health_ok` or temperature. A sleeping disk now produces an explicit "no recent valid
  sample" error instead of `Unknown` / `0°C` / `0 hours`. The InfluxDB lookback is 24 hours
  instead of 10 minutes, covering a 5-minute poll plus sleep cycles.

## [0.2.0] - 2026-10-17

### Added

- Monorepo with a uv workspace: `apps/remote-server-mcp`, `apps/disk-health-mcp` and
  `packages/server-management-lib`, one lockfile and shared tooling.
- Local executor (`executor: local`) that runs validated argv vectors without a shell.
- SFTP-based file reads and listings, confined with remote `realpath` checks.
- Operation catalog for Docker commands, rendered with `shlex.join`.
- Output sanitization (ANSI/control characters) and a configurable 64 KiB cap.
- Opt-in JSONL audit log with secret redaction.
- MCP `ToolAnnotations` for read-only and destructive tools.
- CI workflows for Python 3.11-3.13, `py.typed` markers and coverage gates.
- Harness-agnostic documentation and examples for pi, Claude Code, Codex, Cursor and
  opencode.

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

### Fixed

- Removed the runtime SMART database self-rewrite that dropped `SEAGATE_COMPOSITE`.
- Fixed `docker stats` argument ordering.
- Validate NVMe devices before any database query.
- Removed the dead asyncssh ML-KEM patch and bounded `asyncssh<3`.
- Dropped the unused `pydantic` dependency.

### Removed

- Qwen Code and vLLM-specific configuration, docs and ignore files.
- Per-repository lockfiles, CI workflows and duplicated markdown tooling.

## [0.1.0] - 2026-04-14

- Initial `remote-server-mcp`, `disk-health-mcp` and `server-management-lib` releases.
