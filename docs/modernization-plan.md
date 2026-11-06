# Modernization and Remediation Plan

Single source of truth for the Server MCP suite. This document merges the former
modernization backlog, the live-deployment findings from the `catafalco` host, and the
architecture/security reviews. Point-in-time review records live in
[`docs/reviews/`](reviews/README.md); accepted findings are merged here and the snapshot is
frozen. The former `docs/next-phase-plan.md` handoff is merged here and removed. Earlier
snapshots remain in git history.

- **Status:** the releases are out. `v0.2.0` (signed, on `9901974`) and `v0.2.1` (signed, on
  `2a5de15`) are tags pushed to `origin`, and all three packages are published on PyPI at
  both versions; `uvx remote-server-mcp` and `uvx disk-health-mcp` install from the index.
  `0.2.0` folded the pre-release remediation into the first published version; `0.2.1` shipped
  the stale-SMART and short-credential-key fixes. `v0.2.1` was published by
  `.github/workflows/publish.yml` through PyPI trusted publishing with no stored token
  (run `39507146796`), so the steady-state release path is verified.
  **Current release:** `v0.5.0` (signed, 2026-11-03, on `0968abe`) ships the 3.8 Phase 2
  container runtime (image, Quadlet units, `deploy/install.sh`, token-file transport,
  `--check-config`), the InfluxDB schema tool and the redaction/dump-refusal fixes. Publish
  run `41553210132` uploaded all three packages in library→apps order, the image run
  `41553210242` published `ghcr.io/elmuz/server-mcp:v0.5.0` (index digest
  `sha256:1f6854eb5949445f80022bee5c55524e570a26c8c5b5e291c4365f610c968c0c`), and
  `uvx --no-cache` resolves `0.5.0` for both servers. 3.9 release channel parity is
  complete. The next in-repo work is the review hardening in 3.10 (R7/R8 next), then
  multi-target support (3.7). The author sandbox integration and the deployer/approval
  boundary are deployment work outside this repository. The remaining external prerequisites
  are the catafalco items in 3.5 and the host-side self-test privilege in 3.6.
- **Last updated:** 2026-11-06 (lands R6: installer unit refresh is separate from
  configuration replacement; earlier
  landed R3: bounded collection in the executors and HTTP clients; R1/R2: internal
  `mcp-egress` plus a default-deny policy proxy, and automated author/MCP isolation checks;
  triages the post-`0.5.0` review
  into 3.10, moves review records to `docs/reviews/`, and removes the
  `next-phase-plan.md` handoff. 2026-11-03:
  verified `0.5.0` release on both channels and closed 3.9. 2026-11-02: the 3.8 Phase 2
  container runtime, 3.9 and the corrected release order)
- **Plan retention:** this file remains the single backlog. Completed sections are kept as
  history because they carry live findings and verification evidence; extend the plan
  rather than replacing it with a second document.
- **Provenance:** every finding below was re-verified against `81733d2` before merging;
  findings already fixed are marked `[x]` and kept only as history.
- **Target deployment:** `catafalco` (Ubuntu home server/NAS; Docker services under `/srv`)
- **Legend:** `[ ]` todo, `[~]` in progress, `[x]` done, `[!]` blocked, `[?]` needs decision
- **Severity:** **P0** correctness/safety, **P1** capability/usability, **P2** polish

## 1. Context

Server MCP is a security-first proxy between an autonomous agent and a Linux host. Two MCP
servers (`remote-server-mcp`, `disk-health-mcp`) sit on top of a shared library
(`server-management-lib`). The suite is a uv workspace monorepo with one lockfile, one
pre-commit configuration and one CI workflow.

The design constraints are:

- No generic command execution; only a fixed, validated tool catalog.
- SSH by default, with host key verification; a shell-free local executor as an alternative.
- File access confined to the configured service directory, verified on the target.
- Read-only database access and bounded output.
- Harness-agnostic documentation and packaging.

The reference deployment matters because it exposes assumptions the unit tests cannot:

- 43 running containers and 28 directories under `/srv`; container names and service
  directories are not one-to-one.
- Telegraf runs as a **host systemd service**, not a container, and writes SMART data to
  InfluxDB v3 Core (`system-monitor`; measurements `smart_device`, `smart_attribute`).
- The server uses mergerFS + SnapRAID, not ZFS or mdadm.
- Prometheus was retired; there is no `node_exporter` and no `smartmon_*` metric family.
- InfluxDB is reachable over HTTPS through SWAG with a token; it is also bound to
  `127.0.0.1:8181` on the host.

## 2. Status snapshot

### 2.1 Completed in 0.2.0

#### Core security and correctness

- [x] MCP SDK 2.x (`mcp.server.mcpserver.MCPServer`), console entry points fixed.
- [x] Config resolution via `--config`, environment, XDG path and `./config.yaml`; fail fast
      with exit code 2 when no config exists.
- [x] Host key verification by default; unparseable legacy known_hosts entries skipped
      individually instead of disabling verification.
- [x] DHM no longer rewrites `smartdb.py` at runtime; `SEAGATE_COMPOSITE` restored.
- [x] `services_path` honored by every tool and the SSH executor.
- [x] `docker stats` argument order fixed; NVMe device validated before database access.
- [x] Operation catalog for Docker commands, rendered with `shlex.join`.
- [x] SFTP file reads/listings with remote `realpath` confinement.
- [x] Output sanitization (ANSI/control characters) and a 64 KiB cap per command/file/query.
- [x] Opt-in JSONL audit log with secret redaction.
- [x] `ToolAnnotations` on every tool (read-only, write or destructive).
- [x] Semantic SQL validation (`sqlparse`, single `SELECT`) and usable PromQL validation.
- [x] SMART parsing fixes (`smart_support`, `smart_status`, zero thresholds, device type).
- [x] Persistent SSH connection in DHM; dead asyncssh ML-KEM patch removed.
- [x] Unused `pydantic` dependency removed.

#### Structure, packaging and docs

- [x] uv workspace monorepo with imported history, one `uv.lock`, one pre-commit config,
      one CI workflow and shared ruff/ty configuration.
- [x] `py.typed` in all packages; coverage gates (90% / 60% / 65%).
- [x] Harness-agnostic README, `AGENTS.md`, `CLAUDE.md`, docs and examples for pi,
      Claude Code, Codex, Cursor and opencode.
- [x] `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/releasing.md`.
- [x] Qwen/vLLM artifacts and duplicated per-repo tooling removed.

### 2.2 Completed in the reference deployment

These are deployment fixes outside this repository. They are recorded so future MCP work is
not validated against a broken environment.

- [x] **InfluxDB UI 502.** The SWAG upstream used port 80 while
      `influxdata/influxdb3-ui` listens on 8080. Added `influxdb_ui_port: 8080` in the
      catafalco role, rendered the config and reloaded SWAG. The UI now returns 200.
- [x] **InfluxDB enabled in the live MCP configs.** Both `remote-server-mcp` and
      `disk-health-mcp` point at the SWAG HTTPS endpoint with `use_https: true` and
      `database: system-monitor`; the token lives in `.env` next to each config (mode 0600).
      Prometheus was retired from the host and is disabled in both configs.
- [x] **vLLM, OpenWebUI and Prometheus retired.** Roles, containers, directories, stale SWAG
      vhosts, the Grafana Prometheus datasource and the vLLM dashboard were removed;
      `/srv/openwebui` data was preserved intentionally.
- [x] **SMART polling reduced.** Telegraf now polls SMART every 5 minutes and disk usage
      every minute instead of every 10 seconds; `nocheck = "standby"` is unchanged.
- [x] **`hd_idle` typo fixed.** Removed a reference to an undefined variable.
- [x] **Deluge healthcheck fixed.** The image grepped for an `openvpn|wg` process, but kernel
      WireGuard has no daemon. The override checks `wg show` and the Deluge web UI; the
      container now reports healthy.

Operational note: running MCP server processes still hold the old config. Restart the MCP
client/session before re-validating live behavior.

## 3. Open work

### 3.1 P0 — correctness and safety

All items in this subsection block the next tag; they are correctness or confinement bugs,
not polish.

#### P0-1 `get_disk_health` fabricates a healthy report when data is unavailable

- [x] **Fix and test.** `apps/disk-health-mcp/src/disk_health_mcp/server.py`
      (`get_disk_health`) returns a full report with `Health Score: 100/100`,
      `Power-On Hours: 0`, `Temperature: 0°C` and `✅ No issues detected` when both data
      sources are unavailable.
- **Root cause:** `_run_command` only prefixes `❌` on executor exceptions. A
  command-not-found produces `zsh:1: command not found: smartctl` plus
  `⚠️ Exit code: 127`. That string is not `❌`, so it is treated as success: `json.loads`
  fails, the text fallback (`smartctl -a`) also fails, and `parse_smart_text()` returns an
  empty `SmartDevice`. `format_smart_summary()` in `smart_parser.py` renders empty fields as
  zeros and prints `✅ No issues detected` when no attributes are flagged.
- **Repro (live):** `get_disk_health("sda")` on a host without `smartctl` on `PATH`.
- **Required behaviour:** return an explicit error ("no SMART data available; InfluxDB
  disabled and smartctl unavailable/failed") and never render a health score without a data
  source.
- **Implementation sketch:**
  - Treat `⚠️ Exit code:` and `command not found` as failures before JSON parsing.
  - Make `parse_smart_text()` fail (return `None`) when it finds no device/health/attribute
    data; make `format_smart_summary()` refuse empty devices.
  - Prefer InfluxDB; only fall back to `smartctl` when a usable response is parsed.
- **Tests:** add cases for exit-code text, empty text, and JSON parse failure asserting an
  error string and the absence of `100/100` / `No issues detected`.
- **Done:** command failures are detected before parsing;
  `parse_smart_text()` returns `None` for unusable text; `format_smart_summary()` refuses
  empty devices; regression tests cover the error paths.

#### P0-2 NVMe device names do not match InfluxDB tag values

- [x] **Fix and test.** `list_disks` returns `nvme0n1` / `nvme1n1`, but Telegraf writes
      `device=nvme0` / `device=nvme1` (namespace-less). `_get_influxdb_latest_device` and
      `_get_influxdb_latest_attributes` use exact equality (`WHERE device = 'nvme0n1'`), so
      they never match and silently fall through to the broken smartctl path from P0-1.
      `get_nvme_health` already strips the `n1` suffix; `get_disk_health` and
      `get_smart_attributes` do not.
- **Repro (live):** InfluxDB `SELECT DISTINCT device ...` returns
      `sda,sdb,sdc,sdd,nvme0,nvme1`; `list_disks` returns `nvme0n1,nvme1n1`.
- **Options:** normalize `nvmeXnY` → `nvmeX` in the lookup, or match
      `device = '<base>' OR device LIKE '<base>%'`, or expose aliases in config.
- **Tests:** a lookup test that seeds `device=nvme0` and queries `nvme0n1`; cover both
      `get_disk_health` and `get_smart_attributes`.
- **Docs:** update the device-name section and the `get_smart_attributes("nvme0n1")` example
      in `docs/tools.md`.
- **Done:** both InfluxDB lookups normalize `nvmeXnY` to `nvmeX`; live
  `get_disk_health("nvme0n1")`, `get_smart_attributes("nvme0n1")` and
  `get_nvme_health("nvme0n1")` now return real InfluxDB data.
- **Superseded by P1-19:** the label normalization is now only the fallback. Samples are
  selected by `serial_no` first, because the Telegraf deployment publishes a static role
  label (`Cache1`, `Parity1`, ...) in the `device` tag instead of a kernel name.

#### P0-3 SMART fallback cannot work on a standard Ubuntu host

- [x] **Fix.** The fallback commands use bare `smartctl` / `nvme` (in `get_disk_health`,
      `get_smart_attributes`, `get_nvme_health`, `run_smart_test` and
      `_get_full_report_via_ssh`). Non-interactive SSH sessions do not include `/usr/sbin`
      in `PATH`, so the commands fail even when `smartmontools` is installed.
- [x] Use absolute paths (`/usr/sbin/smartctl`, `/usr/sbin/nvme`); they are already in
      `SAFE_COMMAND_PREFIXES` in `security.py`.
- [x] **Decide the `sudo` policy.** Keep the global `sudo` block: the MCP requires the
      executor user to have block-device access (for example the `disk` group), and
      InfluxDB remains the preferred source. Documentation and error hints now match this
      policy.
- **Acceptance:** `get_smart_attributes("sda")` either returns data or a clear
      permission/availability error, never a command-not-found.
- **Done:** absolute paths are used for every host-tool fallback. Live
  verification reaches `/usr/sbin/smartctl` and `/usr/sbin/nvme`, but the executor user
  currently gets `Permission denied`; the tools now report that clearly instead of
  fabricating health data or claiming the command is missing.

#### P0-4 `get_service_status` cannot report container health

- [x] **Fix and test.** `INSPECT_FORMAT` in
      `apps/remote-server-mcp/src/remote_server_mcp/operations.py` omits `.State.Health`, so
      an unhealthy container looks healthy. Example: `deluge` has been `unhealthy` for days
      while `get_service_status("deluge")` shows `State: running`.
- [x] Add `Health`, `FailingStreak`, and `ExitCode` to the inspect format.
- [x] Add a `get_container_health` tool that returns `State.Health.Log` (last N entries)
      with a read-only annotation, or expose it through `get_service_status` as an extra
      section.
- **Acceptance:** `get_service_status("deluge")` shows `Health: unhealthy`; the failing
  probe output is retrievable.
- **Done:** `get_service_status` reports the health fields and
  `get_container_health` returns the last N probe results. Tests cover health, no-healthcheck,
  Docker-error and entry-clamping paths.

#### P0-5 Secure the command policy fall-through

- [x] **Fix and test.** `packages/server-management-lib/src/server_management_lib/security.py`
      has a permissive blacklist: `is_command_safe` falls through to `return True` for
      unknown commands, and `security.allow_generic_commands` is never read. RSM is
      protected by its operation catalog; DHM still relies on this policy.
- [x] Choose one and enforce it:
  - Convert DHM to an operation catalog (preferred; it also makes command construction
    consistent with RSM) and delete the fall-through.
  - Or make the policy explicitly allowlist-based for every executable.
- [x] Add tests that unknown commands are rejected and that
      `security.allow_generic_commands` cannot enable arbitrary execution.
- **Done:** `disk-health-mcp` now uses `operations.py` with the shared
  `Operation` template, and `is_command_safe()` rejects anything outside an exact argv
  allowlist. Shell syntax, unknown executables and `docker run`/`docker exec` are rejected;
  `allow_generic_commands` has no effect. Tests assert both catalogs pass the policy and that
  unknown commands fail.

#### P0-6 `EXECUTOR` and `CONTAINER_RUNTIME` environment overrides corrupt the config

- [x] **Fix and test.** `config.py` stores `executor` and `container_runtime` as top-level
      scalars, but `ENV_OVERRIDES` maps them as nested `(section, key)` pairs. With
      `EXECUTOR=local`, `_apply_env_overrides()` replaces the scalar with
      `{"executor": "local"}`; `create_executor()` then raises
      `ValueError: Unknown executor "{'executor': 'local'}"`. `CONTAINER_RUNTIME=podman`
      is silently downgraded to `docker` by `SecurityValidator`.
- **Required behaviour:** `EXECUTOR=local` selects the local executor and
      `CONTAINER_RUNTIME=podman` selects Podman end-to-end.
- **Implementation sketch:** allow a top-level entry in `ENV_OVERRIDES` (for example a
      `section=None` sentinel) and set `config[key]` directly in `_apply_env_overrides()`.
- **Tests:** `load_config(env={"EXECUTOR": "local", "CONTAINER_RUNTIME": "podman"})`
      through `create_executor()` and `SecurityValidator`; update the `config_schema()` test
      that currently asserts the broken nested shape.
- **Done:** `ENV_OVERRIDES` now marks those two keys as top-level (`section=None`), and
  `_apply_env_overrides()` writes `config[key]` directly. Environment overrides are also
  applied when no config file exists (previously they were silently skipped on that path).
  `config_schema()` keeps the existing `section` display by mapping the top-level key to
  itself. Tests cover a missing config file, the executor/security factories, and the schema
  output.

#### P0-7 SSH SFTP confinement compares a realpath against a raw base

- [x] **Fix and test.** `LocalExecutor.read_remote_file`/`list_remote_dir` resolve both
      `path` and `allowed_base`, but `SSHManager` resolves only `path` and compares the
      result to the raw `allowed_base` string. A symlinked `/srv` (for example
      `/srv -> /mnt/storage/srv`) therefore breaks every read and listing, and a canonical
      target is compared against an un-canonicalized base, violating
      [docs/security-model.md](security-model.md) §5.
- **Implementation:** resolve `real_base = str(await sftp.realpath(allowed_base))` in both
      `read_remote_file` and `list_remote_dir` before `is_within()`.
- **Tests:** legacy `test_ssh_manager.py` coverage for a symlinked base that must succeed and
      for a symlink escape that must be rejected.
- **Done:** `read_remote_file` and `list_remote_dir` resolve `allowed_base` with the remote
  `sftp.realpath` before `is_within()`. Tests cover a symlinked `/srv` base and a symlink
  escape.

#### P0-8 Non-regular files in a service directory can hang the server

- [x] **Fix and test.** Neither `SSHManager.read_remote_file` nor
      `LocalExecutor.read_remote_file` checks `stat.S_ISREG` before reading. A FIFO or device
      node inside `/srv/<service>/` blocks `get_service_file` indefinitely; the local
      executor additionally performs blocking file I/O on the event loop.
- **Implementation:** `stat.S_ISREG(attrs.permissions)` in `SSHManager` and
      `stat.S_ISREG(real_path.stat().st_mode)` in `LocalExecutor`; raise
      `RemoteFileError("Not a regular file")`. Wrap SFTP file operations in
      `asyncio.wait_for(..., timeout=...)`; move local file I/O to a thread.
- **Tests:** `os.mkfifo` under `tmp_path` for both executors, asserting a fast, explicit
      error instead of a hang.
- **Done:** both executors stat the resolved path and require `stat.S_ISREG` before opening.
  SFTP `realpath`/`stat`/`read`/`readdir` are bounded by a 30 s timeout, and local reads run
  through `asyncio.to_thread` so blocking I/O and special files cannot stall the event loop.
  Tests cover a FIFO on both executors.

### 3.2 P1 — capability, usability and library hardening

The P1-12 through P1-17 items are new findings from the 2026-10-19 review. They harden
controls that already exist (SQL validation, argv policy, redaction, rate limiting, audit)
rather than adding new surface.

#### P1-1 The service model assumes `/srv/<dir> == container name`

- [x] **Fix.** 19 of 43 running containers are unreachable because the tool requires a
      matching `/srv/<service>` directory *and* uses that name for `docker inspect/logs/stats`.
      Examples: `immich-server`, `immich-postgres`, `dawarich-sidekiq`, `cypht-db`,
      `influxdb-explorer`, `socket-proxy`, `watchtower`, `wud`.
- **Repro:** `get_service_status("immich")` → `error: no such object: immich`;
  `get_service_status("immich-server")` → `❌ Service 'immich-server' does not exist in /srv/`.
- [x] Add `list_containers` (`docker ps -a`) so stopped/crashed containers are discoverable.
      Today a container that never started is invisible (`vllm` is a live example).
- [x] Accept either a service directory or a container name. When a directory is given,
      resolve its containers via the `com.docker.compose.project` label; otherwise use the
      container name directly.
- [x] Keep the security boundary: still require the target to belong to a directory under
      `services_path` (or an explicit container allowlist via
      `security.allowed_containers`), and never accept arbitrary `docker` arguments.
- **Tests:** resolve `immich` → its containers; reject `../../etc`; parse `docker ps -a`.
- **Docs:** replace the "container is assumed to have the same name" statement in
  `docs/tools.md` with the real resolution rules.
- **Done:** `resolution.py` resolves directories through the compose project
  label (with a same-name fallback for legacy deployments) and accepts container names
  that map to a service directory or are allowlisted. `list_containers` reports stopped and
  crashed containers, and the container tools label multi-container output per container.
  Tests cover project resolution, container-name resolution, the allowlist, unknown and
  traversal targets, `docker ps -a` parsing and `list_containers` errors.

#### P1-2 No host-service or NAS-aware diagnostics

- [x] **Add tools.** `remote-server-mcp` now exposes read-only `get_host_service_status`
      and `get_host_service_logs`, backed by `systemctl status` / `journalctl -u`. Unit
      names are validated by `SecurityValidator.validate_host_unit()` against the new
      `security.host_units` allowlist (default: `telegraf`, `smartd`, `docker`, `snapraid`,
      `mergerfs`, `smbd`); arbitrary units are rejected before execution.
- [x] `disk-health-mcp` now exposes `get_snapraid_status` (`snapraid status`) and
      `get_mount_status` (`findmnt` plus `df`), gated by `host.enabled`.
- [x] `get_zfs_status`/`get_raid_status` are kept. `docs/tools.md` maps ZFS, mdadm and
      mergerFS + SnapRAID to the matching tools; `README.md` and `docs/architecture.md`
      state that host infrastructure services are in scope through the allowlist.
- **Acceptance:** `get_host_service_logs("telegraf", lines=200)` renders
  `journalctl -u telegraf -n 200 ...`; arbitrary unit names are rejected; SnapRAID and
  mergerFS state are reported. Covered by app and library tests.

#### P1-3 `.env` files are blocked, with a misleading error

- [x] **Fix.** `SENSITIVE_FILE_PATTERNS` in `security.py` substring-matches `.env`,
      `secret`, `token`, `password`, `.key`, etc. against the path.
      `get_service_file("cypht", ".env")` returns
      `❌ Invalid file path: .env / File must be within /srv/cypht/`, which is both wrong and
      unhelpful. This blocks the primary way to debug compose stacks whose `compose.yml` only
      contains `${VARS}`.
- [x] Prefer reading and **redacting values** (`KEY=***`) over rejecting the file; if full
      rejection is kept, return a specific "blocked by sensitive-file policy" error.
- [x] Remove substring false positives (`monkey.txt` matching `.key`, `tokenizer.json`
      matching `token`); match path components / extensions instead.
- **Tests:** `.env` read returns redacted output; `../../etc/shadow` is still blocked; add a
  regression test for the misleading message.
- **Done:** the substring list is replaced by `BLOCKED_PATH_COMPONENTS`,
  `BLOCKED_PATH_SUFFIXES` and the `REDACTED_PATH_*` sets, matched per path component and
  extension. `SecurityValidator.check_service_file_path()` returns a `ServiceFilePath` with
  `ALLOW`, `REDACT`, `BLOCKED_INVALID` or `BLOCKED_SENSITIVE`, so `get_service_file` can
  distinguish a policy refusal from a bad path. `.env`/`.env.*`/`*.env` reads are returned
  with `KEY=***` via `redact_env_content()`; keys, comments and blank lines are preserved.
  Tests cover redaction, the false positives, policy vs invalid errors and the
  `../../etc/shadow` regression.

#### P1-4 `get_server_health` is NAS-blind

- [x] **Fix.** `DISK_USAGE` in `operations.py` ran `df -h /srv`, which is on the root
      filesystem. The 48 TB mergerFS pool (`/mnt/storage`) and `/mnt/data*`, `/mnt/parity*`
      were never shown.
- [x] Add configurable `health.disk_paths` (default `["/"]`) or report all local mounts and
      deduplicate. Include unhealthy containers in the summary.
- **Acceptance:** the tool reports the mergerFS pool and root usage separately.
- **Done:** `SecurityValidator.health_disk_paths` reads
  `health.disk_paths`, validates each entry as a shell-safe absolute path, normalises it
  with `PurePosixPath` and deduplicates without reordering. `get_server_health` renders
  one `df -h <path>` block per mount (default `["/"]`), so `/` and `/mnt/storage` are
  reported separately, and adds an `=== Unhealthy Containers ===` section backed by
  `docker ps -a --filter health=unhealthy`. Tests cover ordering, normalisation,
  deduplication, invalid/relative/traversal entries, the root fallback, the per-path
  commands and the unhealthy section.

#### P1-5 Log and search tools are limited for incident work

- [x] Add `--since`/`--until` and timestamps to `docker logs`; `--tail N` alone makes time
      correlation hard.
- [x] Let `get_service_logs`/`search_service_logs` target a specific container in a compose
      project (depends on P1-1).
- [x] `search_service_logs` sanitizes the pattern and then matches the **sanitized** string,
      so characters such as `!`, `#`, `~`, quotes silently change the search. Filter with the
      exact pattern (matching happens locally, so no shell escaping is needed) and validate
      length/control characters only.
- [x] Show `docker stats` as "not running" instead of `0B / 0B` for stopped containers.
- **Done:** `docker logs` always renders `--timestamps`; both log tools accept
  optional `since`/`until` and `container` arguments. `SecurityValidator.validate_log_time()`
  accepts only RFC3339 timestamps, dates or relative durations, so a value cannot become a
  Docker option. `sanitize_search_pattern()` is replaced by `validate_search_pattern()`,
  which preserves the exact pattern and rejects only empty, overlong or control-character
  input. `get_service_status` replaces zeroed stats for a stopped container with an explicit
  "not running" message. Tests cover exact punctuation matching, time-filter rendering and
  validation, per-container targeting and stopped-container stats.

#### P1-6 Standby rows are formatted as health data

- [x] **Fix and test.** With `nocheck=standby`, Telegraf emits a `smart_device` row every
      interval with `exit_status=2` and no `health_ok`/`temp_c`. `get_disk_health` currently
      treats that row as real data and renders `Unknown`/0°C/0 hours.
- [x] Filter `exit_status != 0` and use the last valid sample (look back 24h), reporting its
      age. The hardcoded 10-minute lookback is also too narrow for a 5-minute poll plus
      sleeping disks.
- **Tests:** a standby-only series returns an explicit "no recent valid sample" message, not
  zeroed health fields.
- **Done:** `smart_device` and `smart_attribute` lookups require
  `exit_status = 0` and use a 24-hour lookback. Health reports and the disk overview show the
  sample timestamp and age, and missing fields are omitted instead of rendered as zero. With
  InfluxDB only and a standby-only series, `get_disk_health` returns an explicit no-valid-
  sample error. Tests cover the standby row shape, the filtered queries, age formatting,
  missing fields and the InfluxDB-only path.

#### P1-7 Metric endpoints: HTTPS proxy and loopback SSH tunnel

- [x] **Live configs.** InfluxDB is enabled in both configs with the SWAG HTTPS endpoint,
      `use_https: true`, `database: system-monitor`, and the token from `.env`. Prometheus is
      disabled because the service was retired from the host.
- [x] **Fix the sample configs and docs.** `apps/disk-health-mcp/.env.example` uses a
      generic database name and both `.env.example` files show `use_https`. The sample
      configs and `docs/configuration.md` now use non-loopback HTTPS examples and explain
      that `host` is a hostname/IP, never a URL.
- [x] Document both supported modes: (a) HTTPS reverse proxy (SWAG) + token, (b) an
      explicit local SSH tunnel for loopback-only deployments.
- [x] Optional `ssh_tunnel` config block. `tunnel.py` opens a loopback-only local forward
      over the configured SSH connection at server startup, rewrites the section's
      `host`/`port` to the endpoint, and closes it on shutdown. The destination and remote
      port are operator configuration; the model cannot influence them.
- [x] Clarify that `query_prometheus_disk`'s `smartmon_*` examples require
      `node_exporter` (smartmon collector). Prometheus is optional and is not a
      prerequisite for disk health; Telegraf -> InfluxDB remains the SMART source.
- **Done:** `.env.example` files, both `config.example.yaml` files,
  `README.md`, the app READMEs, `docs/configuration.md`, `docs/tools.md`,
  `docs/architecture.md`, `docs/security-model.md` and `CHANGELOG.md` describe the two
  endpoint modes. Unit tests cover tunnel validation, startup/open failure cleanup and
  shutdown; no live tunnel was available on the reference deployment because InfluxDB is
  reached over SWAG.
- **Acceptance:** with a token and the SWAG URL, `query_influxdb` returns data on this
  deployment (verified at the library level; re-verify through the MCP tools after
  restarting the server processes). `query_prometheus`/`get_prometheus_targets` report
  "not enabled" while Prometheus is retired.

#### P1-8 Local path resolution in `validate_service_file_path`

- [x] **Fix.** `security.py` still called `Path.resolve()` on the MCP host for a remote path.
      The SFTP layer performs the authoritative remote `realpath` check, but a local `/srv`
      symlink could still change or break the constructed path. The remote path is now built
      lexically with `PurePosixPath` and resolution is left to the executor.
- **Tests:** the returned path is lexical (a symlink below `services_path` on the MCP host is
  not followed) and traversal is still rejected.
- **Done:** `check_service_file_path()` joins the service base and the relative
  path with `PurePosixPath`, checks the lexical result is still below the base, and no longer
  imports or calls `Path.resolve()`. The SSH executor still verifies the remote `realpath`
  before reading; the local executor does the equivalent on the target filesystem.

#### P1-9 Single response cap for composite/list results

- [x] **Fix.** `execute_safe_command` caps each command, but `list_service_files`,
      `get_service_status`, `get_full_disk_report` and directory listings can concatenate
      multiple capped outputs or return a very large listing.
- [x] Apply a final `sanitize_output` cap to the complete tool response.
- **Tests:** a composite response larger than `output.max_bytes` is truncated exactly once
  with the standard marker.
- **Done:** both MCP servers apply a final `sanitize_output` cap (`tool output`)
  to composite and listing responses, including service files, server health, host-service
  logs, ZFS/RAID/SnapRAID/mount summaries and the full disk report. `sanitize_output()` is
  idempotent at the same limit, so a nested cap cannot append a second truncation marker.
  Tests cover oversized directory listings and composite command output.

#### P1-10 Audit HTTP queries

- [x] **Fix.** The audit log covered commands, blocked operations and file access. InfluxDB
      and Prometheus queries were not recorded. `InfluxDBClient` and `PrometheusClient` now
      accept an `AuditLogger` and log query metadata (length/SHA-256, database, status,
      duration) without storing query text that may contain secrets.
- **Tests:** enabled audit log records an InfluxDB and a Prometheus query with redacted
  metadata.
- **Done:** `create_audit_logger()` builds the logger from the shared `audit`
  config section. Both servers pass it to their HTTP clients. `influxdb_query` and
  `prometheus_query` records contain `query_length`, `query_sha256`, `status`,
  `duration_ms` and (for InfluxDB) `database`; connection errors and timeouts are recorded
  by exception type. The query text is never written to the log.

#### P1-11 `run_smart_test` pre-flight

- [x] **Fix.** `run_smart_test` is not covered by a host-availability test. Pre-flight
      `smartctl` and return a clear error when it is unavailable.
- [x] Do not run tests on disks that may be spun down without an explicit user action.
- **Tests:** mock an unavailable `smartctl` and assert the error, with no write operation
  attempted.
- **Done:** `run_smart_test` runs `/usr/sbin/smartctl --version` first. That
  pre-flight never opens a block device, so it cannot spin up a sleeping disk. If the
  version check fails, the tool returns "SMART self-tests unavailable ... No test was
  started" and never renders the write command. The test itself uses `-n standby`, so
  smartctl skips a sleeping disk (exit status 2) instead of waking it; the tool reports that
  no self-test was started and asks the operator to wake the disk explicitly and retry.
  Tests cover both the missing-tool and standby paths.
- **Superseded by 3.6:** the version-only probe could not distinguish a permission failure
  from standby, because smartctl exits 2 for both. The probe is now `smartctl -i`
  (`-n standby` for ATA), NVMe omits the flag, and the failure reason is published.

#### P1-12 InfluxDB LIMIT handling and query pass-through are bypassable

- [x] **Fix and test.** `_ensure_limit()` returned the query unchanged whenever
      `\blimit\b` appeared anywhere, including string literals and identifiers, and never
      clamped an existing `LIMIT 10000000`. `validate_influxdb_query()` did not reject `--`
      or `/*` comments although the tool error text claimed it did. Both
      `query_influxdb_disk` and `query_prometheus_disk` validated into `validated` but passed
      the original `query` to the client.
- **Done:** `_ensure_limit()` walks the top-level `sqlparse` tokens, ignores a
      `LIMIT` inside a string literal, identifier or nested subquery, clamps an outermost
      numeric `LIMIT` to `query_limit` and appends one when it is missing.
      `validate_influxdb_query()` rejects SQL comments. Both disk-health query tools pass
      `validated` to the client. Tests cover literals, subqueries, an oversized `LIMIT`, a
      column named `limit`, comment rejection and the exact query sent to the mock client.

#### P1-13 Command policy validates only a 1–2 token prefix

- [x] **Fix and test.** `is_command_safe()` compared only `argv[:len(prefix)]`, so
      `docker inspect --format '{{json .Config.Env}}' app`,
      `ls -1 /etc/ssl/private` or `/usr/sbin/smartctl -s off /dev/sda` passed the policy.
      `SHELL_METACHARACTERS` also did not reject `\x00`–`\x1f` or `\x7f` inside a quoted
      token.
- **Done:** every token is rejected if it contains a control character, and
      `_argument_shape_safe()` validates the complete vector for the container runtimes,
      `systemctl`, `journalctl`, `smartctl`, `nvme`, `ls`, `test`, `df`, `lsblk`, `zpool`,
      `zfs`, `mdadm`, `cat`, `snapraid` and `findmnt`. Docker inspect/stats formats that
      reference `.Config`, `.Args`, `.Mounts`, `.HostConfig` or `.NetworkSettings` are
      rejected. Catalog output formats now use Docker's `\\n`/`\\t` escapes instead of
      literal control characters. Tests cover acceptance and rejection per family plus a
      control-character regression.

#### P1-14 `get_full_disk_report` trusts `lsblk` device names

- [x] **Fix and test.** `_get_full_report_via_ssh()` passed `dev.get("name")` straight to
      `SMART_JSON.render(device=name)` without `validate_device_name()`. `loop`, `rom` and
      malformed entries reached `smartctl` because the policy only checked the command
      prefix.
- [x] Widen `DEVICE_NAME_PATTERN` to `sd[a-z]{1,2}` so `sdaa`..`sdzz` work on hosts with
      more than 26 SATA/SAS disks, and document partition versus whole-disk handling.
- **Done:** `_disk_devices()` keeps only `type: disk` rows whose name passes
      `validate_device_name()`; the overview and health loop both use it. The device pattern
      now accepts two-letter SATA/SAS names. Tests feed `loop0`, `sr0`, `sdaa`, `zram0`, a
      partition and a traversal-shaped name, and assert that only `/dev/sdaa` reaches
      `smartctl`. `docs/tools.md` documents the whole-disk rule.

#### P1-15 Rate limiting and bearer handling are inconsistent

- [x] **Fix and test.** `disk-health-mcp` never called `create_rate_limiter(config)`, so the
      `WRITE_ACTION` `run_smart_test` was unthrottled. `remote-server-mcp.start_service` was
      a write action without `_rate_limited("start_service")`. `BearerTokenMiddleware`
      compared the raw `Authorization` value, so lowercase `bearer <token>` was rejected
      even though RFC 9110 auth schemes are case-insensitive.
- **Done:** `disk-health-mcp` creates the limiter at import and in
      `apply_config()`, and `run_smart_test` checks it before the pre-flight.
      `start_service` is guarded. The bearer middleware splits the scheme and credential,
      compares the scheme case-insensitively and keeps `hmac.compare_digest` on the token.
      Tests cover limiter rejection without a second command and lowercase bearer
      acceptance.

#### P1-16 Audit log permissions and coverage gaps

- [x] **Fix and test.** `AuditLogger` created directories with the default umask and
      `audit.jsonl` as `0o644` instead of `0o700`/`0o600`. `PrometheusClient.get_targets()`
      did not audit, unlike `query()`. Policy refusals that happened before the executor
      (sensitive file, host unit, query, rate limit) were never logged.
- **Done:** new audit directories are created with mode `0700` and the log
      file is `0600`; an existing file is tightened on the next write. `get_targets()`
      emits `prometheus_targets`, and both servers log `file_blocked_sensitive`,
      `host_unit_blocked`, `query_blocked` and `rate_limited`. Tests assert POSIX modes,
      the targets record and one record per refusal.

#### P1-17 Secret redaction stops at `.env`

- [x] **Fix and test.** Only `.env`-classified files were redacted. Compose files with
      inline `environment:` secrets (`POSTGRES_PASSWORD: ...`, `- TOKEN=...`) and common
      `*.yml`/`*.json`/`*.toml`/`*.ini`/`*.conf` service files were returned verbatim;
      `systemctl status --full` could also print tokens in command lines and journal tails.
      `test_security_bypass.py` documented this gap.
- **Done:** `redact_secrets()` masks YAML/JSON/INI/dotenv assignments,
      inline `KEY=value`, CLI flags, bearer headers, JWT shapes and URL passwords while
      preserving keys, comments and structure. `get_service_file` applies it to non-`.env`
      service files, and `get_host_service_status`/`get_host_service_logs` apply it to host
      output. The `BLOCKED_*` policy still refuses real credential stores. Tests cover a
      compose password, JSON token field, bearer/JWT values, `systemctl` command lines and
      URL credentials.
- **Live finding (fixed):** the key matcher was a substring search over a
      fixed word list, so short spellings leaked. An INI file such as
      `[section]` / `pass = XXXX` was returned verbatim, and so were `db_pass`, `pw`,
      `passphrase` and `credential`-only keys. Keys are now normalized and split on
      separators, and each word is matched as an exact name or suffix, so `pass`, `pw`,
      `db_pass`, `dbpass`, `apiKey` and `POSTGRES_PASSWORD` are masked while `tokenizer`
      and `keyboard` stay readable. Tests cover the reported INI shape end to end through
      `get_service_file` and the key spellings at the redactor level.

#### P1-18 Overview failed polls follow the mutable `device` label

- [x] **Fix and test (T-20).** The Telegraf deployment now stamps `serial_no` on every
      poll, including standby rows, but `get_full_disk_report` still built its failure
      evidence from `_influxdb_recent_failures_by_device()`, which grouped rows by the
      `device` tag. After a label rewrite, failures written under the old label were no
      longer attached to the disk's newest valid sample (keyed by serial), so a sleeping
      disk could lose the explanation for its stale sample.
- **Done:** `_influxdb_recent_failures_by_disk()` returns a `_FailedPolls`
      index: rows with `serial_no` are keyed by serial, and only rows without one fall back
      to the label. `_influxdb_latest_device_rows()` attaches evidence with
      `for_disk(serial, label)`, and the no-valid-sample path groups by label for display.
      Tests cover a standby row written under the old label, a legacy row without a serial
      and the label fallback in the index.

#### P1-19 Disks are identified by serial, not by the mutable `device` tag

- [x] **Fix and test.** The Telegraf deployment changed the `device` tag from a kernel name
      (`sda`) to a role label (`Parity1`) and later rewrote that label, so a disk report
      keyed by the tag could follow the wrong row or lose its history. `get_disk_health`,
      `get_smart_attributes`, `get_nvme_health` and `get_full_disk_report` now resolve the
      live device with `lsblk` and query `serial_no = '<serial>'`; the label is only a
      fallback when no live serial can be resolved.
- [x] Stored serial/model/time and the live `lsblk` identity are echoed when available. A
      serial mismatch names both disks and refuses to call the requested device healthy;
      a sample older than two 5-minute poll intervals is marked stale instead of green.
- [x] The overview partitions by `serial_no`, so one physical disk stays one line across a
      tag rewrite or a reboot that re-enumerates controllers. Failed polls are keyed by
      serial (P1-18) with the label as a fallback for legacy rows. Structured output adds
      `devices`, `labels` and `serials`, aligned by index.
- **Tests:** the InfluxDB query selects by serial, a label-only legacy row still works, a
      rewritten label keeps one line per disk, a stale sample is not healthy, and a serial
      mismatch is reported without a `PASSED`/100 result.
- **Docs:** `docs/tools.md` explains the `Data1 (/dev/sda)` rendering, the whole-disk rule
      and that a `devices` value can always be passed back to `get_disk_health`.

#### P1-20 One canonical device vocabulary (`catafalco` T-11)

- [x] **Fix and test.** `disk-health-mcp` accepted only canonical kernel names, so the
      `nvmeX` spelling used by Telegraf/smartd/tool output, `/dev/<name>`, by-id paths,
      serials and role labels were rejected even though the serial is the documented disk
      identity. Every device-taking tool now uses `server_management_lib.normalize_device_name()`
      plus a serial-first resolver, and only the resolved canonical name (still gated by
      `DEVICE_NAME_PATTERN`/`validate_device_name`) is rendered into a command. This links
      back to the `catafalco` backlog item T-11; check it off there after `0.4.0` is
      deployed and the MCP process has been reloaded.
- [x] `get_nvme_health` detects the protocol from `lsblk` `tran`, the stored sample's field
      set or `smartctl -j`, and refuses a SATA disk (with the detected type named) instead
      of returning the identical generic SMART report `get_disk_health` produces.
- **Tests:** `normalize_device_name` accepts/rejects matrix in
      `packages/server-management-lib/tests/test_security.py`; per-spelling resolution,
      `nvme0`/`nvme0n1` attribute equivalence, the `run_smart_test` argv, and the
      non-NVMe rejection paths (lsblk and InfluxDB-only) in
      `apps/disk-health-mcp/tests/test_server.py`.
- **Docs:** `docs/tools.md` (device vocabulary and NVMe protocol check),
      `docs/security-model.md` (input vocabulary vs command boundary) and CHANGELOG
      `0.4.0`.

### 3.3 P2 — modernization and polish

P2-10 through P2-14 are complete; they were performance/consistency work and never
blocked the release.

#### P2-1 Structured tool outputs

- [x] **Fix.** Tools return formatted strings; clients cannot consume typed results. Return
      pydantic models/dicts (and keep a readable text fallback) using `MCPServer` structured
      output.
- **Done:** `server-management-lib.responses` defines the `ToolResponse`
  pydantic envelope (`ok`, `tool`, `summary`, `text`, `data`) and a `make_structured_tool()`
  wrapper. Both servers register an MCP-facing wrapper with a `ToolResponse` output schema
  while the implementation functions keep returning readable strings for direct use and
  tests. Container lists, service status/logs, files, query rows and disk data populate
  `data`. Tests assert the schema on every tool and the structured payload for
  representative tools.

#### P2-2 Streamable HTTP transport

- [x] **Fix.** Only stdio is implemented. Add an opt-in `--transport streamable-http` path
      (loopback/token protected) for clients that cannot launch a process.
- **Done:** `transport.py` serves the Streamable HTTP app (default `/mcp`) and
  enforces two rules: a non-loopback bind requires a token, and a configured token must be
  presented as `Authorization: Bearer ...` on every HTTP request. Configuration lives in
  `transport.*` (`MCP_TRANSPORT`, `MCP_HTTP_HOST`, `MCP_HTTP_PORT`, `MCP_HTTP_PATH`,
  `MCP_HTTP_TOKEN`); CLI flags override host/port/path. Both servers exit with status 2 on
  an unsafe binding. Tests cover the policy, the ASGI middleware and the serving path.

#### P2-3 Container runtime adapter

- [x] **Fix.** `docker` is hardcoded in
      `apps/remote-server-mcp/src/remote_server_mcp/operations.py`. Add
      `container_runtime: docker|podman|nerdctl` and build operations from the selected
      runtime.
- **Done:** `build_container_catalog(runtime)` returns every container and
  Compose operation for the selected runtime; `SecurityValidator.container_runtime` rejects
  unknown values with a warning and falls back to Docker. The command allowlist covers
  Podman/nerdctl subcommands and the existing Docker ones. The resolver and every tool use
  the selected catalog; `apply_config()` rebuilds it. Tests render every operation for all
  three runtimes through the command policy.

#### P2-4 Compose deployment operations

- [x] **Fix.** There is no `compose up/down/pull/ps`. Add a small, explicit set of compose
      operations scoped to `services_path/<service>/`, with a dry-run or confirmation
      argument.
- **Done:** `compose_ps` is read-only; `compose_pull`, `compose_up` and
  `compose_down` run through `<runtime> compose --project-directory
  <services_path>/<service> <subcommand>` and require `confirm=true`. All four are added to
  the command policy with fixed subcommand arguments, a directory below `services_path`
  and no arbitrary flags. Tests cover the rendered commands, previews, failures and policy
  rejections.

#### P2-5 Rate limiting and destructive-action confirmation

- [x] **Fix.** `restart_service` and `stop_service` execute immediately. Add a `confirm`
      parameter or MCP elicitation, and a simple per-session rate limit.
- **Done:** `restart_service`, `stop_service`, `compose_pull`, `compose_up`
  and `compose_down` default to `confirm=false` and return the exact command preview without
  executing it. Confirmed calls pass a sliding-window `RateLimiter` (`rate_limit`, default
  10 calls per 60 s, per server process). Tests cover the preview path, execution, the
  limit and the disabled configuration.

#### P2-6 CI markdown enforcement

- [x] **Fix.** `.github/workflows/ci.yml` runs ruff, format, ty and pytest, but not
      `pymarkdown` or `check-md-links`. Add both steps (or run `pre-commit` in CI) so
      documentation checks are enforced remotely.
- **Done:** CI runs `pymarkdown -c .pymarkdown scan .` and
  `python scripts/check_md_links.py` after the test suites.

#### P2-7 Known_hosts summary logging

- [x] **Fix.** The loader logs up to three skipped entries plus a count. Aggregate skipped
      entries into one summary warning per file.
- **Done:** the loader logs a single warning with the skipped count, the first
  ten line numbers and the file name; host key verification remains enabled for every entry
  that parses. A test asserts one aggregated record for two skipped lines.

#### P2-8 MCP resources and resource templates

- [x] **Optional.** No MCP resources are exposed (`list_mcp_resources` is empty). Consider
      exposing the config schema and tool catalog as resources.
- **Done:** both servers expose `server-mcp://config/schema` (defaults and
  environment override names, credential values masked), `server-mcp://tools/catalog`
  (name, description, annotations and schemas) and a `server-mcp://tools/{name}` template.
  Reading a resource never executes a host command. Tests cover registration, content and
  unknown-tool handling.

#### P2-9 Community and packaging polish

- [x] Add `[project.urls]`, `classifiers`, `keywords` and `authors` to the package metadata.
- [x] Add `CODE_OF_CONDUCT.md`, issue templates, a pull-request template and `CODEOWNERS`.
- [x] Consider Python 3.14 in the CI matrix (currently 3.11–3.13; local verification already
      runs on 3.14).
- [x] Consider a short demo/screenshot section in the README once the repository is public.
- **Done:** all three publishable packages declare authors, URLs, keywords and
  classifiers; CI includes Python 3.14; the repository has a code of conduct, bug/feature
  issue forms, a PR template and `CODEOWNERS`; the README has a "See it work" section with
  representative response snippets.

#### P2-10 SSH connect race and tunnel reconnect

- [x] Add an `asyncio.Lock` around `SSHManager.connect()` so concurrent tool calls cannot
      race at startup or after a disconnect and leak connections.
- [x] `SSHTunnel` opens a static forward at startup with no reconnect. Re-open the forward
      when the SSH connection drops, or surface a clear "tunnel down" error instead of
      hanging queries.
- **Done:** `connect()` is serialized and re-checks `_connected` inside the
  lock, so concurrent calls share one connection. The tunnel monitors its SSH connection,
  re-opens the forward on the previously bound local port with exponential backoff, exposes
  `down`/`last_error` while reconnecting, and stops the monitor on shutdown.
- **Tests:** concurrent `connect()` calls produce one connection; a forced disconnect
  re-opens the forward on the same port and a failed reconnect is reported.

#### P2-11 HTTP session reuse and N+1 InfluxDB queries

- [x] `InfluxDBClient` and `PrometheusClient` create a new `aiohttp.ClientSession` per
      query. Reuse one session per client and close it on shutdown.
- [x] `get_full_disk_report()` issues `1 + N` sequential InfluxDB queries. Use one query (or
      concurrent queries over the shared session) to cut report latency.
- **Done:** each HTTP client owns one lazily created `ClientSession` and
  exposes `close()`; both servers cache one client per service and close the sessions on
  shutdown. The disk overview uses one window-function query to return the latest valid row
  per device instead of one query per disk.
- **Tests:** a mocked session is reused across two queries and closed once; the report
  issues exactly one InfluxDB query.

#### P2-12 `get_service_status` queries stats for stopped containers

- [x] `get_service_status` runs `docker stats --no-stream` (1–2 s per container) and
      `docker port`, then discards the stats when `Running: false`. Check the inspect result
      first and skip both commands for stopped containers.
- **Done:** inspect is the first command per container; when `Running:` is
  false, the tool reports that stats and ports are unavailable without running either
  command.
- **Tests:** a stopped container emits no `stats`/`port` command; a running container still
  does.

#### P2-13 Structured output is incomplete in `disk-health-mcp`

- [x] Only `list_disks`, `get_disk_health` and `get_full_disk_report` return
      `ToolOutput(..., data=...)`. The other ten tools return bare `str`, so
      `ToolResponse.data` is empty. Populate `data` for `get_smart_attributes`,
      `get_nvme_health`, `run_smart_test`, `get_zfs_status`, `get_raid_status`,
      `get_snapraid_status`, `get_mount_status`, `get_io_stats`, `query_prometheus_disk`
      and `query_influxdb_disk`.
- **Done:** all thirteen tools return `ToolOutput` with `data` on success:
  parsed SMART/NVMe attributes, test status, ZFS/RAID/SnapRAID/mount/I/O command output and
  the decoded query payload (`rows`/`row_count` or `result`).
- **Tests:** every tool publishes the `ToolResponse` schema, and each tool's representative
  success payload is asserted.

#### P2-14 Stale PromQL error message

- [x] `remote-server-mcp/server.py` still says `"- Not contain quotes or newlines"`,
      contradicting `validate_prometheus_query()`, which allows them. Update the message to
      describe the actual policy.
- **Done:** both PromQL error messages now state the real limits: no null
  bytes or control characters other than newline/tab, at most 5000 characters, one
  expression. Quotes, label matchers and comparisons are explicitly allowed.

#### P2-15 Structured output depth (deferred)

- [x] `remote-server-mcp` now publishes structured data for `get_host_service_status`
      (unit, status and entries), `get_host_service_logs` (unit, window, source and redacted
      entries) and `search_host_service_logs` (matches). `get_service_status` also carries
      `container_details` parsed from inspect (state, running, health, failing streak,
      restart count, exit code and start time).
- [x] `get_snapraid_status` keeps the raw text and adds `data.parsed`: per-disk and total
      rows, sync state, scrub ages, not-scrubbed percentage, errors and zero-timestamp file
      count. SnapRAID has no JSON output, so the parser reads its stable report lines and
      keeps `data.status` as the authoritative raw payload.
- **Status:** both typed-payload improvements landed in the 0.4.0 tree (see 3.6).

### 3.6 Handover remediation (2026-10-23)

These findings came from an agent operating the live MCP servers. The in-repo fixes are
complete; the one host-side prerequisite remains in catafalco.

- [x] **`run_smart_test` no longer infers standby from an exit code.** A read-only
      `smartctl -i` probe runs first (`-n standby` for ATA), and failures are classified as
      `permission`, `standby`, `unsupported` or `error`. NVMe tests omit `-n standby`, and
      every result publishes the raw output, parsed `exit_status` and the
      `smartctl -l selftest` command that shows the result.
- [!] **Host-side self-test privilege (catafalco, outside this repository).** If tests must
      actually start under the MCP user, add a scoped `smart-selftest` sudo wrapper plus a
      `SMART_SELFTEST_SUDO_ARGV` catalog entry. Until then a permission failure is reported
      as such instead of as "standby".
- [x] **`start_service` checks state and requires confirmation.** Already-running containers
      are reported with `changed: false` and are not passed to `docker start`; unconfirmed
      calls return a preview only.
- [x] **Output and parsing fixes.** SnapRAID structured parsing (the redundant legacy
      `fields` map removed), a readable `list_disks` table, full paths in
      `list_service_files` errors, key-aware `.env` redaction with `redacted_keys`, NVMe
      error-information severity, and the InfluxDB v3 `GROUP BY` projection advisory in both
      servers. Failed-poll summaries use readable status labels, and error responses carry a
      structured `data.error` object.
- [x] **Routing fixes.** Host-unit hints from the container tools, file-log hints for
      nginx/swag, Ansible-managed/absent-compose detection before Compose runs, host journal
      `since` support and a local `search_host_service_logs`. Journal relative durations are
      normalized to the `-2h` form journalctl accepts; RFC3339 timestamps and dates are
      passed through unchanged.
- [x] **Host unit defaults.** `smartmontools` replaces the `smartd` alias; the non-existent
      `snapraid` and `mergerfs` units are gone. The defaults are now `telegraf`,
      `smartmontools`, `docker` and `smbd`.

### 3.4 Release and migration

- [x] **CI is green.** Run 39123943472 was superseded by runs `39173411533` (`de6d981`)
      and `39175566454` (`81733d2`), both successful across Python 3.11–3.14. No red run
      needs investigating.
- [x] **Create the remote repository.** `elmuz/server-mcp` exists and is configured as
      `origin`.
- [x] **Push `main`.** `origin/main` and local `main` both point at `9901974`;
      `feat: complete P0/P1 remediation and library hardening` (`de6d981`),
      `feat: complete P2 modernization` (`81733d2`) and
      `feat: complete 0.2.0 remediation and harden metric clients` (`3c5f307`) are pushed.
- [x] **Resolve the version number before tagging.** The current tree is **`v0.2.0`**. The
      `[Unreleased]` entries moved into `## [0.2.0] - 2026-10-20`, and the version strings
      (three package `pyproject.toml` files, the workspace root `pyproject.toml`, the three
      `__version__` values and `uv.lock`) already said `0.2.0`, so they are unchanged. The
      `server-management-lib>=0.2,<0.3` constraints stay valid.
- **Rationale:** `50de082` only *named* the consolidation `v0.2.0` in its commit message;
  no tag was created and PyPI has no artifact for any of the three names. An untagged,
  unpublished version is not a release, so it is still the upcoming one and its contents may
  change. The P0-1…P0-8 defects found after `50de082` (fabricated `100/100` disk health,
  invisible container health, permissive command policy, env-override config corruption) are
  bugs in that same unreleased tree; publishing them as `0.2.0` and immediately shipping
  `0.2.1`/`0.3.0` fixes would put a known-broken artifact on PyPI and burn two version
  numbers. No consumer exists that could depend on the `0.2.0` contents, so nothing is
  broken by folding the fixes in. Bumping to `0.3.0` was rejected for the same reason: it
  implies a `0.2.0` release that never happened and would leave a phantom changelog section.
  The first change *after* this release starts at `v0.2.1`/`v0.3.0`. `docs/releasing.md`
  records the decision and warns that, because the version string did not change, `dist/`
  must be cleaned before `uv build` so a stale pre-fix wheel cannot be published.
- [x] **Create and push the tag.** `v0.2.0` is a GPG-signed annotated tag on `9901974`
      (`docs: record the verified 0.2.0 release build`, which adds only documentation on top
      of `3c5f307`), pushed to `origin`. The release artifacts in `dist/` were rebuilt from
      `3c5f307` and diffed file-by-file against the three source trees before tagging; the
      documentation-only commit does not change them.
- [x] **Publish to PyPI.** `server-management-lib` went first, then `remote-server-mcp` and
      `disk-health-mcp`. All three now answer on the PyPI JSON API at `0.2.0` with a wheel
      and an sdist, and `uvx remote-server-mcp --help` / `uvx disk-health-mcp --help`
      install from the index instead of the workspace. The bootstrap account token was used
      once for this upload; `.github/workflows/publish.yml` now publishes through PyPI
      trusted publishing, so later releases store no token.
- [x] **Archive the old repositories.** `remote-server-mcp`, `disk-health-mcp` and
      `server-management-lib` are archived on GitHub.
- [x] **`v0.3.0`.** Signed annotated tag on `c688dea` (`chore(release): 0.3.0`) with the
      serial-identity work (P1-19), the pluralized sample ages and the narrowed `AUTH_*`
      redaction. Built from a clean `dist/`, published by the trusted-publishing workflow
      (run `39852335149`) in library→apps order, and verified with `uvx` and installed-package
      smoke calls.
- [x] **`v0.5.0`.** Signed annotated tag on `0968abe`
      (`chore(release): 0.5.0`). Bumped the library pin to `>=0.5,<0.6` in both apps before
      the tag, so the published wheels resolve. `uv publish --dry-run` checked all six
      artifacts, publish run `41553210132` uploaded library→apps, and image run
      `41553210242` published `ghcr.io/elmuz/server-mcp:v0.5.0`. `uvx --no-cache`
      installs `0.5.0` for both servers.
- [x] **`v0.4.0`.** Signed annotated tag on `37ae9dc` with the live-operation handover fixes,
      journal-time normalization, structured errors and the corrected host-unit defaults.
      The trusted-publishing workflow (run `39869621919`) uploaded all three packages in
      library→apps order; `uvx --no-cache` resolves `0.4.0`. A first tag push failed before
      publishing because one test depended on the developer's local host config; the test was
      fixed, the unpublished tag was recreated on the corrected commit, and the rerun passed.
- **Prerequisite:** `gh` was missing during the migration and is now installed and
  authenticated (`gh auth status`), so `gh workflow run`, `gh run watch` and
  `gh api repos/elmuz/server-mcp/environments` are available for the release steps.

### 3.5 Cross-repo prerequisites (`~/projects/catafalco`)

These are deployment issues, not server-mcp bugs, but they change what the MCP can observe.
They are listed so the MCP work is not "fixed" against a broken environment.

- [ ] **The `containers` list does not gate role execution.** Only SWAG network discovery and
      backups consume it. `redlib` was in the list but not in the playbook (now removed);
      `vllm` was in the playbook but not running (now removed). Either implement gating or
      correct the docs/AGENTS.md.
- [ ] **InfluxDB 3 Core has no read-only tokens.** Version 3.12.1 only supports
      `influxdb3 create token --admin` (permissions `*:*:*`); there is no `--permission` flag.
      Use a dedicated named admin token (shorter expiry, separate from Telegraf/Grafana) plus
      a query-only reverse proxy or an SSH tunnel, or move to InfluxDB 3 Enterprise if
      fine-grained tokens are required.
- [x] **Optional SMART hardening.** The Telegraf role now uses an explicit
      `[[inputs.smart]] devices = [...]` list built from `/dev/disk/by-id/...` paths with
      `-d sat` / `-d nvme`, so there is no device-type autodetection and no per-interval
      `--scan`. The kernel name used in the `device` tag is resolved from the by-id link at
      deploy time: the hardcoded `device` values in `host_vars` had gone stale after a disk
      was added, which made InfluxDB (and `get_disk_health`/`get_full_disk_report`) report
      one disk's SMART data under another disk's name. `nocheck="standby"` remains.
- [x] **Host MCP prerequisites.** The `telegraf` role adds `username` to `systemd-journal`
      (otherwise `get_host_service_logs` returns "No entries") and installs `sysstat` for
      `get_io_stats`. The `snapraid` role grants an ACL on the content directories/files so
      `snapraid status` can create its lock and read the content (otherwise
      `get_snapraid_status` fails with `Permission denied`); a stale root-owned lock left by
      a killed run must be removed manually once. Ansible-managed containers without a
      compose project label (`invidious-db`, `speedtest_tracker-db`, `socket-proxy`, ...) are
      listed in `security.allowed_containers` in the local MCP config.
- [ ] **AGENTS.md examples that cannot work in the catafalco repo:**
      `restart_service(service="telegraf")` / `get_service_logs(service="telegraf")` (host
      service), Telegraf deploy via `--tags containers` (tags are `telegraf`, `monitoring`),
      and `docker-compose.yml` (actual name is `compose.yml` or no file at all).
- [x] **Do not add `node_exporter`.** SMART data comes from Telegraf/InfluxDB; there are no
      `smartmon_*` metrics. Prometheus remains optional and is retired on this host.

### 3.7 Multi-target support (planned, 2026-10-26)

**Status:** design agreed, not implemented. This section is the working plan; keep it in
sync with the code as the phases land. The current code is already host-agnostic per
process: `catafalco` appears only in documentation and example configs, and the target is
selected by `ssh.host`, `services_path`, metric endpoints and the other config sections.
The real limitation is that one process owns one config, one executor, one rate limiter and
one metric/tunnel set.

**Goal:** let one MCP server address several configured hosts so an agent can debug a
cross-host problem (for example, server A cannot reach server B) without losing the
security properties of the single-host design.

**Non-goal:** accepting an arbitrary hostname, username, key path or port from the model.
That would turn the MCP server into a network pivot and a credential-laundering proxy. A
`target` argument must resolve through an operator-configured allowlist.

#### Security invariants

- A target is an alias in the `targets` configuration map, never a free-form host value.
- The model cannot supply SSH credentials, key paths, ports, `known_hosts` files or
  `services_path`. Those belong to the target context.
- Each target has its own credentials, host-key policy, `services_path`,
  `allowed_containers`, `host_units`, disk paths, container runtime, metric endpoints,
  rate limiter and audit metadata.
- `target` is required when more than one target is configured. Omission is allowed only
  for the legacy single-target configuration, and the response still names the resolved
  target. Never silently default to the first target when several exist.
- Every command, file read, query, policy refusal and rate-limit event carries the target
  alias. A shared audit file is acceptable only when every record is target-tagged.
- Cross-host probes are opt-in, read-only and destination-allowlisted. Do not add generic
  `curl`, `nc`, `ssh` or port-scanning tools.

#### Configuration model

Keep the existing top-level sections as defaults and add an optional `targets` map. A target
inherits the defaults and overrides only what differs. If `targets` is absent, synthesize a
single target (working name `default`) from the existing config, so current deployments and
tests keep working.

```yaml
targets:
  catafalco:
    ssh:
      host: catafalco.example.com
      username: mcp
      key_path: ~/.ssh/mcp_catafalco
    security:
      services_path: /srv
    health:
      disk_paths: ["/", "/mnt/storage"]
    influxdb:
      enabled: true
      host: 127.0.0.1
      ssh_tunnel:
        enabled: true

  server-b:
    ssh:
      host: server-b.example.com
      username: mcp
      key_path: ~/.ssh/mcp_server_b
    security:
      services_path: /opt/services
```

Open question to settle in Phase 1: target-scoped environment overrides. The current
`ENV_OVERRIDES` table is singular (`SSH_HOST`, `INFLUXDB_TOKEN`, ...). Either add an
explicit naming scheme such as `REMOTE_SERVER_MCP_TARGET_<ALIAS>_SSH_HOST`, or require
secrets to live in a per-target `.env`/config file. Do not make the model or an HTTP caller
choose credentials.

#### Runtime model

Introduce a target registry in `server-management-lib`, for example
`packages/server-management-lib/src/server_management_lib/targets.py`:

```python
@dataclass
class TargetContext:
    name: str
    config: dict
    security: SecurityValidator
    executor: Executor
    catalog: ContainerCatalog
    rate_limiter: RateLimiter | None
    audit: AuditLogger
```

The registry lazily creates and caches one context per alias. It owns executor lifecycle,
metric clients and tunnels. Do not use a mutable global "current target" or a contextvar as
the primary routing mechanism: pass the resolved context explicitly through the tool
functions so a concurrent call cannot observe another call's target.

`apply_config()` should build a new registry and swap it atomically instead of mutating the
global `security`, `executor`, `catalog` and `rate_limiter` objects in place. In-flight calls
keep their old context until they finish; new calls use the new one.

#### Tool surface

- Add `target` as the first argument to every host-scoped tool in both apps. Keep `service`,
  `device`, `unit` and query arguments unchanged.
- Add `list_targets()` returning aliases, capabilities and (optionally) reachability.
- Include `target` in every `ToolOutput.data` payload, error message and audit record.
- Update tool descriptions so the model knows the target is an allowlisted alias and that
  it must not guess or invent one.
- Keep `READ_ONLY`, `WRITE_ACTION` and `DESTRUCTIVE_ACTION` annotations tool-wide. The
  annotation does not vary by target; `confirm=true` remains mandatory for state-changing
  calls.
- Scope MCP resources by target, for example `server-mcp://targets`,
  `server-mcp://targets/{target}/config/schema` and
  `server-mcp://targets/{target}/tools/catalog`. Keep the old resource URIs as aliases for
  the single-target case if that is cheap.

#### Lifecycle, rate limits and metrics

- Create executors lazily; do not open SSH connections at import time.
- At startup, probe every target and report degraded targets without refusing to start the
  whole process. One unreachable host must not block tools for the others.
- Close every executor, metric client and tunnel on shutdown.
- Replace the global rate limiter with a per-target limiter (probably keyed by
  `(target, action)`) so one noisy host cannot exhaust the budget for another.
- Key metric clients and tunnels by target, not by `id(config)`. Replace the brittle
  `_metric_clients` cache.
- Add `target` to audit events. Decide whether the default is one shared JSONL file with a
  `target` field or one file per target; shared is better for cross-host timelines, split
  files are easier to isolate.

#### Cross-host diagnostics (separate opt-in phase)

Multi-target support alone lets the agent inspect both hosts, but not prove that A can reach
B. Add this only after the registry is stable:

- `get_network_status(target)` using allowlisted `ip`/`ss` operations.
- `check_connection(source, destination, port)` where `destination` is another configured
  target or an explicitly allowlisted endpoint. Never accept an arbitrary host/port from the
  model.
- Aggregate views that collect logs from both ends for a bounded time window, with explicit
  target-local timestamps and a clock-skew warning.

#### Implementation phases

- [ ] **Phase 1 — config and registry.** Add the `targets` config merge, alias validation,
      single-target compatibility synthesis and target-scoped environment override decision.
      Add `TargetContext`/`TargetRegistry` in the library. Tests cover inheritance, alias
      validation, duplicate aliases, missing `targets`, and the legacy single-target config.
- [ ] **Phase 2 — remote-server-mcp.** Replace module-level `security`, `executor`, `catalog`
      and `rate_limiter` reads with a resolved target context. Add `target` to every tool,
      `list_targets()`, target-aware errors and `ToolOutput.data`. Keep `resolution.py`
      stateless; it already accepts `executor`, `security` and `catalog` explicitly.
- [ ] **Phase 3 — disk-health-mcp.** Apply the same registry and `target` parameter. Keep
      per-target `host.enabled`, InfluxDB/Prometheus settings, device identity and SMART
      source priority. A target may legitimately support disks but not Docker, or the
      reverse; expose that through `list_targets()` capabilities.
- [ ] **Phase 4 — lifecycle and observability.** Per-target rate limiters, target-tagged
      audit, metric clients and tunnels keyed by target, startup probes, shutdown cleanup and
      partial-failure reporting.
- [ ] **Phase 5 — MCP surface.** Target-scoped resources, tool description updates and the
      documented compatibility rule (`target` optional only with one configured target).
- [ ] **Phase 6 — cross-host diagnostics (optional).** Add the allowlisted network/status
      tools and aggregate views only after the first five phases are covered by tests.
- [ ] **Phase 7 — docs and release.** Update `README.md`, `docs/configuration.md`,
      `docs/tools.md`, `docs/architecture.md`, `docs/security-model.md`, `AGENTS.md` and
      `CHANGELOG.md`. Add a multi-target example config and a live smoke procedure with two
      targets.

#### Testing requirements

- Unit tests must not require a real host or network. Mock executors per target and assert
  that each tool routes to the requested alias only.
- Security tests must assert that a raw hostname, IP, username, key path or port is rejected
  as a target; that a target cannot escape its configured `services_path`; and that one
  target's credentials never appear in another target's command, file read or audit record.
- Concurrency tests: two simultaneous tool calls for different targets must not share a
  connection, rate limit or metric client. A config reload during an in-flight call must not
  change that call's target.
- Integration tests use the existing `integration` marker and remain opt-in.
- Keep or raise the current coverage gates; do not lower them.

#### Acceptance criteria

- An existing single-target `config.yaml` works unchanged; tools may omit `target` and the
  resolved alias appears in the response.
- With two configured targets, `target` is mandatory and an unknown alias is rejected with a
  helpful `list_targets()` hint.
- No tool accepts or forwards an operator-supplied host, user, key, port or arbitrary path.
- Audit and rate limiting are unambiguous per target; one unreachable target does not block
  the other.
- `list_targets()` and target-scoped resources expose capabilities without leaking secrets.
- Docs, tests and `CHANGELOG.md` are updated in the same change.

#### Risks and open questions

- **Blast radius.** One process with credentials for several hosts is a higher-value target
  than several single-host processes. For sensitive deployments, keep the recommended mode
  as one MCP server per target; make multiplexing opt-in.
- **HTTP authorization.** The Streamable HTTP transport has one process-wide bearer token.
  A multi-target HTTP server therefore grants access to every target. Per-user/per-target
  authorization is out of scope unless the deployment requires it.
- **Model mistakes.** A model can forget or guess `target`. Make it required with multiple
  targets, reject unknown aliases, and echo the resolved target in every result.
- **Output volume.** Per-call caps still apply, but a model can call many targets in one
  turn. Aggregate views must apply a composite cap.
- **Naming.** Prefer `target` over `host` or `server`: `host` implies an arbitrary network
  hostname, and `server` collides with the existing `service` vocabulary.
- **Decision needed:** shared versus per-target audit files, and the exact target-scoped
  environment-variable scheme.

### 3.8 Containerized trust domains (runtime implemented, 2026-10-27)

**Status:** the MCP runtime is implemented. The author sandbox integration, deployer and
end-to-end isolation verification remain deployment work. This section extends the plan; it
does not replace 3.7 or the completed history.

**Why:** the controls in [security-model.md](security-model.md) assume the agent reaches the
target only through the MCP server. A coding agent with a shell on the control node can edit
the MCP checkout or configuration, kill or restart the process, read SSH keys and vault
passwords directly, or bypass the MCP with `ssh`, `docker` or `ansible-playbook`. In that
deployment the MCP policy is not a security boundary.

**Goal:** make the MCP policy meaningful again when the agent is untrusted (prompt
injection, a compromised model or a compromised dependency) by separating the untrusted
author/harness from the privileged MCP/deployer with process, user, filesystem and
credential boundaries. The human approval for deployment must live outside both.

**Non-goals:**

- Do not add a generic `ansible-playbook`, `docker run` or shell tool to `server-mcp`.
- Do not accept a playbook path, tag, inventory, extra vars, image or command from the
  model. Deployment remains a fixed, operator-configured operation on an approved commit.
- Do not treat a container as sufficient for fully hostile code. Docker shares the host
  kernel; use a VM or separate machine when the code itself is untrusted.
- Do not break the trusted single-user workflow: stdio and the local executor remain
  supported, but they are not an isolation boundary.

#### Trust domains

```text
Host / human approval
│
├── author container (untrusted model)
│     - workspace read-write, no host home
│     - no SSH keys, vault password, MCP config or Docker socket
│     - no host PID/network/IPC; non-root; dropped capabilities
│     - reaches only the model API and the MCP endpoint
│
├── MCP container (privileged executor)
│     - pinned read-only image; no agent-writable code
│     - config, SSH key and known_hosts read-only or injected as secrets
│     - audit volume is the only writable mount
│     - egress only to the configured target and metric endpoints
│
└── deployer/approval boundary
      - approved commit/diff, not a mutable working tree
      - vault password and deployment credentials only here
      - human approval outside the author container
```

The author and the MCP must not share a writable repository, a Docker socket, a home
directory or a process namespace. If the author can write the code or configuration that
the MCP loads, the split provides no protection.

#### Security invariants

- The MCP code is installed from a pinned wheel or image and mounted read-only. The author
  workspace is never mounted into the MCP container.
- The MCP configuration, SSH key, `known_hosts` and metric tokens are read-only inputs. The
  audit log is the only writable state.
- The author container has no host SSH keys, no vault password, no cloud credentials, no
  MCP configuration and no Docker socket.
- The author container runs as a non-root user with `cap_drop: ALL`,
  `no-new-privileges`, a read-only root filesystem, tmpfs for temporary files and explicit
  CPU, memory and PID limits.
- The MCP container uses the same hardening and a minimal base image. It does not run
  privileged and does not mount the host root, the Docker socket or `/proc`.
- The MCP transport is Streamable HTTP with a bearer token over an internal network. The
  listener is not publicly reachable. stdio remains available for a trusted local setup,
  but stdio by itself does not create a trust boundary.
- The deployer accepts only an approved commit or artifact. It rejects a dirty worktree,
  model-supplied tags, extra vars, inventory paths and playbook paths, and verifies the
  commit/diff that the human approved.
- The model can request a deployment; it cannot mint the approval. The approval is a human
  action in a terminal, CI or Git host outside the author container.
- Multi-target support (3.7) must not be deployed next to an untrusted agent without these
  boundaries. One process holding credentials for several hosts increases the blast radius.

#### Workstreams and phases

- [x] **Phase 1 — threat model and docs.** Add the trust-boundary section to
      `docs/security-model.md`, link it from the plan, and state that the MCP policy is not
      a boundary against a local agent with write access. This phase is documentation-only.
- **Done:** `docs/security-model.md` now scopes the controls to an agent that reaches the
  target only through the MCP, records the local-agent limitation and links to this
  section. The outdated catafalco blanket-sudo statement was corrected in the security
  model and `docs/tools.md`.
- [x] **Phase 2 — MCP runtime.** Add a minimal container image and an example Compose or
      systemd unit that runs `remote-server-mcp` and `disk-health-mcp` as separate services
      over Streamable HTTP. The image runs non-root, from a read-only root filesystem, with
      config/key/`known_hosts` secrets and a writable audit volume. Pin the image by digest
      in the example. Keep the tools and the command policy unchanged.
- **Done:** `container/Dockerfile` builds one image with both console scripts from the locked
  workspace. `deploy/quadlet/` runs them under `server-mcp.target` on an internal
  `pi-control` network plus a separate `mcp-egress` network; config, key, `known_hosts` and
  token are read-only mounts and the audit directory is the only writable state.
  `transport.token_file`/`MCP_HTTP_TOKEN_FILE` and `--check-config` were added, container
  startup rejects `executor: local`, and `.github/workflows/image.yml` lints, builds,
  smoke-tests and publishes the image with provenance and an SBOM. The units use
  `localhost/server-mcp:dev` for local builds; replace it with the GHCR digest printed by
  the release workflow. See [container.md](container.md).
- [ ] **Phase 3 — author sandbox.** Document a harness-agnostic sandbox template: workspace
      read-write, no host home, no SSH keys, no vault password, no Docker socket, restricted
      egress and the MCP endpoint as the only control-plane destination. Client-specific
      setup stays in `docs/harnesses.md`; root docs stay harness-agnostic.
- [ ] **Phase 3b — isolate the sandbox workspace.** The current `pi-sandbox` mounts the
      project directory read-write, so an untrusted author can plant files that a host-side
      process later executes: `.pi/mcp.json`, `.pi/extensions`, `AGENTS.md`, git hooks, test
      configuration, build metadata and scripts. Ignored paths such as `.pi/` do not appear
      in `git diff`. Add a disposable clone or ephemeral workspace copy for sandbox
      sessions, or make the host checkout read-only when the sandbox runs. Until then,
      document the interim rule: never run host `pi`, tests, build, deploy or `pre-commit`
      in a checkout an untrusted sandbox has written to without a separate review.
- [ ] **Phase 4 — deployer and approval.** If Ansible deployment is added, build it as a
      separate deployer, not as a `server-mcp` tool. The deployer reads only an approved
      commit, maps service names to fixed tags, runs the fixed playbook from a clean
      worktree and keeps the vault password and deployment SSH key. A local approval helper
      or CI approval is the trust anchor. This is a cross-repo workstream with the Ansible
      repository; `server-mcp` only documents the contract.
- [ ] **Phase 5 — verification and release.** Add a repeatable smoke test that starts the
      MCP container, calls read-only tools over HTTP, verifies the author cannot read the
      MCP config/key or the Docker socket, verifies the MCP cannot read the author
      workspace, checks that `mcp-egress` reaches only the configured endpoints, and checks
      the audit volume. Update `docs/configuration.md`, `docs/architecture.md`,
      `docs/security-model.md`, `README.md` and `CHANGELOG.md`. The executable scope is
      tracked as R1 and R2 in 3.10; the author-side companion is the pi-sandbox roadmap.
- **Done (2026-11-05):** `scripts/container-smoke.sh` starts the image, exercises both entry
  points, the token file, `--check-config` and the HTTP bearer-token middleware under Docker
  and Podman, then runs `scripts/egress-smoke.sh` and `scripts/isolation-smoke.sh`. The
  egress allowlist and author/MCP isolation directions are therefore automated (R1/R2).
  The author-side launcher checks live in the pi-sandbox isolation self-test; this
  repository verifies the MCP side with a representative author container.

#### Acceptance criteria

- A user can run the MCP from a read-only image with read-only configuration and secrets,
  and the existing read-only tools work over Streamable HTTP.
- An author container with the workspace mounted cannot read the host SSH key, the MCP
  configuration, the audit log or the Docker socket, and cannot signal the MCP process.
- The MCP container cannot read the author workspace or the Ansible vault password.
- The MCP image is pinned and the only writable path is the audit volume.
- A deployment request without an approved commit or outside the approval boundary is
  refused before any privileged command runs.
- The trusted single-user stdio setup still works and is documented as the lower-isolation
  option.
- Tests cover the configuration/secrets boundary where it can be tested without Docker;
  container smoke checks are documented and opt-in.

#### Risks and open questions

- **Docker is not a VM.** A kernel or runtime escape defeats the split. Use rootless Docker
  or Podman where possible, and a VM/separate host for fully hostile code.
- **Shared HTTP token.** The Streamable HTTP transport has one process-wide bearer token.
  Keep the listener on an internal network, rotate the token and do not expose it to the
  model. Per-user authorization is out of scope.
- **Operational complexity.** Two images, secrets, network policy and an approval helper are
  more work than a local stdio process. Start with Phase 2 and keep the stdio path for
  trusted single-user use.
- **Deployer scope.** Ansible roles are code execution as root, not just file edits. Do not
  let the author container write the playbook or role that the deployer runs. The approved
  commit is the boundary.
- **Shared writable workspace.** The author sandbox and the host development checkout can
  be the same directory. The container prevents direct host access during the session, but
  it cannot prevent the operator from later executing agent-written files in that checkout
  as the host user. Treat the sandbox workspace as untrusted output until Phase 3b lands.
- **Supply chain.** Pin image digests, build from the locked workspace, and publish the
  image only from CI. Do not let the author build the image the deployer trusts.
- **Decided:** one image with two entry points (`remote-server-mcp` and `disk-health-mcp`),
  because both servers share `server-management-lib` and the same hardening; Quadlet (not
  Compose) is the shipped unit format. The deployer stays outside this repository
  (Phase 4); `server-mcp` documents the contract only.

### 3.9 Release channel parity (planned, 2026-11-02)

#### Context

The project ships two artifacts from one signed tag: the PyPI packages
(`server-management-lib`, then the two apps) and the GHCR container image built from
`container/Dockerfile`. The container deployment is the recommended security boundary; the
PyPI install remains the supported stdio/host-run channel and the documented
lower-isolation option, so `README.md` and `docs/harnesses.md` still show `uvx`.

#### Decision

Keep publishing all three packages. Do not collapse the project to a container-only support
contract now. The release gate must cover both channels so a tag cannot publish one artifact
while the other is broken or missing.

- [x] **Gate the image in the publish workflow.** `.github/workflows/publish.yml` now has a
      `container` job that builds `container/Dockerfile` and runs
      `scripts/container-smoke.sh` on the release tag, and `publish` needs it. GHCR
      publication stays in `image.yml`; the smoke script still selects Docker or Podman.
- [x] **State the support contract.** `README.md` now opens the quick start with the channel
      choice (container for an untrusted agent, checkout or `uvx` for a trusted single user)
      and `docs/getting-started.md` no longer claims the packages are unpublished.
      `docs/releasing.md` records that one tag publishes PyPI and GHCR from the same commit,
      that the image is the recommended deployment, and that release notes carry the digest.
      The `>=0.5,<0.6` library pin is documented as part of every version bump.
- [x] **Verify the fan-out in the release checklist.** `v0.5.0` (commit `0968abe`) published
      all three PyPI packages (run `41553210132`) and
      `ghcr.io/elmuz/server-mcp:v0.5.0` (run `41553210242`, index digest
      `sha256:1f6854eb5949445f80022bee5c55524e570a26c8c5b5e291c4365f610c968c0c`) from the
      same commit. The digest is recorded here and in `docs/releasing.md`; `git describe`
      on the release commit prints the tag.

#### Acceptance criteria

- A failing image build or smoke test blocks the PyPI upload in the same workflow run.
- One signed tag produces all three PyPI packages and the matching GHCR image from the same
  commit, pinned by digest in the Quadlet examples.
- The README names the recommended channel and the alternative without implying that a
  PyPI install provides the container's isolation, token middleware or audit guarantees.
- `scripts/container-smoke.sh` works under Docker (CI) and Podman (local).

#### Follow-up (2026-11-03)

Re-dispatching `publish.yml` against the released `v0.5.0` tag, to exercise the image gate,
failed at the first upload: `uv publish --check-url` reported "Local file and index file do
not match" for the wheel, because a rebuild is not byte-identical (setuptools stamps archive
timestamps; `SOURCE_DATE_EPOCH` makes the wheels reproducible, not the sdists). The gate
itself passed.

- [x] Publish by filename instead of by hash. `scripts/pypi_missing.py` lists the dist
      artifacts PyPI does not have, and each workflow step passes only those; `--check-url`
      stays as the second guard. A dispatch against a tag created before the helper existed
      falls back to every artifact with a warning, because the workflow file comes from
      `main` while the tree comes from the tag. `docs/releasing.md` documents both paths.
- [ ] Optional: build with `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)` so the wheels are
      reproducible too. Not needed for idempotent publishing, only for artifact-level
      verification.

#### Deferred decision

Dropping PyPI (container-only support) stays an option but is out of scope. If adopted,
remove `publish.yml`, the `uvx` snippets and the stdio installation path from the docs in one
change, and say so explicitly in the README.

#### Risks

- Version drift between the image digest and the PyPI version. The shared release gate and
  the digest in the release notes are the guard.
- A single gate lengthens the publish run; the image build is cached, so the cost is the
  smoke test, not a cold rebuild.

### 3.10 Post-0.5.0 review follow-up (2026-11-05)

**Source:** [the 2026-11-05 project review](reviews/2026-11-05-project-review.md). The review
was static (no live host) and is preserved as a snapshot; this subsection is the only
actionable copy. IDs `R1`–`R8` are stable for commit messages and cross-repo references.

Ranking rule: **P0** means the documented trust boundary or a security claim is wrong;
**P1** means a realistic resource-exhaustion, disclosure or operator-footgun path; **P2** is
maintainability and supply-chain polish. None of these is a known wrong tool result.

#### R1 P0 — `mcp-egress` must allowlist destinations, not just name a network

- [x] **Done (2026-11-05).** `mcp-egress` is internal; `mcp-egress-proxy` is the only
      dual-homed member and applies a host-owned default-deny policy. The MCP units use the
      proxy for HTTP(S) and SSH (`server-mcp-connect`), and `deploy/render-egress-policy.py`
      derives the allow rules from the configs. `scripts/egress-smoke.sh` proves the
      reachable/blocked pair, direct-route denial and that the policy is not visible to the
      MCP container. The policy syntax is shared with pi-sandbox; the pi-sandbox proxy
      copy is kept in sync with this implementation, and its live isolation test now covers
      an unlisted public host, an unlisted IPv6 literal and policy invisibility.
- [x] **Problem.** `deploy/quadlet/mcp-egress.network` only sets `NetworkName=mcp-egress`.
      `docs/container.md` and `README.md` describe the network as the MCP's route to the
      target and metric endpoints, but a Podman bridge with NAT reaches the LAN and the host
      by default. A compromised MCP process or dependency can therefore connect anywhere
      the host can, regardless of the tool catalog.
- [x] **Change.** Make `mcp-egress` default-deny except for the destinations derived from
      the target configuration: `ssh.host` on `ssh.port`, the InfluxDB/Prometheus endpoints
      when enabled, and DNS if the deployment needs it. Enforce it with a host firewall
      rule set or a small egress proxy/policy container; do not rely on the network name or
      on `--internal`. Translate endpoint names to addresses deliberately (DNS changes,
      multiple A/AAAA records, IPv6), and keep the policy outside the MCP container.
- **Reasoning.** The pi-sandbox egress proxy already implements the same
      default-deny-plus-allowlist model for the author. Reuse that policy vocabulary where
      practical so the two repos do not drift into two incompatible definitions of "allowed".
- [x] **Acceptance.** A container test (or documented opt-in host test) proves that the
      configured SSH/metrics endpoints are reachable, an unrelated endpoint on the same
      network is blocked, IPv6 is not an accidental bypass, and the policy is not writable
      from inside the MCP container. `scripts/container-smoke.sh` grows the reachable/
      blocked pair. **Verified 2026-11-05** with `scripts/egress-smoke.sh` on Podman: the
      allowed target and the SSH `CONNECT` helper succeed, the blocked target returns 403,
      direct routes fail, an unlisted IPv6 literal is denied, and the probe cannot see the
      host-owned policy file.

#### R2 P0 — automate the author/MCP isolation checks

- [x] **Done (2026-11-05).** `scripts/isolation-smoke.sh` checks the author cannot reach
      `mcp-egress`, read the MCP config/key/known_hosts/token or a runtime socket, and that
      the MCP cannot read an author workspace path; the audit volume is the only writable
      mount. `scripts/container-smoke.sh` now runs both boundary scripts, so removing a
      boundary fails CI. The author in that script is a representative container; the real
      launcher's companion checks are in pi-sandbox `scripts/isolation-test.sh`
      (sensitive-path guard, `pi-egress`/`pi-control` reachability, `mcp-egress`
      unreachability).
- [x] **Problem.** 3.8 Phase 5 is still verified by hand. The container smoke test proves
      startup and token middleware, not that the author cannot read MCP secrets or that the
      MCP cannot read the author workspace.
- [x] **Change.** Extend the smoke/isolation script into a repeatable check: the author
      cannot reach `mcp-egress`, read the MCP config/key/known_hosts/token or the Docker
      socket; the MCP cannot read the author workspace; the audit volume is writable only
      where intended. Keep it opt-in when it needs a real container runtime, and document
      the exact prerequisites.
- [x] **Acceptance.** The check fails when any boundary is removed (negative test), not
      only when the happy path breaks. Results are recorded in this plan's verification
      section after a release. **Verified 2026-11-05** with `scripts/isolation-smoke.sh` on
      Podman: the author cannot reach `mcp-egress` or read MCP secrets/runtime sockets, the
      MCP cannot read the author workspace, and only the audit volume is writable.

#### R3 P1 — bound bytes while collecting, not only after capture

- [x] **Done (2026-11-05).** `output.BoundedCollector` shares one byte budget across
      stdout/stderr, retains at most `max_output_bytes` and drains the rest. The local
      executor reads both pipes concurrently instead of `communicate()`; the SSH executor
      uses `create_process(..., encoding=None)` and the same collector instead of
      `connection.run()`. The HTTP clients consume `aiohttp.StreamReader` in chunks before
      JSON/text decoding and return a clear "exceeded the N-byte output limit" message when
      a body is capped. Tests cover oversized stdout, stderr, SSH output and JSON/text HTTP
      responses.
- [x] **Problem.** `local_executor.py` used `process.communicate()` and `ssh_manager.py`
      used `connection.run()` before `sanitize_output()`; HTTP clients decoded JSON/text
      before applying the cap. The cap protected the model, not the MCP process: a command
      or response that emitted hundreds of megabytes was fully retained.
- [x] **Change.** Read stdout/stderr concurrently and retain at most `max_output_bytes`,
      marking truncation. For SSH, use a streaming process/channel API with the same bound.
      For aiohttp, enforce a response-byte limit while consuming chunks, before JSON
      decoding. On reaching the cap, drain without retaining. Keep timeout and SQL row
      limits as separate controls.
- [x] **Acceptance.** Tests cover oversized stdout, oversized stderr, oversized SSH output
      and oversized JSON/text HTTP responses; peak retention stays near the configured cap.
      This must land before multi-target 3.7 Phase 2, which multiplies concurrent calls.

#### R4 P1 — close the redaction gaps or narrow the claim

- [x] **Done (2026-11-06).** Option (a): comment bodies are redacted while the marker and
      ordinary text stay readable, and a sensitive key followed by a YAML block-scalar
      indicator masks the indented value lines. The dotenv path applies the same comment
      rule. Tests cover `# API_TOKEN=...`, `|`/`>-` block scalars, non-secret block
      scalars and the dotenv comment case; docs and the changelog describe the new scope.
- [x] **Problem.** `_redact_line()` returned comment lines unchanged, so a commented-out
      credential was returned verbatim. The matcher was line-oriented, so a YAML block
      scalar such as `api_token: |` masked the key line but not the indented value lines.
      The docs/tests documented the comment behaviour as intended.
- [x] **Change.** Redact recognized secret keys inside comments and handle multiline
      values for the config formats we expose, with conservative handling for unknown
      formats. The comment-preservation test now hides a secret value while ordinary
      comments remain readable.
- [x] **Acceptance.** `# API_TOKEN=...` and a YAML block-scalar secret are masked, with
      regression tests in the library and the remote-server app.

#### R5 P1 — authenticate SSH host keys at bootstrap

- [x] **Done (2026-11-06).** The container, getting-started, configuration and security
      docs, the example `known_hosts`, the installer next steps and the missing-file error
      now require scanning to a temporary file, checking the fingerprint with
      `ssh-keygen -lf`, comparing it with the host console or inventory, and only then
      appending. No doc presents `ssh-keyscan >> known_hosts` as sufficient.
- [ ] **Problem.** `docs/container.md` and `docs/getting-started.md` tell operators to
      append `ssh-keyscan` output to `known_hosts`. That retrieves a key but does not
      authenticate it, so a first-connection MITM can establish the trusted key.
- [x] **Change.** Document a verified flow: scan to a temporary file, inspect with
      `ssh-keygen -lf`, compare the fingerprint with a value from the host console or
      inventory, and only then append. Keep host-key verification enabled afterwards. Add
      the same note wherever `known_hosts` is populated.
- [x] **Acceptance.** No doc presents `ssh-keyscan >> known_hosts` as sufficient on its own;
      the troubleshooting entry also points to the verification step.

#### R6 P1 — make installer `--force` safe

- [x] **Done (2026-11-06).** `--force` now refreshes installed units only.
      `--replace-config` is the explicit opt-in for replacing `remote.yaml`, `disk.yaml`,
      `.env`, `known_hosts` and the SSH-key placeholder, and each replaced file keeps a
      timestamped `.bak.<UTC timestamp>` backup. The token and egress policy are never
      replaced. A failed `systemctl --user daemon-reload` is reported and exits non-zero.
      `scripts/test-install.sh` covers the three behaviors against a temporary
      `HOME`/`XDG_*` tree and runs in CI.
- [x] **Problem.** `deploy/install.sh` applies `--force` to configs, `.env`,
      `known_hosts`, the SSH-key placeholder and units alike, so refreshing units can
      overwrite operator configuration with examples. `systemctl --user daemon-reload ||
      true` can also hide a failed install.
- [x] **Change.** Separate "refresh units" from "replace config/secrets". For a config or
      key overwrite, require an explicit flag and keep a timestamped backup (or print a
      diff/preview and refuse non-interactively). Report `daemon-reload` failure and exit
      non-zero when a reload was required.
- [x] **Acceptance.** `--force` unit refresh leaves `remote.yaml`, `disk.yaml`, `.env`,
      `known_hosts` and `ssh/id_ed25519` unchanged; replacing a config requires the
      explicit flag; a failing `daemon-reload` makes the installer fail. Tests use a
      temporary `HOME`/`XDG_*` tree.

#### R7 P2 — pin the image base by digest

- [ ] **Problem.** `container/Dockerfile` defaults `PYTHON_IMAGE` to the mutable
      `python:3.13-slim` tag, so rebuilding the same source revision can silently change
      the OS/Python base.
- [ ] **Change.** Default to an approved multi-platform digest
      (`python:3.13-slim@sha256:...`) and update it through a reviewed dependency bump. Keep
      the build arg override for local experiments, but CI and release builds use the
      pinned default.
- [ ] **Acceptance.** The Dockerfile and the image workflow reference the same digest; a
      comment records how to refresh it and which platforms were verified.

#### R8 P2 — keep the app modules maintainable as the surface grows

- [ ] **Problem.** The two app modules mix tool handlers, orchestration and output shaping
      and have grown to thousands of lines. The application coverage floors (60% and 65%)
      are far below the library's 90%, so behavior changes are less protected.
- [ ] **Change.** When adding a tool, extract domain handlers (service lifecycle, metrics,
      disk diagnostics) behind the existing registration layer instead of adding more
      branches to one module. Raise each floor when the extracted area has tests; never
      lower a floor to land a change. Do not move policy out of the library.
- [ ] **Acceptance.** New domain modules have focused tests; the coverage floors move up
      with the extracted code; no tool bypasses the executor/security interface.

#### Recommended sequence

1. R1 + R2, together with 3.8 Phase 5 (the boundary must be real and tested before it is
   recommended). Coordinate the policy vocabulary with the pi-sandbox egress work.
2. R3 + R4 (memory bound and redaction) before 3.7 Phase 2 multiplies concurrent calls.
3. R5 + R6 (operator bootstrap and installer) before the next container release.
4. R7 + R8 as normal maintenance; R7 can land with any image change.

3.7 Phase 1 (config and target registry) is independent and may proceed in parallel. Do not
*deploy* multi-target support next to an untrusted author until R1, R2 and 3.8 Phases 3/3b
are complete.

## 4. Documentation drift

These are part of their parent items; do not close a parent until the documentation is
updated. Earlier drift items (P0-2, P0-3, P1-1, P1-2, P1-7, P1-8, P1-9, P1-10, P1-11 and
the `grafana` `get_service_file` example) are verified fixed in the current tree and are no
longer tracked here.

- [x] **P0-6:** `docs/configuration.md` states that `EXECUTOR`/`CONTAINER_RUNTIME` are
  top-level, and both `.env.example` files label them accordingly.
- [x] **P0-7/P0-8:** `docs/security-model.md` documents the remote `realpath` confinement
  and the regular-file restriction, timeouts and threaded local reads.
- [x] **P1-12/P1-13:** `docs/security-model.md` and `docs/tools.md` describe the tightened
  SQL `LIMIT`/comment policy and the argument-shape command policy; no claim that a prefix
  check alone is sufficient remains.
- [x] **P1-15/P1-16:** `docs/configuration.md` documents which tools are rate-limited and
  the audit file permissions; `docs/security-model.md` lists the policy events now audited.
- [x] **P1-17:** `docs/tools.md` and `docs/security-model.md` widen the redaction claim from
  `.env` to service config files and host status/log output.
- [x] **P2-14:** the `query_prometheus` error message is user-facing; fixed to describe
  the actual policy text.
- [x] **3.8 trust boundary:** `docs/security-model.md` now states the scope of the MCP
  policy, links to the containerized trust-domain plan and no longer claims that catafalco
  uses blanket passwordless sudo. `docs/tools.md` matches the narrow-sudo description.
- [x] **`docs/issues/influxdb-api-error-handling.md`:** the HTML/proxy-body detection
  (A–C) and the structured-database field (E) were implemented and this plan now owns the
  history. Item D (do not send DB queries through public ingress) is covered by the
  `influxdb.ssh_tunnel` / `prometheus.ssh_tunnel` block from P1-7, which opens a loopback
  forward over the executor SSH connection and reconnects on drop.
- **All tool changes:** update `README.md`, `docs/tools.md`, `docs/configuration.md`,
  `docs/security-model.md` and `CHANGELOG.md` in the same change.
- **Review records:** `docs/reviews/` holds frozen snapshots. When a review is triaged, add
  its accepted items to section 3 (or a `3.x` subsection), mark the snapshot status in
  [`docs/reviews/README.md`](reviews/README.md), and do not keep a parallel TODO list there.

## 5. Implementation order

1. **All pre-0.5.0 P0, P1 and P2 items are complete** (P0-1 through P0-8, P1-1 through
   P1-20, P2-1 through P2-15). The serial-identity work (P1-19), the canonical device
   vocabulary (P1-20) and the structured-output depth (P2-15) landed through `0.4.0`. The
   container runtime (3.8 Phase 2) is implemented in the current tree.
2. **Release:** `0.5.0` followed the steady-state path in `docs/releasing.md`: clean build,
   `uv publish --dry-run`, signed tag, trusted-publishing workflow, then the live smoke checks
   in 6.3 with the installed packages. The next release uses the same path, and now also
   gates on a successful image build and smoke test (3.9).
3. **The 3.8 Phase 2 MCP runtime has landed.** Multi-target support (3.7) increases the
   blast radius of one process; do not deploy it next to an untrusted agent before the
   author sandbox integration (Phase 3) and end-to-end isolation checks (Phase 5). The
   Ansible deployer is a separate cross-repo workstream.
4. **The next in-repo work is the rest of the 2026-11-05 review hardening (3.10), then
   multi-target support (3.7).** 3.9 is complete. R1/R2 (real, tested egress and author/MCP
   boundaries) are done; R3 (bounded collection) and R4 (honest redaction) are done, so
   land R5/R6 before the next container release, R7/R8 as maintenance. 3.7 Phase 1 may run in parallel,
   but do not deploy 3.7 next to an untrusted author before 3.8 Phases 3/3b are done. Keep
   the single-target process as the default deployment.
5. **Remaining external work is outside this repository:** the catafalco prerequisites in
   3.5.
6. **P2-15 is complete** (structured host/status data and SnapRAID parsing). The only
   remaining item from the pre-0.5.0 backlog is the catafalco host-side self-test privilege
   wrapper in 3.6.

There is no pending PR split; the branch history is linear on `main`.

## 6. Verification

### 6.1 Local suite

```bash
cd ~/code/server-mcp
uv sync --locked --all-packages --all-extras
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q
env -u VIRTUAL_ENV pre-commit run --all-files
uv build --all-packages
```

### 6.2 Current snapshot

| Check | Result |
|---|---|
| `server-management-lib` tests | 531 passed, 91.03% coverage (gate 90%) |
| `remote-server-mcp` tests | 297 passed (+17 integration opt-in), 84.44% coverage (gate 60%) |
| `disk-health-mcp` tests | 224 passed, 82.93% coverage (gate 65%) |
| Python version used locally | 3.12.16 |
| `ruff check`, `ruff format --check`, `ty check` | passing on the `0.5.0` tree |
| `pre-commit run --all-files` | passing on the `0.5.0` tree (ruff, ty, per-package pytest, pymarkdown, link check) |
| Remote CI | green through the `0.2.1` release and the post-release commits, Python 3.11–3.14 |
| `uv build --all-packages` | all three wheels/sdists build, `py.typed` included; `dist/` is always rebuilt from scratch |
| Package version | `0.5.0` in the four `pyproject.toml` files, the three `__version__` values, `uv.lock` and the newest `CHANGELOG.md` section |
| PyPI | `0.5.0` on all three projects (publish run `41553210132`); `uvx --no-cache` resolves both servers |
| Container image | `ghcr.io/elmuz/server-mcp:v0.5.0`, built by run `41553210242`; index digest `sha256:1f6854eb…68c0c` |

### 6.3 Live smoke checks (read-only)

Run after restarting the MCP servers with the updated config and again after each P0/P1 PR
that touches the relevant tool.

```text
get_server_health()
list_services()
list_containers()                                  # stopped and crashed containers too
get_service_status("deluge")                       # expect the Health field (healthy after the probe fix)
get_container_health("deluge")                     # expect the recent probe output
get_service_status("immich-server")                # expect it to work after P1-1
get_host_service_status("telegraf")                # after P1-2
get_host_service_logs("telegraf", lines=200)       # after P1-2; journalctl -u
get_host_service_status("sshd")                    # expect "Host unit not allowed"
get_disk_health("nvme0n1")                         # expect real InfluxDB data after P0-2
get_snapraid_status()                              # after P1-2
get_mount_status()                                 # after P1-2; mergerFS + df
get_service_logs("immich-server", lines=100, since="1h")   # after P1-5
search_service_logs("immich", "connection refused", since="1h")  # after P1-5
get_service_status("vllm")                         # retired: expect "Unknown service or container", no zeroed stats
get_disk_health("sda")                             # expect valid data plus sample age after P1-6
get_disk_health("vda")                             # expect explicit no-data error, not 100/100
get_smart_attributes("sda")
get_service_file("cypht", ".env")                  # expect redacted values after P1-3
query_influxdb("SELECT device, health_ok FROM smart_device WHERE time > now() - INTERVAL '1 hour' ORDER BY time DESC LIMIT 10")
query_prometheus("up")                             # expected: "not enabled" (Prometheus retired)
get_service_file("cypht", "compose.yml")           # after P1-17: inline secrets masked
```

Verified on 2026-10-22 against the workspace tree that became `0.3.0` (the servers were
started with `uv run --project …`): `sda` and `nvme0n1` returned InfluxDB samples with
verified serial identity, freshness and failed-poll evidence; `vda` returned the explicit
no-data error; mount/mergerFS, SnapRAID and `iostat` reported real data; `immich-server`
resolved through its compose project; `deluge` was healthy with probe output; `vllm` was
reported as unknown; `telegraf` logs and the `sshd` refusal worked; `.env` and `compose.yml`
were redacted; the InfluxDB query returned rows and Prometheus reported "not enabled".
These checks used the workspace. The installed `0.3.0` artifacts were then exercised through
the MCP client (`uvx --from …==0.3.0`): `get_disk_health("sda")` returned `ok:true`,
`get_disk_health("vda")` and `get_host_service_status("sshd")` returned `ok:false`, and
`get_service_status("immich-server")` returned `ok:true`.

Additional checks after the review fixes:

- **P0-6 (no host needed):** `EXECUTOR=local uv run remote-server-mcp --help` and
  `CONTAINER_RUNTIME=podman ...` must not raise `Unknown executor`; assert the selected
  values in a unit test rather than relying on the live config.
- **P0-7:** if `/srv` or `/srv/<service>` is a symlink on the target, `get_service_file` and
  `list_service_files` must still work; a symlink pointing outside the service directory
  must be rejected.
- **P0-8:** `get_service_file` on a FIFO must return an explicit "not a regular file" error
  quickly, never hang.

Observed on 2026-10-18: `nvme0n1` and `sda` returned real InfluxDB data, `vda`
returned the explicit no-data error, and the absolute `smartctl`/`nvme` commands reached
the host but the executor user received `Permission denied`. That permission result is the
expected no-sudo policy; use InfluxDB or grant block-device access.

For P1-5/P1-6, after the worktree changes: `get_service_logs("immich")` with
`lines=5`, `since="1h"` and `container="immich-server"` rendered
`docker logs --tail 5 --timestamps --since 1h -- immich-server` and returned timestamped
lines; `search_service_logs` matched the literal phrase. `get_disk_health("sda")` used the
last valid sample from 21:05 despite newer standby rows and reported
`Sample: 55 minutes ago`; the overview reported sample ages for all six devices instead of
`0°C`/`0 hours`.

For P1-1, after the worktree changes: `list_containers()` reported all 43 containers and
their service mapping; `get_service_status("immich")` returned `immich-server`,
`immich-machine-learning`, `immich-postgres` and `immich-redis`;
`get_service_status("immich-server")` resolved through the `immich` project; `watchtower`
was rejected with the allowlist hint. Remaining containers without a directory or project
label (for example `watchtower`, `wud`, `socket-proxy`) still need
`security.allowed_containers`.

## 7. Decisions

- Monorepo with a uv workspace; the two MCP servers stay separate for least privilege.
- History imported with `git subtree` (merge commit per repository) because
  `git-filter-repo` was unavailable.
- Recommended remote is a new `elmuz/server-mcp` repository; reusing/renaming
  `remote-server-mcp` is documented as an alternative.
- Local executor remains the single-host alternative to SSH. Multi-target support is now
  planned as an allowlisted target registry (section 3.7), not as a free-form host argument.
  The recommended secure deployment remains one MCP server process per target; multiplexing
  is opt-in.
- No runtime SMART database refresh; generation is an explicit offline script.
- InfluxDB is the primary SMART source; `smartctl` is an explicit fallback and must never
  fabricate a healthy result.
- Do not add `node_exporter` for the reference deployment; Prometheus is optional and
  retired there.
- Host infrastructure services are in scope only through a configured unit allowlist.
- The command policy is an allowlist of argv vectors, not a shell parser. Argument shapes
  matter: matching only the first one or two tokens is not sufficient for commands that
  accept paths, formats or units.
- Redaction is defense-in-depth for files the operator intentionally exposes (`.env`,
  compose/config files). Real credential stores remain blocked.
- `docs/modernization-plan.md` is the only backlog. Review/handoff documents are merged here
  rather than kept as parallel plans; frozen reviews live in `docs/reviews/` and carry no
  open TODOs. The plan is extended, not replaced: completed sections remain as history
  because they carry live findings and verification evidence.
- Container egress is allowlisted by destination, not implied by a network name. The
  pi-sandbox egress proxy and the server-mcp `mcp-egress` policy should share one policy
  vocabulary so an operator can reason about both boundaries together.
- The MCP policy is not a boundary against a local agent that can edit the MCP or use a
  host shell. The fix is separate trust domains (3.8), not another confirmation prompt.
- Do not add a generic `ansible-playbook` or deployment tool to `server-mcp`. Deployment is a
  separate, operator-approved operation on an approved commit.
- The container image and the PyPI packages are released by the same signed tag. The image
  is the recommended deployment; the `uvx`/`uv` install stays supported as the
  lower-isolation stdio/HTTP channel, and the one image carries both entry points.
- The first published release is `0.2.0`. A version that was never tagged or published is
  not a release, so post-`50de082` fixes are folded into it rather than published as
  `0.2.1`/`0.3.0`. From `0.2.0` onward, released sections are immutable.

## 8. Resume instructions

1. The in-repo open work is the review hardening in 3.10 (R1–R8) and multi-target support
   in 3.7. Release channel parity (3.9) is complete. The 3.8 Phase 2 container runtime is
   implemented; the author sandbox integration, deployer and end-to-end isolation checks
   (3.8 Phases 3, 3b, 4, 5) remain deployment work. The remaining open work outside this
   repository is the catafalco prerequisites in 3.5 and the host-side self-test privilege
   in 3.6.
2. For new in-repo work, start with 3.10 R5/R6 (R1–R4 are done), then 3.7 Phase 1. Add new items
   to section 3 with a checkbox that names the file or area to change; do not create a
   second backlog in `docs/reviews/`. The 3.8 Phase 2 runtime is done; Phase 3 (author
   sandbox) and Phase 5 (isolation verification) are deployment work.
3. Read the relevant code/doc section before editing; keep the security model in
   `docs/security-model.md` intact.
4. Add or update tests in the same PR (P0 items require regression tests).
5. Run the local suite in section 6.1.
6. Run the relevant live smoke checks in section 6.3.
7. Update this file and `CHANGELOG.md` when an item is completed; move remaining items if
   priorities change.
8. Do not commit `config.yaml`, `.env`, keys or tokens. Use environment variables or a
   `.env` file next to the config with mode `0600`.
9. For release steps, follow `docs/releasing.md`.

## Appendix A — Live evidence snapshot (2026-10-18)

Observed during the investigation. Values are illustrative; secrets are omitted.

| Check | Observation |
|---|---|
| `get_server_health` disk section | Only `/dev/sdd2` mounted on `/`; no `/mnt/storage` |
| `get_disk_health("sda")` | `Health Score: 100/100`, `Power-On Hours: 0`, `✅ No issues detected` |
| `get_smart_attributes("sda")` | `zsh:1: command not found: smartctl`, exit 127 |
| `get_nvme_health("nvme0n1")` | `zsh:1: command not found: nvme`, exit 127 |
| `get_io_stats()` | `zsh:1: command not found: iostat`, exit 127 |
| `get_raid_status()` | `cat: /proc/mdstat: No such file or directory` |
| `get_zfs_status()` | `zsh:1: command not found: zpool`, exit 127 |
| `list_disks()` | `sda,sdb,sdc,sdd,nvme1n1,nvme0n1` |
| InfluxDB `smart_device.device` | `sda,sdb,sdc,sdd,nvme0,nvme1` (no `n` suffix on NVMe) |
| `get_service_status("immich")` | `error: no such object: immich` |
| `get_service_status("immich-server")` | `❌ Service 'immich-server' does not exist in /srv/` |
| `get_service_status("deluge")` | `State: running` (no health), while `docker ps` says `unhealthy` |
| `get_service_status("influxdb")` | Works; `8181/tcp -> 127.0.0.1:8181` |
| `get_service_logs("telegraf")` | `❌ Service 'telegraf' does not exist in /srv/` |
| `get_service_file("cypht", ".env")` | `❌ Invalid file path` (misleading; path is valid) |
| `get_service_file("../../etc/hostname")` | Rejected (path traversal protection works) |
| `query_influxdb(...)` | Disabled in config before the live config fix |
| `query_prometheus(...)` | Disabled in config |
| Prometheus `up` | Single vLLM target, value `0`, `lastError: 502 Bad Gateway` |
| Prometheus `smartmon_*` metrics | 0 |
| `get_service_status("vllm")` | `❌ Service 'vllm' does not exist in /srv/` (cannot see stopped containers) |
| Deluge `State.Health.Log` | `Process 'openvpn\|wg' is not running`; `wg0` is UP and `http://127.0.0.1:8112/` returns 200 |
| `hd-idle` log | `Data2` stayed `stopped` for 10,811 s (~3 h) while Telegraf polled SMART every 10 s |
| InfluxDB `smart_device` | `sda` 465/720 and `sdb` 400/720 rows had `exit_status=2` (standby skip) |
| Grafana `/api/datasources` | After cleanup: only `InfluxDB_v3_SQL` remains |
| Grafana `/api/search` | No vLLM dashboard; System Monitor / Docker / SMART / Temperature remain |
| `influxdb-ui` | 502 before the port fix, HTTP 200 after |
