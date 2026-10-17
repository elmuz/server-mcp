# Modernization Plan (2026-10)

Resumable working plan for the three related projects:

- `~/code/remote-server-mcp` (RSM) — MCP server: Docker/SSH service operations
- `~/code/server-management-lib` (SML) — shared security, SSH, HTTP clients, config
- `~/code/disk-health-mcp` (DHM) — MCP server: SMART/NVMe/ZFS/RAID diagnostics

Status legend: `[ ]` todo, `[~]` in progress, `[x]` done, `[!]` blocked

Last updated: 2026-10-17

## 1. Context

The original intent stands: an MCP server acts as a constrained proxy so an autonomous
agent cannot run arbitrary commands on a production home server. The architecture is
still valid:

```text
harness (any MCP client)
        |
        v
remote-server-mcp / disk-health-mcp        tool layer (thin)
        |
        v
server-management-lib                      policy + SSH + HTTP clients
        |
        v
target host (Docker, smartctl, InfluxDB, Prometheus)
```

Constraints that changed since the original design:

- No local OpenAI-compatible inference server; the harness is now `pi` (and potentially
  Claude Code, Codex, Cursor, opencode). Everything Qwen-specific must go.
- The MCP server should be installable and runnable from anywhere (`uvx`), not only from
  a repo checkout with a `cwd`.
- MCP SDK 2.x is current; the projects still import the removed `FastMCP` API.

## 2. Verified findings

### P0 — broken or dangerous now

1. DHM rewrites its own source at startup (`smartdb.refresh_if_stale`). The rewrite drops
   `SEAGATE_COMPOSITE = {1, 7, 10}`, which breaks `smart_parser` and currently leaves 2
   failing tests and a dirty worktree. It also downloads unpinned code from GitHub master
   and writes it into the import path.
2. `mcp>=1.0.0` with no upper bound. PyPI now serves `mcp` 2.3.0, where
   `mcp.server.fastmcp` raises `ModuleNotFoundError`; `FastMCP` was renamed `MCPServer`.
   Fresh installs (pip, `uvx`, `uv sync` without the lock) crash at import.
3. Config discovery is `Path(__file__).parent.parent.parent / "config.yaml"`. Installed as
   a wheel this resolves to `site-packages`, so the server silently falls back to
   `root@localhost` defaults. `.env.example`, `MCP_LOG_LEVEL` and all `SSH_*` variables are
   advertised but never read. No `--config` flag, no XDG path.
4. Host key verification is disabled (`known_hosts=None` in `SSHManager.connect`).
5. Console entry points (`remote-server-mcp`, `disk-health-mcp`) point at an `async def
   main`, so the generated wrapper calls a coroutine and never runs the server. Only
   `python -m ...` works.
6. `services_path` is configurable in `SecurityValidator` but ignored by
   `SSHManager.check_service_exists` and several RSM tools (hardcoded `/srv`).
7. `get_service_status` puts `--format` after `--` in `docker stats`, so Docker treats it
   as a container name (resource-usage section always errors).
8. `get_nvme_health` builds an InfluxDB SQL string from an unvalidated `device` argument
   before calling `validate_device_name` (DB-level injection).
9. The documented "whitelist" command policy is actually a blacklist with a permissive
   fall-through (`is_command_safe` returns `True` for anything not matching dangerous
   substrings or disk prefixes). Not directly exploitable today, but it is not the
   advertised control. `allow_generic_commands` is never read.

### P1 — serious bugs and weak points

1. PromQL validation blocks `"`, `'`, `>`, `<`, so label matchers and comparisons are
   impossible; the blacklist is meaningless for an HTTP API anyway.
2. File paths are validated by calling `Path.resolve()` on the MCP host for a remote path;
   remote symlinks are not resolved and a local `/srv` symlink changes behavior.
3. Unbounded output from files and logs (no byte cap, no ANSI stripping) → context flood
   and prompt injection surface.
4. DHM reconnects SSH on every tool call, and `get_full_disk_report` does one handshake per
   disk.
5. `smart_parser` reads `smartcapable`/`smart_enabled` instead of `smart_support`, treats a
   missing `smart_status` as `FAILED`, and flags `value <= thresh` with `thresh == 0` as
   critical.
6. Dead asyncssh ML-KEM patch: `asyncssh.kex.client_kex_algorithms` does not exist in
   2.22+, so the patch is a silent no-op. `asyncssh` is unbounded in SML.
7. Config keys that do nothing: `prometheus.query_timeout`, `influxdb.query_limit`
   (sent as a non-documented body field), `security.allow_generic_commands`,
   `MCP_LOG_LEVEL`. The InfluxDB endpoint whitelist is tautological (hardcoded path).
8. No tests for RSM tool command construction; bypass tests contain no-op assertions;
   DHM coverage gate is 44%; RSM has no `pytest-cov`.
9. Packaging: git dependency without a tag/rev in `pyproject`, no `py.typed`, no CI,
   three drifting copies of `check_md_links.py`, duplicated `.qwenignore`, stale `build/`
   directory in SML, unused `pydantic` dependency, no `LICENSE` file in SML.

### P2 — structure and generalization

1. Consolidate the three repos into one `uv` workspace monorepo (see section 5) or, if
   keeping separate repos, publish SML 0.2.0 and use workspace/path overrides.
2. Replace shell string construction with an operation catalog executed via
   `shlex.join`, and use SFTP for remote file reads/lists.
3. Harness-agnostic docs and packaging: remove all Qwen artifacts, add pi / Claude Code /
   Codex / Cursor / opencode snippets, support `uvx`, structured outputs and tool
   annotations, optional streamable HTTP transport, optional local executor.
4. Optional: multi-target config, container runtime adapter (docker/podman), compose
   deployment operations with explicit confirmation, audit log, rate limits.

## 3. P0 work items

- [x] **P0.1 DHM self-rewrite**
  - Restore `src/disk_health_mcp/smartdb.py` from HEAD.
  - Remove `refresh_if_stale` from `smartdb.py`, the call in `server.main()`, and the now
    dead copy in `scripts/generate_smartdb.py`.
  - Regression tests: `SEAGATE_COMPOSITE` is `{1, 7, 10}`, `SEAGATE_COMPOSITE_ATTRS`
    includes them, generated module keeps the constant, no auto-refresh symbol.
- [x] **P0.2 MCP SDK 2.x**
  - Depend on `mcp>=2.3,<3` in both MCP servers.
  - Migrate `FastMCP` → `mcp.server.mcpserver.MCPServer`.
  - Update anything reaching into `_tool_manager`; verify `uv sync` from scratch.
- [x] **P0.3 Config discovery, env, logging**
  - SML: `resolve_config_path()` and `load_config(..., env_var=, app_name=, required=)`,
    deep merge over `DEFAULT_CONFIG`, env overrides, optional `.env` next to the config,
    `ConfigNotFoundError`.
  - Servers: `--config` flag, `$REMOTE_SERVER_MCP_CONFIG` / `$DISK_HEALTH_MCP_CONFIG`,
    XDG path, fail fast in `main()` when no config was found.
  - Wire `MCP_LOG_LEVEL`; move `logging.basicConfig` out of import time.
  - Fix console entry points to a sync `cli()` wrapper that runs `asyncio.run(main())`.
- [x] **P0.4 SSH hardening**
  - Verify host keys by default (`~/.ssh/known_hosts`), configurable/disable-able with a
    warning.
  - Use ssh-agent / `~/.ssh/config` when no key or password is configured; only pass
    explicit connection options when configured.
- [x] **P0.5 Consistency and injection fixes**
  - Pass `services_path` through `SSHManager.check_service_exists` and all RSM tools.
  - Fix `docker stats` argument order; quote constructed paths with `shlex.quote`.
  - Validate the NVMe device before any InfluxDB query.

Acceptance for P0: all three test suites green, `ruff`/`ty` clean, fresh install of both
MCP servers importable with `mcp` 2.3.x, no startup network access in DHM, no hardcoded
`/srv` left in tool command construction.

### P0 completion evidence (2026-10-17)

- SML: 131 tests, 93% coverage; RSM: 151 unit tests + 17 integration tests (opt-in);
  DHM: 60 tests. `pre-commit run --all-files` passes in all three repos.
- MCP SDK is now `mcp>=2.3,<3` (lock: 2.3.0) and both servers use `MCPServer`.
- Console entry points work: `remote-server-mcp --help` / `disk-health-mcp --help`;
  a missing config exits 2 with an actionable message.
- DHM no longer performs any network access at startup and `smartdb.py` is stable.
- Both apps temporarily depend on the sibling checkout via `[tool.uv.sources]`
  (`path = "../server-management-lib"`). Remove this override when SML is released.
- The local `~/.ssh/known_hosts` contains one legacy DSA entry that modern
  cryptography rejects. The loader now keeps verification enabled and skips only
  the unreadable lines (warning per skipped entry). Consider a single summary log.
- RSM integration tests are excluded by default (`addopts = "-m 'not integration'"`);
  run them with `uv run pytest -m integration`.

Remaining P0-adjacent follow-ups:

- [ ] Documentation still references Qwen and the old config resolution.
- [ ] Operation catalog / output caps / command policy (P1).
- [ ] SML release and removal of the path override.

## 4. P1 backlog

- [x] Operation catalog + `shlex.join`; SFTP for file reads and listings.
- [x] Output caps, ANSI stripping, audit log, tool annotations (read-only/destructive).
- [x] Replace PromQL/SQL character blacklists with read-only semantics (single SELECT
      parser; Prometheus HTTP API is already read-only).
- [x] Fix `smart_parser` flags/health/severity, add captured `smartctl -j` fixtures,
      raise DHM coverage gate.
- [x] Remove the dead asyncssh ML-KEM patch and bound `asyncssh<3` (done in P0).
- [x] Persistent SSH connection in DHM (shared lazy connection, no per-call handshake).
- [ ] Drop unused `pydantic` or use it for config validation.
- [x] RSM command-construction unit tests.
- [~] CI workflow (3.11–3.13) and `py.typed` (done). Shared pre-commit config and release
      tags still depend on the workspace/PyPI decision (section 5).

### P1 completion evidence (2026-10-17)

- SML: 157 tests, 92% coverage. RSM: 143 unit + 17 integration tests, 63% coverage.
  DHM: 65 tests, 57% coverage (gate raised 44% → 55%).
- New SML modules: `output.py` (ANSI/control stripping + byte caps), `audit.py`
  (JSONL, best effort, redaction), `py.typed`.
- SFTP is now used for service file reads/listings; paths are resolved on the remote
  side and checked against the real path of the service base directory.
- Query validation is semantic: `sqlparse` enforces a single read-only statement;
  PromQL accepts label matchers, quotes and comparison operators. Shell metacharacters
  are no longer treated as shell injection because queries go over HTTP.
- RSM commands come from `operations.py` (argv + `shlex.join`), with read-only /
  destructive tool annotations. DHM has read-only/write annotations too.
- Audit logging is opt-in (`audit.enabled`), output cap defaults to 64 KiB
  (`output.max_bytes`), and the HTTP clients honor `prometheus.query_timeout`.
- CI workflows were added to all three repos. The app workflows check out
  `server-management-lib` as a sibling until the workspace/PyPI step.

## 5. Structure decision (P2, recommended)

Single repo, `uv` workspace, one lock and one CI:

```text
server-mcp/
├── pyproject.toml                 # workspace root, shared tooling config
├── uv.lock
├── .github/workflows/ci.yml
├── docs/
├── scripts/check_md_links.py
├── packages/server-management-lib/
├── apps/remote-server-mcp/
└── apps/disk-health-mcp/
```

```toml
[tool.uv.workspace]
members = ["packages/*", "apps/*"]

[tool.uv.sources]
server-management-lib = { workspace = true }
```

Preserve history with `git filter-repo --to-subdirectory-filter` per repo before merging.
Keep the two MCP servers separate (least privilege: DHM read-only, RSM destructive), share
the library and the target config schema.

Alternative if the repos must stay separate: tag SML `v0.2.0`, publish it to PyPI (name
`server-management-lib` is currently free), depend on `server-management-lib>=0.2,<0.3`,
and use `[tool.uv.sources]` path/editable overrides for local development.

## 6. Generalization checklist (P2)

- [ ] Delete `.qwen/` references, `.qwenignore`, Qwen/vLLM mentions in docs.
- [ ] Document pi (`pi mcp add ...`), Claude Code (`.mcp.json`), Codex (TOML),
      Cursor, opencode.
- [ ] `uvx`-friendly packaging and config resolution; document `uvx --from git+...`.
- [ ] Structured outputs and `ToolAnnotations`; optional streamable HTTP transport.
- [ ] Optional local executor (no SSH when running on the target host).
- [ ] Container runtime adapter (`docker` / `podman`), compose operations with confirm.

## 7. Resume instructions

1. Read section 3; each checkbox lists its acceptance.
2. Run the verification suite for each repo:

```bash
cd ~/code/server-management-lib && uv sync --all-extras && uv run pytest -q && uv run ruff check . && uv run ty check
cd ~/code/remote-server-mcp   && uv sync --all-extras && uv run pytest -q && uv run ruff check . && uv run ty check
cd ~/code/disk-health-mcp     && uv sync --all-extras && uv run pytest -q && uv run ruff check . && uv run ty check
```

1. Remember: both MCP apps install SML from the sibling checkout via
   `[tool.uv.sources]` (previously they installed from GitHub). After changing SML, run
   `uv sync` in each app (or switch to the workspace in section 5).
2. Run the full hook suite before committing:

```bash
env -u VIRTUAL_ENV pre-commit run --all-files
```

## 8. Decision log

- 2026-10-17: Migrate to MCP SDK 2.x (`MCPServer`) instead of pinning `<2`.
- 2026-10-17: Remove runtime SMART DB refresh entirely; generation stays an explicit
  offline script.
- 2026-10-17: Require an explicit/existing config at runtime; tests may import with
  defaults, but the server refuses to start on `root@localhost` defaults.
- 2026-10-17: Host key verification on by default; disabling requires an explicit option.
  Legacy/unparseable known_hosts lines are skipped individually, not the whole file.
- 2026-10-17: Both MCP apps use `[tool.uv.sources]` with the sibling SML checkout as a
  development override until SML is released (or the workspace in section 5 is done).
- 2026-10-17: RSM integration tests are opt-in (`-m integration`) so the default suite and
  CI do not depend on a reachable server/database.
