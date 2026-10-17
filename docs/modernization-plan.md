# Modernization Plan and Backlog

Current tracking document for the Server MCP suite. It replaces the earlier audit-style plan;
the full findings remain available in git history.

- **Status:** `0.2.0` implemented locally; not pushed or published
- **Last updated:** 2026-10-17
- **Legend:** `[ ]` todo, `[~]` partial, `[x]` done, `[!]` blocked

## 1. Context

Server MCP is a security-first proxy between an autonomous agent and a Linux host. Two MCP
servers (`remote-server-mcp`, `disk-health-mcp`) sit on top of a shared library
(`server-management-lib`). The suite is now a uv workspace monorepo with one lockfile, one
pre-commit configuration and one CI workflow.

The design constraints are:

- No generic command execution; only a fixed, validated tool catalog.
- SSH by default, with host key verification; a shell-free local executor as an alternative.
- File access confined to the configured service directory, verified on the target.
- Read-only database access and bounded output.
- Harness-agnostic documentation and packaging.

## 2. Completed in 0.2.0

### 2.1 Core security and correctness

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
- [x] Output sanitization (ANSI/control characters) and a 64 KiB cap.
- [x] Opt-in JSONL audit log with secret redaction.
- [x] `ToolAnnotations` on all 24 tools (read-only vs destructive/write).
- [x] Semantic SQL validation (`sqlparse`, single `SELECT`) and usable PromQL validation.
- [x] SMART parsing fixes (`smart_support`, `smart_status`, zero thresholds, device type).
- [x] Persistent SSH connection in DHM; dead asyncssh ML-KEM patch removed.
- [x] Unused `pydantic` dependency removed.

### 2.2 Structure, packaging and docs

- [x] uv workspace monorepo with imported history, one `uv.lock`, one pre-commit config,
      one CI workflow and shared ruff/ty configuration.
- [x] `py.typed` in all packages; coverage gates (90% / 60% / 55%).
- [x] Harness-agnostic README, `AGENTS.md`, `CLAUDE.md`, docs and examples for pi,
      Claude Code, Codex, Cursor and opencode.
- [x] `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/releasing.md`.
- [x] Qwen/vLLM artifacts and duplicated per-repo tooling removed.

## 3. Open work

### 3.1 Deferred from the original plan

- [ ] **Structured tool outputs.** Tools return formatted strings; clients cannot consume
      typed results. Return pydantic models/dicts (and keep a readable text fallback) using
      `MCPServer` structured output.
- [ ] **Streamable HTTP transport.** Only stdio is implemented. Add an opt-in
      `--transport streamable-http` path (loopback/token protected) for clients that cannot
      launch a process.
- [ ] **Container runtime adapter.** `docker` is hardcoded in
      `apps/remote-server-mcp/src/remote_server_mcp/operations.py`. Add
      `container_runtime: docker|podman|nerdctl` and build operations from the selected
      runtime.
- [ ] **Compose deployment operations.** There is no `compose up/down/pull/ps`. Add a small,
      explicit set of compose operations scoped to `services_path/<service>/`, with a
      dry-run or confirmation argument.
- [ ] **Rate limiting and destructive-action confirmation.** `restart_service` and
      `stop_service` execute immediately. Add a `confirm` parameter or MCP elicitation, and
      a simple per-session rate limit.

### 3.2 Partial implementations to finish

- [ ] **`is_command_safe` is still a permissive blacklist.**
      `packages/server-management-lib/src/server_management_lib/security.py` falls through
      to `return True` for unknown commands, and `security.allow_generic_commands` is never
      read. RSM is protected by its operation catalog; DHM still relies on this policy.
      Either convert DHM to an operation catalog and delete the fall-through, or make the
      policy explicitly allowlist-based.
- [ ] **Local path resolution in `validate_service_file_path`.**
      `security.py` still calls `Path.resolve()` on the MCP host for a remote path. The SFTP
      layer now performs the authoritative remote `realpath` check, but a local `/srv`
      symlink can still change or break the constructed path. Build the remote path
      lexically with `PurePosixPath` and leave resolution to the executor.
- [ ] **Single response cap for composite/list results.**
      `execute_safe_command` caps each command, but `list_service_files`,
      `get_service_status`, `get_full_disk_report` and directory listings can concatenate
      multiple capped outputs or return a very large listing. Apply a final
      `sanitize_output` cap to the complete tool response.
- [ ] **Audit HTTP queries.**
      The audit log covers commands, blocked operations and file access. InfluxDB and
      Prometheus queries are not recorded. Pass an `AuditLogger` to the HTTP clients and log
      query metadata (length/hash, database, status, duration) without storing secrets.
- [ ] **DHM operation catalog.**
      Disk-health commands are inline strings in
      `apps/disk-health-mcp/src/disk_health_mcp/server.py`. They are built from validated
      device names, but moving them into `operations.py` (or a shared catalog) makes the
      construction model consistent with RSM.
- [ ] **CI markdown enforcement.**
      `.github/workflows/ci.yml` runs ruff, format, ty and pytest, but not `pymarkdown` or
      `check-md-links`. Add both steps (or run `pre-commit` in CI) so documentation checks
      are enforced remotely.
- [ ] **Known_hosts summary logging.**
      The loader logs up to three skipped entries plus a count. Aggregate skipped entries
      into one summary warning per file.

### 3.3 Release and migration

- [ ] **Create the remote repository.** Recommended: new `elmuz/server-mcp`; archive the
      three old repositories after adding a “moved” notice. Commands are in
      `docs/releasing.md`.
- [ ] **Push `main` and create the `v0.2.0` tag.** No remote or tag exists yet.
- [ ] **Publish to PyPI.** `server-management-lib` first, then the two apps. All three names
      are currently free. Until then `uvx remote-server-mcp` does not work; only
      `uv run` from the workspace does.
- [ ] **Archive the old repositories.** `remote-server-mcp`, `disk-health-mcp` and
      `server-management-lib` are still live and could be mistaken for the current code.
- [ ] **Make the CI badge live.** The README badge points at the future repository.
- [ ] **Prerequisite:** `gh` is not installed in the development environment; use it or the
      GitHub web UI for the push/archive steps.

### 3.4 Community and packaging polish

- [ ] Add `[project.urls]`, `classifiers`, `keywords` and `authors` to the package metadata.
- [ ] Add `CODE_OF_CONDUCT.md`, issue templates, a pull-request template and `CODEOWNERS`.
- [ ] Consider Python 3.14 in the CI matrix (currently 3.11–3.13).
- [ ] Consider a short demo/screenshot section in the README once the repository is public.

## 4. Verification snapshot (0.2.0)

From a clean clone:

| Check | Result |
|---|---|
| `uv sync --locked --all-packages --all-extras` | passes |
| `server-management-lib` tests | 177 passed, 92% coverage |
| `remote-server-mcp` tests | 144 passed (+17 integration opt-in), 61% coverage |
| `disk-health-mcp` tests | 65 passed, 57% coverage |
| `ruff check`, `ruff format --check`, `ty check` | pass |
| `pre-commit run --all-files` | all hooks pass |
| `uv build --all-packages` | all three wheels/sdists build, `py.typed` included |

## 5. Decisions

- Monorepo with a uv workspace; the two MCP servers stay separate for least privilege.
- History imported with `git subtree` (merge commit per repository) because
  `git-filter-repo` was unavailable.
- Recommended remote is a new `elmuz/server-mcp` repository; reusing/renaming
  `remote-server-mcp` is documented as an alternative.
- Local executor instead of multi-target support (explicit user decision).
- No runtime SMART database refresh; generation is an explicit offline script.

## 6. Resume instructions

1. Pick an item from section 3; each checkbox names the file or area to change.
2. Run the full suite:

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
```

1. Update this file and `CHANGELOG.md` when an item is completed.
2. For release steps, follow `docs/releasing.md`.
