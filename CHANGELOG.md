# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic
versioning.

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
