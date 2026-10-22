# Server MCP — Agent Instructions

## Project overview

**Server MCP** is a security-first MCP suite for managing a home or remote Linux server.
It provides AI assistants with controlled, auditable operations for Docker services and disk
health without exposing credentials or allowing arbitrary commands.

This is a **uv workspace monorepo**:

```text
apps/remote-server-mcp/          MCP server: Docker/SSH and host-service operations (22 tools)
apps/disk-health-mcp/            MCP server: SMART/NVMe/ZFS/mdadm/SnapRAID diagnostics (13 tools)
packages/server-management-lib/  Security policy, executors, config, HTTP clients
```

The two MCP servers are thin tool layers over `server-management-lib`. Security logic lives
in the library, not in the tool modules.

## Development workflow

### Setup

```bash
uv sync --all-packages --all-extras
pre-commit install
```

### Commands

```bash
# All tests (per package, because each has its own coverage gate)
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q

# Integration tests (real host/database; opt-in)
uv run --directory apps/remote-server-mcp pytest -q -m integration

# Lint / format / types
uv run ruff check .
uv run ruff format --check .
uv run ty check

# Full hook suite (what CI and commits run)
env -u VIRTUAL_ENV pre-commit run --all-files
```

If `VIRTUAL_ENV` is set to another project, always run hooks with
`env -u VIRTUAL_ENV`.

### Pre-commit

Hooks: ruff (lint + format), ty, pytest for each package, pymarkdown, markdown link check.
All must pass before committing. Never commit on a broken state.

## Architecture rules

### Executors

`server-management-lib` has two executors behind one interface:

- `SSHManager` — asyncssh, host key verification by default, SFTP for files.
- `LocalExecutor` — runs on the MCP host, argv execution without a shell.

`create_executor(config, security)` selects one from `config["executor"]` (`ssh` or
`local`). Tools must depend on the executor interface, never on SSH specifics.

### Operation catalog

Both MCP servers keep their host commands in an `operations.py` catalog:

- `apps/remote-server-mcp/src/remote_server_mcp/operations.py`
- `apps/disk-health-mcp/src/disk_health_mcp/operations.py`

They are typed argv templates rendered with `shlex.join`. Do **not** add string-concatenated
shell commands. Avoid pipes and shell operators; filter output in Python instead. The shared
`SecurityValidator.is_command_safe()` policy is a strict argv allowlist: unknown executables
and hand-built shell syntax are rejected. `security.allow_generic_commands` is ignored.

`remote-server-mcp` builds its container operations from `build_container_catalog()` using
`container_runtime` (`docker`, `podman` or `nerdctl`). Compose operations are scoped to
`services_path/<service>` and only `ps`, `pull`, `up -d` and `down` with fixed arguments are
allowed by the policy.

### Security requirements

Every tool MUST:

1. Validate service names with `security.validate_service_name()`.
2. Validate file paths with `security.validate_service_file_path()`.
3. Use the executor (`execute_safe_command`, `read_remote_file`, `list_remote_dir`) rather
   than `subprocess`, `os.system` or raw asyncssh calls.
4. Not expose credentials, tokens or sensitive files.
5. Not allow command injection. Prefer argv vectors over strings.
6. Declare MCP `ToolAnnotations` (`read_only_hint`, `destructive_hint`).
7. Require `confirm=true` for restart/stop/compose actions and pass state-changing calls
   through the shared `RateLimiter`; never execute on a missing confirmation.
8. Return a readable string (or `ToolOutput` with `data`) and register the tool through
   `structured_tool(...)` so clients receive a `ToolResponse` as structured content.

Reads go through SFTP or the local filesystem with a `realpath` check against the service
base directory. Output is sanitized and capped by the library; do not bypass it.

### Adding a tool

```python
@structured_tool(READ_ONLY)
async def my_tool(service: str) -> str:
    """Describe exactly what the tool does and what it cannot do."""
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"
    command = catalog.my_operation.render(service=service)
    return await executor.execute_safe_command(command)
```

Add a command-construction test (mock the executor and assert the argv) and, for
security-relevant behavior, a test in `tests/test_security*.py`.

### Configuration

Config resolution: `--config` → env var (`REMOTE_SERVER_MCP_CONFIG` /
`DISK_HEALTH_MCP_CONFIG`) → XDG path → `./config.yaml`. Environment variables override YAML;
`.env` next to the config is loaded. Never add a code path that silently falls back to
`root@localhost`.

## Testing philosophy

- Unit tests must not require a real host or network.
- Integration tests use the `integration` marker and are excluded by default.
- Coverage gates: lib 90%, remote 60%, disk 65%. Raise them when adding tests, never lower.
- Security tests should assert the behavior we want, not merely document current behavior.

## Documentation

- Root docs are harness-agnostic. Do not add client-specific setup outside
  `docs/harnesses.md`.
- Keep `README.md`, `AGENTS.md`, `docs/configuration.md`, `docs/tools.md` and
  `docs/security-model.md` in sync with the code.
- Markdown is linted and relative links are checked by pre-commit.

## What not to do

- Do not add a generic `exec_command`/`run_command`/`shell` tool.
- Do not use `shell=True`, `os.system`, `subprocess` with a shell, or string-formatted
  commands built from user input.
- Do not disable host key verification by default.
- Do not return unbounded output to the model.
- Do not commit `config.yaml`, `.env`, keys or tokens.
- Do not add Qwen-, vLLM- or client-specific assumptions to code or docs.

## Reference

- [README](README.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/configuration.md](docs/configuration.md)
- [docs/tools.md](docs/tools.md)
- [docs/development.md](docs/development.md)
- [docs/releasing.md](docs/releasing.md)
- [docs/modernization-plan.md](docs/modernization-plan.md) — single source of truth for the backlog and live-deployment findings
