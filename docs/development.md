# Development

## Setup

```bash
uv sync --all-packages --all-extras
pre-commit install
```

The workspace has one virtual environment and one lockfile. Each package keeps its own
pytest and coverage configuration.

## Commands

```bash
# Run one package's tests
uv run --directory packages/server-management-lib pytest -q
uv run --directory apps/remote-server-mcp pytest -q
uv run --directory apps/disk-health-mcp pytest -q

# Integration tests (real host/database; excluded by default)
uv run --directory apps/remote-server-mcp pytest -q -m integration

# Lint, format, types
uv run ruff check .
uv run ruff format --check .
uv run ty check

# Full hooks
env -u VIRTUAL_ENV pre-commit run --all-files
```

`uv run --directory` keeps each package's relative coverage paths and pytest options
working while using the shared workspace environment.

## Coverage gates

| Package | Gate |
|---|---|
| `server-management-lib` | 90% |
| `remote-server-mcp` | 60% |
| `disk-health-mcp` | 65% |

Raise a gate when adding tests; do not lower it to make a change pass.

## Repository layout

```text
apps/remote-server-mcp/src/remote_server_mcp/
├── server.py          tools and input validation
└── operations.py      typed argv templates

apps/disk-health-mcp/src/disk_health_mcp/
├── server.py          tools and formatting
├── operations.py      typed argv templates
├── smart_parser.py    smartctl JSON/text parsing
└── smartdb.py         generated SMART attribute database

packages/server-management-lib/src/server_management_lib/
├── security.py        validation and command/query policy
├── operations.py      shared Operation template
├── base.py            executor primitives
├── ssh_manager.py     SSH + SFTP executor
├── local_executor.py  local executor
├── executor.py        factory and protocol
├── config.py          config resolution and env overrides
├── output.py          sanitization and limits
├── audit.py           JSONL audit log
└── http_clients.py    InfluxDB and Prometheus clients
```

## Adding a tool

1. Add the operation to the relevant app's `operations.py` (remote server or disk health).
   Never concatenate shell strings, and keep shell operators out of the template.
2. Validate every argument before use.
3. Add `ToolAnnotations` matching the safety level.
4. Add a command-construction or handler test with the executor mocked.
5. Update [tools.md](tools.md).
6. Run the full hook suite.

## Style

- Python 3.11+, type hints on public functions.
- Ruff lint/format; line length 88.
- Prefer small pure helpers for parsing and validation.
- Keep user-facing error messages actionable.
- No client- or model-specific assumptions in code or docs.

## Markdown

Markdown is linted with pymarkdown (line length 200) and relative links/anchors are checked
by `scripts/check_md_links.py`. Both run in pre-commit.

## CI

`.github/workflows/ci.yml` runs on Python 3.11, 3.12, 3.13 and 3.14: locked sync, ruff,
format check, ty, all three test suites, pymarkdown and the markdown link check.

## Releasing

See [releasing.md](releasing.md).
