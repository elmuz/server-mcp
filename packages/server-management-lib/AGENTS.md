# Server Management Library - Project Context

> Roadmap / modernization plan: `~/code/remote-server-mcp/docs/modernization-plan.md`

## Project Overview

**server-management-lib** is the **central shared security layer** for multiple server management MCP (Model Context Protocol) servers.

### Architecture

This library is **not** an MCP server itself. It is a dependency that MCP servers import to get:
- validated SSH execution with command whitelisting
- input sanitization (commands, queries, paths, device/service names)
- YAML configuration loading with sensible defaults
- read-only HTTP clients for InfluxDB v3 and Prometheus

**How it works:**

```
┌─────────────────────────────┐
│   disk-health-mcp server    │
├─────────────────────────────┤
│   remote-server-mcp server  │  ← MCP servers (separate repos)
├─────────────────────────────┤
│   host-info-mcp server      │
└──────────────┬──────────────┘
               │  import
┌──────────────▼──────────────┐
│   server-management-lib     │  ← THIS library: shared security core
│  (SSH, validation, config)  │
└─────────────────────────────┘
               │
┌──────────────▼──────────────┐
│      Remote Server / APIs   │
└─────────────────────────────┘
```

Each MCP server focuses on its **domain-specific tools** (e.g. docker commands, disk metrics, service management) and delegates **all security concerns** to this library:
- The library decides what commands are safe, not the MCP server
- The library validates all inputs (device names, service names, file paths, queries)
- The library manages SSH connections with strict policies
- MCP servers just call the library's validated methods

### Design Principles

1. **Single source of truth for security** — all security logic lives here, not duplicated across MCP servers
2. **Whitelist over blacklist** — explicitly allow safe commands/patterns, reject everything else
3. **Defense in depth** — multiple validation layers (input sanitization + command whitelist + SSH restrictions + endpoint whitelisting)
4. **MCP servers are thin wrappers** — they expose tools to the AI, the library enforces safety

## Tech Stack

| Category | Tool/Library |
|----------|-------------|
| Language | Python 3.11+ |
| Package manager | `uv` |
| Build system | setuptools |
| Async SSH | asyncssh >= 2.14.0 |
| HTTP client | aiohttp >= 3.9.0 |
| Config parsing | PyYAML >= 6.0 |
| Data validation | Pydantic >= 2.0.0 |
| Testing | pytest >= 8.0.0 |
| Linting | ruff >= 0.9.0 |
| Type checking | ty |
| Git hooks | pre-commit >= 4.0.0 |
| Markdown linting | pymarkdownlnt >= 0.9.0 |

## Project Structure

```
server-management-lib/
├── src/server_management_lib/
│   ├── __init__.py          # Public API exports
│   ├── config.py            # YAML config loader with defaults
│   ├── security.py          # Input validation & sanitization
│   ├── ssh_manager.py       # Async SSH connection manager
│   └── http_clients.py      # InfluxDB & Prometheus HTTP clients
├── tests/
│   ├── conftest.py          # Shared pytest fixtures
│   ├── test_config.py       # Configuration loading tests
│   ├── test_security.py     # Security validation tests
│   ├── test_ssh_manager.py  # SSH manager tests (mocked)
│   └── test_http_clients.py # HTTP client tests (mocked)
├── scripts/
│   └── check_md_links.py    # Markdown link checker utility
├── pyproject.toml           # Project configuration
├── uv.lock                  # Dependency lock file
├── .pre-commit-config.yaml  # Pre-commit hooks
└── .pymarkdown              # Markdown linter configuration
```

## Module Details

### `config.py`
- Loads YAML configuration files
- Provides `DEFAULT_CONFIG` with sections for `ssh`, `security`, `influxdb`, `prometheus`, and `host`
- Generic command execution is **disabled by default** (`allow_generic_commands: false`)
- Function: `load_config(config_path: Path) -> dict`

### `security.py`
Core security validations:

| Method | Purpose |
|--------|---------|
| `validate_device_name()` | Block device names (sda, nvme0n1, etc.) |
| `validate_service_name()` | Service names (alphanumeric + hyphens/underscores) |
| `validate_service_file_path()` | Prevent path traversal in /srv/{service}/ |
| `sanitize_search_pattern()` | Strip shell injection from grep patterns |
| `validate_influxdb_query()` | SELECT-only enforcement for SQL |
| `validate_prometheus_query()` | Shell injection prevention for PromQL |
| `is_command_safe()` | Command whitelist + dangerous pattern blocking |

Design philosophy: **whitelist specific safe operations, don't try to blacklist dangerous ones**.

### `ssh_manager.py`
- Uses `asyncssh` for async SSH connections
- Patches asyncssh to handle ML-KEM algorithm errors gracefully
- Commands must pass `SecurityValidator.is_command_safe()` before execution
- Supports async context manager (`async with SSHManager(...)`)
- No generic command execution - only pre-validated safe commands

### `http_clients.py`
- **InfluxDBClient**: Read-only SQL queries via `/api/v3/query_sql` with endpoint whitelisting
- **PrometheusClient**: Instant queries via `/api/v1/query` and scrape target inspection
- Both include built-in security validation and user-friendly error messages

## Building and Running

### Install dependencies

```bash
uv sync
```

### Run tests

```bash
uv run pytest tests/ -v
```

Tests **must** maintain 90%+ code coverage. The pre-commit hook will fail if coverage drops below 90%.

### Run linter

```bash
uv run ruff check .
uv run ruff format .
```

### Run type checker

```bash
uv run ty check
```

### Run pre-commit hooks (all checks)

```bash
uv run pre-commit run --all-files
```

**The pre-commit suite runs automatically before each commit and includes:**
- Ruff linting and formatting
- Type checking (ty)
- **Tests with 100% coverage enforcement**
- Markdown linting and link checking

### Check markdown links

```bash
uv run python scripts/check_md_links.py
```

### Markdown linting

```bash
uv run pymarkdown -c .pymarkdown fix
```

## Testing Conventions

- Tests are organized by module: one test file per source module
- `conftest.py` provides shared fixtures (configs, security validator)
- Test classes are organized by component (e.g., `TestDeviceNameValidation`, `TestCommandSafety`)
- SSH and HTTP operations are **mocked** - no real network connections in unit tests
- Async tests use `asyncio.run()` to execute coroutines
- Integration tests are marked with `@pytest.mark.integration` (for real SSH connections)
- Test file pattern: `test_*.py`, classes: `Test*`, functions: `test_*`

## Code Style

- Line length: **88 characters** (matching Black formatter)
- Imports sorted by **isort** with `known-first-party = ["server_management_lib"]`
- Linting rules: pycodestyle (E/W), pyflakes (F), isort (I), pep8-naming (N), pyupgrade (UP), ruff-specific (RUF)
- Long lines allowed in tests (`E501` ignored for `tests/**`)
- Target Python version: 3.11

## Development Workflow

### After Coding a Feature

**Always run the full pre-commit suite before committing:**

```bash
uv run pre-commit run --all-files
```

This ensures:
- ✅ All code passes linting and formatting checks
- ✅ Type checking passes (no type errors)
- ✅ **Tests pass with 90%+ coverage** (new code must be tested)
- ✅ Markdown files are properly formatted
- ✅ All links are valid

### Before Committing

**Verify that documentation reflects code changes:**

1. **Check if docs need updating:**
   - If code behavior changes → update relevant docs
   - If available tools/methods change → update API docs
   - If error messages change → update error message docs
   - If configuration options change → update config docs

2. **Update docs as part of the same commit:**
   - Do NOT commit code and doc updates separately
   - Code changes and their documentation should be atomic
   - This prevents stale docs from accumulating

3. **What to check:**
   - `AGENTS.md` - module details, security model, validation layers
   - `README.md` - public API, usage examples
   - Docstrings - function signatures, parameters, return types
   - Test descriptions - if test behavior changes

**Example commit checklist:**

```
☐ Code passes all pre-commit hooks
☐ Tests cover new code (90%+ coverage enforced)
☐ Docstrings updated for changed functions
☐ AGENTS.md updated if API/behavior changed
☐ README.md updated if public interface changed
```

### Coverage Requirement

**100% code coverage is the goal, but 90%+ is acceptable for edge cases.** The pre-commit hook enforces 100%, but in practice:

**What must be covered (100%):**
- All business logic
- All validation paths
- All error handling paths that can be reasonably triggered
- All branches (if/else, try/except)

**Acceptable to exclude (with pragma: no cover):**
- Module-level initialization code that runs once on import
- Extremely rare edge cases requiring complex async mocking
- Integration-only code paths (marked with @pytest.mark.integration)

**What this means in practice:**
- Every function must have tests
- Every branch (if/else) must be tested
- Every error path must be tested when reasonably possible
- Mock external dependencies (SSH, HTTP) properly
- Use `# pragma: no cover` sparingly and only with justification

**Less important:**
- Markdown formatting / link checking scripts (utility, not core)
- Configuration defaults structure (simple, unlikely to change)
- Cosmetic changes to error messages

**This is the most important part of the library.** Every change to security-related code must be treated with extreme caution.

### Core Rules

1. **No generic command execution** — `allow_generic_commands` is `false` by default and should stay that way. Commands must pass the whitelist (`SAFE_COMMAND_PREFIXES`) or be blocked by dangerous pattern detection.
2. **Whitelist first** — when adding new safe commands, add them to `SAFE_COMMAND_PREFIXES`, never weaken the blacklist.
3. **Input validation is non-negotiable** — device names, service names, file paths, and queries must all be validated before any use.
4. **Defense in depth** — multiple independent validation layers. If one fails, others should still catch the attack.

### Validation Layers (in order)

| Layer | What it does | Where |
|-------|-------------|-------|
| Input sanitization | Regex validation of device/service names, path traversal blocking, unicode/encoded bypass detection | `security.py` |
| Command whitelist | Only pre-approved command prefixes allowed; dangerous patterns (`sudo`, `dd`, `wget`, shells...) always blocked | `security.py:is_command_safe()` |
| SSH restrictions | asyncssh connection with key/password auth, no shell access | `ssh_manager.py` |
| Endpoint whitelisting | InfluxDB admin/write endpoints blocked at HTTP level | `http_clients.py` |
| Query validation | SELECT-only for InfluxDB, shell injection blocking for PromQL | `security.py` |

### What to prioritize when working on this project

**Important (spend time, be careful):**
- Security validation logic (`security.py`)
- Command whitelist management (`SAFE_COMMAND_PREFIXES`)
- SSH connection handling (`ssh_manager.py`)
- Test coverage for security edge cases
- Path traversal / injection prevention patterns

**Less important:**
- Markdown formatting / link checking scripts (utility, not core)
- Configuration defaults structure (simple, unlikely to change)
- Cosmetic changes to error messages
