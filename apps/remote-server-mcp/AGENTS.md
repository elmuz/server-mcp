# Remote Server MCP — Agent Instructions

## Project Overview

**remote-server-mcp** is a security-first MCP (Model Context Protocol) server for managing remote servers via SSH. It provides AI assistants with controlled, safe operations for debugging services without exposing credentials or allowing dangerous commands.

This is a **thin MCP server layer** built on top of **server-management-lib** (a separate library that provides security validation, SSH management, and HTTP clients for InfluxDB/Prometheus).

## Architecture

```text
src/remote_server_mcp/          # This project
├── server.py                   # MCP server (13 tools)
└── __init__.py                 # Entry point

server-management-lib           # External dependency (GitHub)
├── security.py                 # SecurityValidator
├── ssh_manager.py              # SSHManager
├── http_clients.py             # InfluxDBClient, PrometheusClient
└── config.py                   # load_config, DEFAULT_CONFIG
```

## Development Workflow

### Quick Start

```bash
# Install with dev dependencies
uv sync --all-extras

# Install pre-commit hooks
pre-commit install
```

### Development Commands

```bash
# Run all tests
uv run pytest tests/ -v

# Security tests only
uv run pytest tests/test_security.py tests/test_security_bypass.py -v

# Database tests (unit + live integration tests)
uv run pytest tests/test_database_tools.py -v
uv run pytest tests/test_database_tools.py -v -k live   # live tests only

# Linting
uv run ruff check .

# Fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Type checking
uv run ty check

# Run all checks (what pre-commit does)
env -u VIRTUAL_ENV pre-commit run --all-files
```

### Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`:

- **ruff**: Linting and formatting
- **ty**: Type checking
- **pytest**: Run all tests
- **pymarkdown**: Markdown style/formatting
- **check-md-links**: Markdown link validation

Run manually:

```bash
env -u VIRTUAL_ENV pre-commit run --all-files
```

## Security Philosophy

**Zero-trust design:**
- ❌ NO generic command execution
- ✅ ONLY specific, validated operations
- 🔒 All paths restricted to `/srv/{service}/`
- 🛡️ Comprehensive input validation and sanitization

Security logic lives in **server-management-lib**, not in this project. The MCP server imports and uses it:

```python
from server_management_lib import SecurityValidator, SSHManager, load_config
```

See `README.md` and `docs/security-model.md` for full documentation.

## Quick Start (Server)

### 1. Install

```bash
uv sync --all-extras
```

### 2. Configure

```bash
cp config.example.yaml config.yaml
nano config.yaml  # Add your SSH details
```

### 3. Test

```bash
# Run all tests
uv run pytest tests/ -v
```

### 4. Use with Qwen Code

Add to `.qwen/settings.json`:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": ["run", "python", "-m", "remote_server_mcp.server"],
      "cwd": "/path/to/remote-server-mcp"
    }
  }
}
```

Then restart Qwen Code.

## Available Tools

| Tool | Purpose |
|------|---------|
| `list_services` | List services in `/srv/` |
| `get_service_logs` | Get Docker container logs |
| `get_service_status` | Check service status |
| `restart_service` | Restart container |
| `start_service` | Start container |
| `stop_service` | Stop container |
| `get_service_file` | Read service files |
| `list_service_files` | List service files |
| `search_service_logs` | Search logs |
| `get_server_health` | Server metrics |
| `query_influxdb` | Query InfluxDB v3 via SQL (read-only) |
| `query_prometheus` | Query Prometheus via PromQL |
| `get_prometheus_targets` | List Prometheus scrape targets |

## Testing

```bash
# All tests
uv run pytest tests/ -v

# Security tests only
uv run pytest tests/test_security.py tests/test_security_bypass.py -v

# With coverage (requires pytest-cov)
uv run pytest tests/ --cov=remote_server_mcp --cov=server_management_lib
```

**158 tests, 62% coverage** (as of last run).

## What is MCP?

**MCP (Model Context Protocol)** is an open standard for connecting AI assistants to external tools. Works with:
- Qwen Code ✅
- Claude Desktop ✅
- Any MCP client ✅

Learn more: [modelcontextprotocol.io](https://modelcontextprotocol.io)

## Development

### Adding New Tools

Add a decorated function in `server.py`:

```python
@mcp.tool()
async def my_new_tool(service: str) -> str:
    """Description of the tool."""
    if not security.validate_service_name(service):
        return "❌ Invalid service name"

    cmd = f"safe-command -- {service}"
    return await ssh_manager.execute_safe_command(cmd)
```

### Security Requirements

All tools MUST:
1. Validate service names with `security.validate_service_name()`
2. Validate file paths with `security.validate_service_file_path()`
3. Use `ssh_manager.execute_safe_command()` (never raw execution)
4. NOT expose sensitive data
5. NOT allow command injection

### Pre-commit Verification

**Every time you finalize a feature or bugfix, run the full check suite:**

```bash
env -u VIRTUAL_ENV pre-commit run --all-files
```

This runs all pre-commit hooks in order:

| Check | Tool | What it catches |
|-------|------|----------------|
| Lint | `ruff check` | Style errors, unused imports, ambiguous characters |
| Format | `ruff format` | Code formatting consistency |
| Types | `ty check` | Type mismatches, invalid assignments |
| Tests | `pytest` | Regressions, new test coverage |
| Markdown | `pymarkdown` | Formatting, heading duplicates, code block languages |
| Links | `check-md-links` | Broken relative links and anchors |

**All must pass before committing.** If any fail, fix the issues first — never commit on a broken state.

### Important: VIRTUAL_ENV

If you have `VIRTUAL_ENV` set to a different project (e.g., from PyCharm or another terminal), pre-commit hooks will fail. Always run with `env -u VIRTUAL_ENV` or clear the variable first:

```bash
unset VIRTUAL_ENV
```

## License

MIT
