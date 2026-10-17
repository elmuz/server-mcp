# Development

## Project Structure

```text
disk-health-mcp/
├── src/disk_health_mcp/       # Main package
│   ├── __init__.py            # Package entry point
│   ├── server.py              # MCP server (11 tools)
│   └── smart_parser.py        # SMART parser + normalizer
├── tests/
│   ├── test_security.py       # Security validation tests
│   └── test_smart_parser.py   # SMART parser tests
├── docs/
│   ├── development.md         # This file
│   ├── getting-started.md     # Setup guide
│   ├── security-model.md      # Security design
│   └── tools.md               # Tool descriptions
├── scripts/
│   └── check_md_links.py      # Markdown link checker
├── pyproject.toml             # Build config
├── .pre-commit-config.yaml    # Pre-commit hooks
├── .pymarkdown                # Markdown linter config
└── config.example.yaml        # Config template
```

## Dependencies

disk-health-mcp depends on [server-management-lib](https://github.com/elmuz/server-management-lib) for:

- `SecurityValidator` — Device names, command whitelist, query validation
- `SSHManager` — Secure SSH connections
- `InfluxDBClient` / `PrometheusClient` — Time-series database clients
- `load_config` — YAML configuration loading

Shared security and SSH logic live in the library, not in this project.

## Development Commands

```bash
# Run tests
uv run pytest tests/ -v

# Run security tests only
uv run pytest tests/test_security.py -v

# Run SMART parser tests only
uv run pytest tests/test_smart_parser.py -v

# Run linting
uv run ruff check .

# Fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Type checking
uv run ty check

# Markdown linting
uv run pymarkdown -c .pymarkdown scan .

# Fix markdown issues
uv run pymarkdown -c .pymarkdown fix .

# Link checking
uv run python scripts/check_md_links.py

# Run all checks (what pre-commit does)
uv run ruff check . && uv run ruff format --check . && uv run ty check && uv run pymarkdown -c .pymarkdown scan . && uv run python scripts/check_md_links.py && uv run pytest tests/ --cov=disk_health_mcp --cov-report=term-missing --tb=short
```

## Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`:

- **ruff**: Linting and formatting (from astral-sh/ruff-pre-commit)
- **ty**: Type checking (local hook)
- **pytest**: Run all tests (local hook)
- **coverage**: Coverage threshold enforcement (local hook)
- **pymarkdown**: Markdown linting (local hook)
- **check-md-links**: Markdown link checker (local hook)

To run manually:

```bash
pre-commit run --all-files
```

## Adding New Tools

Add a decorated function in `server.py`:

```python
@mcp.tool()
async def my_new_tool(device: str) -> str:
    """Description of the tool."""
    if not security.validate_device_name(device):
        return "❌ Invalid device name"

    cmd = f"safe-diagnostic /dev/{device}"
    if not security.is_command_safe(cmd):
        return "❌ Command not in whitelist"

    try:
        await ssh_manager.connect()
        return await ssh_manager.execute_safe_command(cmd)
    finally:
        await ssh_manager.disconnect()
```

### Security Requirements

All tools MUST:
1. Validate device names with `security.validate_device_name()`
2. Use whitelisted commands via `security.is_command_safe()`
3. Use `ssh_manager` for SSH execution (never raw SSH execution)
4. NOT expose sensitive data
5. NOT allow command injection
6. Connect/disconnect SSH properly (use try/finally)

### Data Source Priority

When reading disk health data, prefer existing telemetry sources first:
1. **InfluxDB** (Telegraf smart plugin) — no root needed
2. **Prometheus** (node_exporter smartmon) — no root needed
3. **smartctl/nvme-cli via SSH** — fallback, requires sudo

This lets agents diagnose disks without elevated privileges.
Add helpful hints when SSH fallback fails (see `_enrich_error_output()`).

## TDD Approach for Security Tests

When adding a new tool or feature, write security tests first:

```python
class TestNewFeature:
    """Tests for the new feature."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_inputs_accepted(self):
        """Valid inputs should pass validation."""
        assert self.security.validate_something("valid_input") is True

    def test_injection_blocked(self):
        """Injection attempts should be rejected."""
        assert self.security.validate_something("input;rm -rf /") is False
```

## Markdown Editing Rules

When editing markdown files, follow these rules:

1. **No trailing whitespace** at the end of lines (pymarkdown rule)
2. **Always specify code block languages** (e.g., `` ```python `` not just `` ``` ``)
3. **Blank lines around lists** (pymarkdown rule MD032)
4. **No duplicate headings** (pymarkdown rule MD024)
5. **Use hyphens for lists**, not asterisks
6. **Check links after editing**: `uv run python scripts/check_md_links.py`
