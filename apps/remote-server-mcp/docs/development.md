# Development

## Project Structure

```text
remote-server-mcp/              # This project — MCP server layer
├── src/remote_server_mcp/
│   ├── __init__.py             # Entry point
│   └── server.py               # MCP server (13 tools)
├── tests/
│   ├── test_security.py            # Core security tests
│   ├── test_security_bypass.py     # Advanced bypass/encoding tests
│   ├── test_database_tools.py      # InfluxDB + Prometheus tests
│   └── test_ssh_connection.py      # SSH connection tests
├── docs/                       # Documentation
├── .pre-commit-config.yaml
├── config.example.yaml
└── pyproject.toml
```

**Dependencies:**
- **server-management-lib** — provides `SecurityValidator`, `SSHManager`, `InfluxDBClient`, `PrometheusClient`, `load_config`
- **mcp** — Model Context Protocol framework

## Commands

```bash
# Run all tests
uv run pytest tests/ -v

# Security tests only
uv run pytest tests/test_security.py tests/test_security_bypass.py -v

# Lint Python
uv run ruff check .

# Fix Python linting issues
uv run ruff check --fix .

# Format Python
uv run ruff format .

# Type check
uv run ty check

# Lint Markdown (style/formatting)
uv run pymarkdown -c .pymarkdown scan README.md docs/*.md

# Fix Markdown (auto-fixes what it can)
uv run pymarkdown -c .pymarkdown fix README.md docs/*.md

# Check Markdown links (relative links + anchors)
uv run python scripts/check_md_links.py

# Run all checks
uv run ruff check . && uv run ruff format . && uv run ty check \
  && uv run pytest tests/ -v --tb=short \
  && uv run pymarkdown -c .pymarkdown scan README.md docs/*.md \
  && uv run python scripts/check_md_links.py
```

## Pre-commit

Hooks run automatically on `git commit`:

- **ruff** — Python linting and formatting
- **ty** — Python type checking
- **pytest** — all tests
- **pymarkdown** — Markdown style/formatting lint
- **check-md-links** — Markdown link validation (relative links + anchors)

Run manually: `env -u VIRTUAL_ENV pre-commit run --all-files`

## Adding New Tools

Add a decorated function in `server.py`:

```python
@mcp.tool()
async def my_new_tool(service: str) -> str:
    """Description of the tool."""
    if not security.validate_service_name(service):
        return "❌ Invalid service name"

    # Construct command from validated inputs only
    cmd = f"safe-command -- {service}"
    return await ssh_manager.execute_safe_command(cmd)
```

**Rules for new tools:**

1. Always validate service names with `security.validate_service_name()`
2. Always validate file paths with `security.validate_service_file_path()`
3. Use `ssh_manager.execute_safe_command()` — never raw SSH execution
4. Do not expose sensitive data in output
5. Do not allow command injection via input parameters
6. Use `--` separator in Docker commands (defense in depth)

## Adding Security Tests

New attack vectors should be added to `tests/test_security_bypass.py` using TDD:

1. Write a test that **fails** (demonstrates the vulnerability)
2. Fix the code to make the test **pass**
3. Verify all existing tests still pass

## Instructions for Copilot Agents

When working with markdown files, agents should:

### Writing Documentation

1. **Follow the style guide** — run `uv run pymarkdown -c .pymarkdown scan docs/` to check
2. **Use code block languages** — every fenced code block must specify a language (` ```bash`, ` ```text`, ` ```yaml`, etc.)
3. **Lists need blank lines** — put a blank line before and after lists
4. **Line length** — soft limit of 200 chars (headings: 120)
5. **Auto-fix** — run `uv run pymarkdown -c .pymarkdown fix docs/` for auto-fixable issues

### Adding Links

1. **Relative links must resolve** — `uv run python scripts/check_md_links.py` validates:
   - File links → target file must exist
   - Directory links → target directory must exist
   - Anchors (`#heading`) → heading must exist in target file
   - Cross-file anchors (`file.md#heading`) → both file and anchor must exist
2. **External URLs** — skipped by the local checker (not validated in CI)

### When Editing Existing .md Files

After any change to a `.md` file, verify:

```bash
uv run pymarkdown -c .pymarkdown scan <changed-files>
uv run python scripts/check_md_links.py
```

Both must pass. If the pre-commit hook rejects, fix the issue before committing.
