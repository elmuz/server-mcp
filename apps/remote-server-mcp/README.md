# Remote Server MCP

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A security-first MCP server that gives AI assistants controlled, safe access to manage remote servers via SSH.

**Design principle:** Whitelist operations, don't blacklist commands. No generic command execution — only 13 validated tools.

```text
┌───────────────┐    ┌──────────────────────────────┐    ┌──────────────┐
│  AI Assistant │───▶│        MCP Server            │───▶│  SSH to      │
│  (Qwen Code)  │◀───│      (Secure Tools Only)     │◀───│  Remote      │
└───────────────┘    │                              │    │  Server      │
                     │  Safe Tools:                 │    └──────────────┘
                     │  • list_services()           │
                     │  • get_service_logs()        │
                     │  • get_service_status()      │
                     │  • restart/start/stop        │
                     │  • get_service_file()        │
                     │  • list_service_files()      │
                     │  • search_service_logs()     │
                     │  • get_server_health()       │
                     │  • query_influxdb()          │
                     │  • query_prometheus()        │
                     │  • get_prometheus_targets()  │
                     └──────────────────────────────┘
                                │
                     All commands validated
                     against security policy
                     before execution
```

## Quick Start

```bash
uv pip install -e . --python .venv
cp config.example.yaml config.yaml   # edit with your SSH details
uv run pytest tests/ -v
```

See [Getting Started](docs/getting-started.md) for full setup instructions and Qwen Code integration.

## Architecture

This project is a thin MCP server layer built on top of **server-management-lib**, which provides the core security validation, SSH management, and HTTP clients:

```text
remote-server-mcp/          # This project — MCP server layer
├── src/remote_server_mcp/
│   ├── __init__.py         # Entry point
│   └── server.py           # MCP tool definitions (13 tools)
└── tests/

server-management-lib/      # Shared library (separate repo)
├── security.py             # Security validator
├── ssh_manager.py          # SSH connection handler
├── http_clients.py         # InfluxDB + Prometheus clients
└── config.py               # Configuration loader
```

## Security Model 🛡️

- ❌ No arbitrary command execution
- ❌ No file access outside `/srv/{service}/`
- ❌ No sensitive files (`.env`, `.git/`, `*.key`, secrets)
- ✅ Only specific, validated Docker operations
- ✅ All inputs sanitized against injection, traversal, and encoding bypasses

See [Security Model](docs/security-model.md) for the full threat model and controls.

## Available Tools

| Tool | Purpose |
|------|---------|
| `list_services` | List services in `/srv/` |
| `get_service_logs` | Docker container logs |
| `get_service_status` | Status + resource usage |
| `restart_service` | Restart container |
| `start_service` | Start container |
| `stop_service` | Stop container |
| `get_service_file` | Read files in `/srv/{service}/` |
| `list_service_files` | List service directory |
| `search_service_logs` | Search logs (plain text) |
| `get_server_health` | CPU / memory / disk metrics |
| `query_influxdb` | Query InfluxDB v3 via SQL (read-only) |
| `query_prometheus` | Query Prometheus via PromQL |
| `get_prometheus_targets` | List Prometheus scrape targets |

See [Tools](docs/tools.md) for detailed descriptions.

## Development

```bash
uv run ruff check . && uv run ruff format . && uv run ty check && uv run pytest tests/ -v
```

See [Development](docs/development.md) for project structure, pre-commit hooks, and how to add new tools safely.

## License

This tool is licensed under the terms of MIT license.

See [LICENSE](LICENSE) for more information.
