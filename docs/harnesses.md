# Harnesses

Server MCP speaks standard MCP over **stdio** by default. Streamable HTTP is available for
clients that cannot launch a process; see
[configuration.md](configuration.md#transport). The snippets below assume the repository is
at `/path/to/server-mcp`; replace that path and the config paths.

For an installed release, replace the `uv run --project ... --package ...` command with
`uvx remote-server-mcp` or `uvx disk-health-mcp` once the packages are on PyPI.

## Generic stdio entry

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": [
        "run",
        "--project", "/path/to/server-mcp",
        "--package", "remote-server-mcp",
        "remote-server-mcp"
      ],
      "env": {
        "REMOTE_SERVER_MCP_CONFIG": "/home/me/.config/remote-server-mcp/config.yaml"
      }
    },
    "disk-health": {
      "command": "uv",
      "args": [
        "run",
        "--project", "/path/to/server-mcp",
        "--package", "disk-health-mcp",
        "disk-health-mcp"
      ],
      "env": {
        "DISK_HEALTH_MCP_CONFIG": "/home/me/.config/disk-health-mcp/config.yaml"
      }
    }
  }
}
```

## Streamable HTTP entry

Start the server yourself when the client only accepts a URL:

```bash
MCP_HTTP_TOKEN="$(cat ~/.config/remote-server-mcp/http-token)" \
  remote-server-mcp --transport streamable-http --http-host 127.0.0.1 --http-port 8000
```

Point the client at `http://127.0.0.1:8000/mcp` and configure the same bearer token in
the client's MCP headers. Without `MCP_HTTP_TOKEN`, the server only accepts a loopback
bind. See [configuration.md](configuration.md#transport).

## pi

User-level:

```bash
pi mcp add remote-server -- \
  uv run --project /path/to/server-mcp --package remote-server-mcp remote-server-mcp
pi mcp add disk-health -- \
  uv run --project /path/to/server-mcp --package disk-health-mcp disk-health-mcp
pi mcp list
```

Project-level (`.pi/mcp.json`):

```bash
pi mcp add -l remote-server -- \
  uv run --project /path/to/server-mcp --package remote-server-mcp remote-server-mcp
```

Pass config paths with `--env`:

```bash
pi mcp add remote-server --env REMOTE_SERVER_MCP_CONFIG="$HOME/.config/remote-server-mcp/config.yaml" -- \
  uv run --project /path/to/server-mcp --package remote-server-mcp remote-server-mcp
```

## Claude Code

Project scope (`.mcp.json` in the project that should use the server):

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": [
        "run",
        "--project", "/path/to/server-mcp",
        "--package", "remote-server-mcp",
        "remote-server-mcp"
      ],
      "env": {
        "REMOTE_SERVER_MCP_CONFIG": "/home/me/.config/remote-server-mcp/config.yaml"
      }
    }
  }
}
```

Or from the shell:

```bash
claude mcp add remote-server --scope user -- \
  uv run --project /path/to/server-mcp --package remote-server-mcp remote-server-mcp
```

## Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.remote-server]
command = "uv"
args = [
  "run",
  "--project", "/path/to/server-mcp",
  "--package", "remote-server-mcp",
  "remote-server-mcp",
]

[mcp_servers.remote-server.env]
REMOTE_SERVER_MCP_CONFIG = "/home/me/.config/remote-server-mcp/config.yaml"

[mcp_servers.disk-health]
command = "uv"
args = [
  "run",
  "--project", "/path/to/server-mcp",
  "--package", "disk-health-mcp",
  "disk-health-mcp",
]

[mcp_servers.disk-health.env]
DISK_HEALTH_MCP_CONFIG = "/home/me/.config/disk-health-mcp/config.yaml"
```

## Cursor

`.cursor/mcp.json` (project) or the user-level equivalent:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": [
        "run",
        "--project", "/path/to/server-mcp",
        "--package", "remote-server-mcp",
        "remote-server-mcp"
      ],
      "env": {
        "REMOTE_SERVER_MCP_CONFIG": "/home/me/.config/remote-server-mcp/config.yaml"
      }
    }
  }
}
```

## opencode

`opencode.json`:

```json
{
  "mcp": {
    "remote-server": {
      "type": "local",
      "command": [
        "uv", "run",
        "--project", "/path/to/server-mcp",
        "--package", "remote-server-mcp",
        "remote-server-mcp"
      ],
      "environment": {
        "REMOTE_SERVER_MCP_CONFIG": "/home/me/.config/remote-server-mcp/config.yaml"
      },
      "enabled": true
    }
  }
}
```

## Notes

- MCP clients start the server; do not run it in a terminal at the same time unless you are
  debugging.
- Logs go to stderr. Set `MCP_LOG_LEVEL=DEBUG` for troubleshooting.
- The server exits with status 2 when no configuration file is found. Pass `--config` or the
  config environment variable in the client entry.
- Stdio is the default and best-supported transport. If a client requires a URL, run
  `--transport streamable-http` on loopback (or with a bearer token) and point the client at
  the `/mcp` endpoint.
