# Harnesses

Server MCP speaks standard MCP over **stdio** by default. Streamable HTTP is available for
clients that cannot launch a process; see
[configuration.md](configuration.md#transport). The snippets below assume the repository is
at `/path/to/server-mcp`; replace that path and the config paths.

For an installed release (0.2.0 and later is on PyPI), replace the
`uv run --project ... --package ...` command with `uvx remote-server-mcp` or
`uvx disk-health-mcp`; see [releasing.md](releasing.md).

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

Pi has two distinct modes in this repository:

- **Host development.** `pi` runs on the host with the repository mounted
  directly. Use stdio MCP entries so the agent can edit the code, read
  `~/.config/server-mcp/`, inspect systemd/Podman logs and debug the real
  deployment. This is a trusted-operator environment, not a security boundary.
- **Sandbox validation.** `pi-sandbox` runs the agent in a container. It uses
  the internal `pi-control` endpoints and must not see the host config, SSH key
  or Docker socket.

The two modes use different files:

```text
.pi/mcp.json          host development (stdio or loopback)
.pi/mcp.sandbox.json  sandbox (mcp-remote / mcp-disk on pi-control)
```

`pi-sandbox` prefers `.pi/mcp.sandbox.json` and mounts it read-only over
`.pi/mcp.json` inside the container. A host-run `pi` reads `.pi/mcp.json` and
never the sandbox file. Both files are local to the checkout and ignored by
`.gitignore`.

> **Shared-workspace warning.** The sandbox mounts the workspace read-write. Do
> not later run host `pi`, tests, build, deploy or git hooks in a checkout that
> an untrusted sandbox has written to. The agent can edit `.pi/mcp.json`,
> `.pi/extensions`, `AGENTS.md`, git hooks, build metadata and scripts, and
> ignored files such as `.pi/` do not appear in `git diff`. Use a separate
> sandbox clone and approved commits, or review every changed and ignored file
> before host execution. See the open gap in
> [modernization-plan.md](modernization-plan.md#risks-and-open-questions).

The host development entries run the server as a stdio child of Pi and override
only the container-specific paths from the installed host config:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": [
        "run", "--project", ".", "--package", "remote-server-mcp",
        "remote-server-mcp", "--transport", "stdio"
      ],
      "cwd": "~/code/server-mcp",
      "env": {
        "REMOTE_SERVER_MCP_CONFIG": "${HOME}/.config/server-mcp/remote.yaml",
        "MCP_HTTP_TOKEN_FILE": "${HOME}/.config/server-mcp/secrets/http-token",
        "SSH_KEY_PATH": "${HOME}/.config/server-mcp/ssh/id_ed25519",
        "SSH_KNOWN_HOSTS": "${HOME}/.config/server-mcp/known_hosts",
        "AUDIT_LOG_PATH": "${HOME}/.local/state/server-mcp/remote.jsonl"
      }
    }
  }
}
```

The disk server uses the same pattern with `DISK_HEALTH_MCP_CONFIG`,
`disk-health-mcp` and `disk.jsonl`. This lets the host process use the installed
configuration while writing audit records to the host state directory. The
sandbox file keeps the container endpoints and `${MCP_TOKEN}`.

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
