# Getting Started

## Prerequisites

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- SSH access to the target host, **or** permission to run the MCP server on the host itself
- Docker on the target host for `remote-server-mcp`
- `smartctl` / `nvme-cli` / `zpool` / `mdadm` for the matching `disk-health-mcp` tools

## 1. Install

From a checkout:

```bash
git clone https://github.com/elmuz/server-mcp.git
cd server-mcp
uv sync --all-packages --all-extras
```

When the packages are published, `uvx remote-server-mcp` and `uvx disk-health-mcp` will be
the shortest path. Until then use `uv run` from the workspace (see below).

## 2. Configure

Remote server (the default):

```bash
cp apps/remote-server-mcp/config.example.yaml apps/remote-server-mcp/config.yaml
$EDITOR apps/remote-server-mcp/config.yaml
```

Minimal SSH config:

```yaml
executor: ssh

ssh:
  host: "server.example.com"
  port: 22
  username: "admin"
  key_path: "~/.ssh/id_ed25519"
  known_hosts: "~/.ssh/known_hosts"

security:
  services_path: "/srv"
```

Or run everything on the machine where the MCP server runs:

```yaml
executor: local

security:
  services_path: "/srv"
```

With `executor: local` the SSH section is not used. Docker and disk tools run as the user
that started the MCP process; grant only the permissions that user needs.

Config is looked up in this order:

1. `--config PATH`
2. `$REMOTE_SERVER_MCP_CONFIG` (or `$DISK_HEALTH_MCP_CONFIG`)
3. `$XDG_CONFIG_HOME/<app>/config.yaml` (`~/.config/...`)
4. `./config.yaml`

Environment variables override YAML. A `.env` file next to the config is loaded
automatically. The server refuses to start if no config is found, so it can never silently
fall back to `root@localhost`.

See [configuration.md](configuration.md) for every key.

## 3. Run

```bash
# Remote server MCP
uv run --directory apps/remote-server-mcp remote-server-mcp

# Disk health MCP
uv run --directory apps/disk-health-mcp disk-health-mcp
```

Both speak MCP over stdio and log to stderr. You normally do not run them by hand; the MCP
client starts them.

## 4. Connect a client

Any MCP client works. A generic stdio entry:

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

Client-specific snippets are in [harnesses.md](harnesses.md).

## 5. Verify

Ask the agent to call `list_services` (remote) or `list_disks` (disk health). Or check the
server directly:

```bash
uv run --directory apps/remote-server-mcp python -c \
  "from remote_server_mcp.server import mcp; print([t.name for t in mcp._tool_manager.list_tools()])"
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Server exits with code 2 | No config found; pass `--config` or set the config env var |
| `known_hosts file not found` | Add the host key: `ssh-keyscan -H HOST >> ~/.ssh/known_hosts` |
| `Permission denied (publickey)` | `ssh -v HOST true`, check `key_path` and agent |
| `smartctl` permission errors | Run the MCP as a user with device access, or configure sudoers |
| `Service ... does not exist` | `services_path` must contain one directory per service |
| `Error reading file` / SFTP errors | The SSH server must allow the SFTP subsystem |
| Docker commands fail | The container name is assumed to match the service directory name |
| InfluxDB HTTP 500 | Add a `WHERE time > ...` clause; InfluxDB 3 has a file-scan limit |
| Truncated output | Raise `output.max_bytes` (default 64 KiB) deliberately |

More: [configuration.md](configuration.md) and [security-model.md](security-model.md).
