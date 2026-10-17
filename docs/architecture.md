# Architecture

## Layout

```text
server-mcp/
├── apps/
│   ├── remote-server-mcp/          MCP tool layer for Docker service operations
│   └── disk-health-mcp/            MCP tool layer for disk diagnostics
├── packages/
│   └── server-management-lib/      shared policy, executors, config, HTTP clients
├── docs/
├── examples/
└── scripts/
```

The apps are deliberately thin. They define tool schemas, validate inputs, build operations
and format results. Anything security-relevant lives in the library so both servers get the
same behaviour.

## Request flow

```text
MCP client
   │ tool call (stdio MCP)
   ▼
tool function (apps/*/server.py)
   │ validate service/device/path/query
   ▼
Operation.render(...) or validated command
   │ argv vector -> shlex.join
   ▼
executor.execute_safe_command(...)
   │ policy check, audit, timeout
   ├── SSHManager: asyncssh connection, host key verification
   └── LocalExecutor: create_subprocess_exec (no shell)
   │
   ▼
sanitize_output(...)  strip ANSI/control chars, cap bytes
   │
   ▼
MCP result (text)
```

File reads do not go through a shell:

```text
tool -> executor.read_remote_file(path, allowed_base=service_dir)
     -> SFTP realpath + base check (SSH)  or  Path.resolve + base check (local)
     -> size cap, UTF-8 decode, sanitize
```

## Library modules

| Module | Responsibility |
|---|---|
| `security.py` | Service/device/path validation, SQL/PromQL read-only checks, command policy |
| `base.py` | Shared executor primitives, path confinement, audit/output settings |
| `ssh_manager.py` | asyncssh connection, host key verification, SFTP file access |
| `local_executor.py` | Local argv execution and filesystem access |
| `executor.py` | `Executor` protocol and `create_executor()` factory |
| `config.py` | Config resolution, defaults, deep merge, env overrides, `.env` |
| `output.py` | ANSI/control-character stripping and byte caps |
| `audit.py` | JSONL audit log with secret redaction |
| `http_clients.py` | InfluxDB v3 and Prometheus read-only clients |

## Executors

`create_executor(config, security)` returns `SSHManager` or `LocalExecutor` based on
`config["executor"]`. Both implement:

- `execute_safe_command(command, timeout)`
- `check_service_exists(service)`
- `read_remote_file(path, allowed_base, max_bytes)`
- `list_remote_dir(path, allowed_base)`
- `connect()` / `disconnect()`

The SSH executor keeps one lazily connected session and reconnects after a connection loss.
The local executor has no connection lifecycle; the methods are no-ops for interface parity.

## Command construction

`remote-server-mcp` commands are defined once in `operations.py` as `Operation(argv, ...)`
templates. Values are substituted literally and the vector is rendered with `shlex.join`, so
a validated service name can never become shell syntax. The only operation that used a pipe
(log search) now filters lines in Python, which keeps both executors shell-free.

`disk-health-mcp` builds short commands from validated device names (`sda`, `nvme0n1`,
`dm-0`, ...) and checks them against the command policy before execution.

## MCP layer

- MCP SDK 2.x (`mcp.server.mcpserver.MCPServer`).
- stdio transport; logs go to stderr.
- Tools declare `ToolAnnotations` (`read_only_hint`, `destructive_hint`) so clients can
  auto-approve reads and ask for confirmation on destructive actions.
- Tool results are text; size limits are enforced in the library, not in the client.

## Why a monorepo

The three projects were originally separate repositories. That caused version drift, three
copies of the same tooling and a git dependency that had to be manually refreshed. A uv
workspace keeps one lockfile, one set of lint/type/test settings and atomic changes across
the library and its consumers, while still producing three independently installable
packages.
