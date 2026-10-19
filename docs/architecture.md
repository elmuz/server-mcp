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
   │ tool call (stdio MCP, or opt-in Streamable HTTP)
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
MCP result (text + ToolResponse structuredContent)
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
| `security.py` | Service/device/path validation, sensitive-file policy, SQL/PromQL read-only checks, command policy (including container runtimes and Compose scoping) |
| `base.py` | Shared executor primitives, path confinement, audit/output settings |
| `ssh_manager.py` | asyncssh connection, host key verification, SFTP file access |
| `tunnel.py` | Optional loopback SSH forwarding for InfluxDB/Prometheus endpoints |
| `local_executor.py` | Local argv execution and filesystem access |
| `executor.py` | `Executor` protocol and `create_executor()` factory |
| `config.py` | Config resolution, defaults, deep merge, env overrides, `.env` |
| `output.py` | ANSI/control-character stripping and byte caps |
| `redaction.py` | Dotenv, service-config and host-output secret masking for readable-but-redacted reads |
| `audit.py` | JSONL audit log with secret redaction |
| `http_clients.py` | InfluxDB v3 and Prometheus read-only clients |
| `responses.py` | `ToolResponse`/`ToolOutput` and the structured-output tool wrapper |
| `rate_limit.py` | Sliding-window limiter for state-changing tools |
| `transport.py` | Opt-in Streamable HTTP serving and bearer-token middleware |

## Executors

`create_executor(config, security)` returns `SSHManager` or `LocalExecutor` based on
`config["executor"]`. Both implement:

- `execute_safe_command(command, timeout)`
- `check_service_exists(service)`
- `read_remote_file(path, allowed_base, max_bytes)`
- `list_remote_dir(path, allowed_base)`
- `connect()` / `disconnect()`

The SSH executor keeps one lazily connected session, serializes concurrent `connect()` calls so only one connection can be opened, and reconnects after a connection loss.
The local executor has no connection lifecycle; the methods are no-ops for interface parity.

Metric endpoints are separate from the executor. `tunnel.py` can open an optional loopback
port forward over a dedicated SSH connection for an InfluxDB or Prometheus server that only
listens on the target's loopback interface. The server rewrites the database section's
`host`/`port` to the tunnel endpoint at startup, re-opens the forward on the same local port if the SSH connection drops, and closes the tunnels on shutdown. HTTP clients keep one shared session per service for the process lifetime.

## Host infrastructure services

Not every service is a Docker container. The monitoring collector (`telegraf`), `smartd`,
`docker`, `snapraid`, `mergerfs` and `smbd` run as systemd units on the host and write to
the journal. `remote-server-mcp` exposes `get_host_service_status` and
`get_host_service_logs`, which build `systemctl status` / `journalctl -u` argv vectors from
the operation catalog.

The unit name is validated twice: `SecurityValidator.validate_host_unit()` requires a
well-formed systemd unit name and membership in `security.host_units` (default:
`telegraf`, `smartd`, `docker`, `snapraid`, `mergerfs`, `smbd`), then the rendered command
passes the shared argv allowlist. An arbitrary unit is rejected before the executor runs
anything, so host infrastructure services are in scope only through the explicit allowlist.

## Service and container resolution

`remote-server-mcp` treats a directory below `security.services_path` as the primary
service identifier. `resolution.py` lists containers with `docker ps -a` and maps a
directory to the containers whose `com.docker.compose.project` label matches; if no label
matches, it falls back to a container with the same name. A container name is accepted
directly when its compose project maps to a service directory or when the name is listed
in `security.allowed_containers`. The resolver rejects unknown targets and never passes a
raw target to Docker without service-name validation and a `--` terminator.

## Command construction

Both MCP servers define their host commands once in an `operations.py` catalog as
`Operation(argv, ...)` templates. Values are substituted literally and the vector is
rendered with `shlex.join`, so a validated service, device or unit name can never become
shell syntax. Log search filters lines in Python, which keeps both executors shell-free.
The disk-health catalog also covers the mergerFS + SnapRAID stack (`snapraid status`,
`findmnt`, `df`) next to the ZFS and mdadm operations.

The rendered command still passes `SecurityValidator.is_command_safe()` in the executor. That
policy is a strict argv allowlist: the command must round-trip through `shlex`, match a known
executable and subcommand, and contain no shell metacharacters. Unknown commands are
rejected; there is no fall-through to a permissive default.

## MCP layer

- MCP SDK 2.x (`mcp.server.mcpserver.MCPServer`).
- stdio by default; Streamable HTTP is opt-in, loopback-first and token-protected.
  Logs go to stderr.
- Tools declare `ToolAnnotations` (`read_only_hint`, `destructive_hint`) so clients can
  auto-approve reads and ask for confirmation on destructive actions.
- Tools return a readable text block plus a `ToolResponse` structured payload. Size limits
  are enforced in the library, not in the client.
- Two static resources (`server-mcp://config/schema`, `server-mcp://tools/catalog`) and a
  `server-mcp://tools/{name}` template expose configuration defaults (secrets masked) and
  tool metadata without executing anything.

## Container runtime adapter

The remote-server catalog is built per runtime (`docker`, `podman` or `nerdctl`) from
`container_runtime`. `build_container_catalog()` produces every operation once, so the
tools, the resolver and the tests use the selected CLI consistently. Compose operations
carry `--project-directory <services_path>/<service>`; the command policy validates that
directory and the exact subcommand arguments, and rejects any other Compose invocation.

## Why a monorepo

The three projects were originally separate repositories. That caused version drift, three
copies of the same tooling and a git dependency that had to be manually refreshed. A uv
workspace keeps one lockfile, one set of lint/type/test settings and atomic changes across
the library and its consumers, while still producing three independently installable
packages.
