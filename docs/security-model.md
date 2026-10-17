# Security Model

## Principle

**Whitelist operations, don't blacklist commands.**

The model can only call the tools that exist. Each tool validates its inputs, builds a
bounded operation and passes it to an executor. There is no `exec_command`, no `run_shell`
and no path where arbitrary user text is concatenated into a shell string.

## What the agent cannot do

- Execute arbitrary commands or open a shell
- Run `docker run`, `docker exec` or `docker build`
- Read files outside `security.services_path/<service>/`
- Read `.env`, `.ssh`, private keys, tokens or `/etc/shadow`
- Escalate privileges with `sudo`
- Download or upload files
- Use the InfluxDB or Prometheus APIs to write data
- Bypass output limits or the audit log

## Controls

### 1. Fixed tool catalog

The MCP servers expose a small, explicit set of tools. There is no generic command tool and
no "execute this string" escape hatch.

### 2. Typed command construction

Docker commands are `Operation` templates with argv vectors rendered by `shlex.join`. Values
are validated first (service name regex, bounded integers), then substituted literally.
Disk-health commands are built from validated device names and checked by
`SecurityValidator.is_command_safe()`.

The local executor rejects shell operators entirely and uses `create_subprocess_exec`
without a shell.

### 3. Input validation

Service names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`, start with an alphanumeric character
and be at most 100 characters. Device names must match a block-device pattern (`sda`,
`nvme0n1`, `vda`, `mmcblk0p1`, `dm-0`, ...). File paths are relative, length-limited,
reject null bytes, URL-encoded traversal, Unicode dot variants, shell metacharacters and
sensitive names, and must resolve inside the service directory.

### 4. Path confinement on the target

For SSH, file access uses SFTP. The requested path and the allowed base are resolved with
the remote `realpath`, and the resolved file must be inside the resolved service directory.
This closes symlink escapes that a local lexical check cannot see. The local executor does
the equivalent with `Path.resolve()`.

### 5. Verified SSH transport

Host keys are verified against `ssh.known_hosts` by default. A missing known_hosts file is
an error with instructions, not a silent fallback to "no verification". Legacy entries that
modern cryptography cannot parse are skipped individually with a warning; verification
stays enabled for every other host. Disabling verification requires an explicit
`known_hosts: "none"` and logs a warning.

### 6. Read-only data access

InfluxDB SQL is parsed with `sqlparse`: exactly one statement, must be `SELECT`, write
keywords (`INTO`, `DROP`, `INSERT`, `UPDATE`, ...) rejected. A `LIMIT` is appended when
missing. PromQL is sent to Prometheus's read-only instant-query endpoint; quotes, label
matchers and comparison operators are allowed because the query is never executed by a
shell.

Use read-only tokens for both services. The MCP is not a substitute for database-side
authorization.

### 7. Output safety

All executor output, file contents and HTTP responses pass through `sanitize_output`:
ANSI/OSC escapes and control characters are stripped, and the result is capped at
`output.max_bytes` (64 KiB by default). This limits context flooding and reduces the
surface for terminal-escape and prompt-injection tricks.

### 8. Audit logging

`audit.enabled` writes JSONL records for commands, blocked commands, timeouts, file reads
and directory listings. Records include timestamps, duration, exit status and truncation
state. Password/token/secret fields are redacted. The log is best effort: a write failure
never blocks an operation.

### 9. MCP tool annotations

Read-only tools set `readOnlyHint: true`; `restart_service` and `stop_service` set
`destructiveHint: true`. Clients can use this metadata for auto-approval policies.

## Known limitations

- **Container name = service directory name.** The service tools assume the Docker container
  is named like the directory under `services_path`. Compose projects with generated names
  need a mapping feature (not implemented).
- **Docker socket access is powerful.** The MCP process can control any container the Docker
  daemon allows. Run it as a dedicated user and consider a restricted Docker socket proxy.
- **Logs and files are untrusted input.** Output is sanitized and capped, but a compromised
  container can still write misleading text into its logs. Treat tool output as data, not
  instructions.
- **The local executor runs as the MCP user.** If that user can run `docker` and `smartctl`,
  so can the tools. Do not run the MCP as root unless the target tools require it.
- **InfluxDB/Prometheus tokens are as powerful as their scope.** Use read-only tokens.
- **No multi-target support.** One process manages one target (remote or local). Run
  multiple instances for multiple hosts.
- **stdio only.** The servers do not expose an HTTP transport yet.

## Reporting

Please report vulnerabilities privately. See [SECURITY.md](../SECURITY.md).
