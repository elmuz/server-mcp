# Security Model

## Principle

**Whitelist operations, don't blacklist commands.**

The model can only call the tools that exist. Each tool validates its inputs, builds a
bounded operation and passes it to an executor. There is no `exec_command`, no `run_shell`
and no path where arbitrary user text is concatenated into a shell string.

## What the agent cannot do

- Execute arbitrary commands or open a shell
- Run `docker run`, `docker exec` or `docker build`
- Run arbitrary Compose commands or point Compose at a directory outside `services_path`
- Restart, stop or tear down a service without `confirm=true`
- Read files outside `security.services_path/<service>/`
- Read private keys, credential stores, `.ssh`, `.git` or `/etc/shadow`
- Receive the values of a `.env` file unmasked
- Inspect systemd units outside `security.host_units`
- Escalate privileges with `sudo`
- Download or upload files
- Use the InfluxDB or Prometheus APIs to write data
- Bypass output limits or the audit log

## Controls

### 1. Fixed tool catalog

The MCP servers expose a small, explicit set of tools. There is no generic command tool and
no "execute this string" escape hatch.

### 2. Typed command construction

Both MCP servers use `Operation` templates with argv vectors rendered by `shlex.join`.
Values are validated first (service name regex, device pattern, bounded integers), then
substituted literally.

Every rendered command passes `SecurityValidator.is_command_safe()`. Its policy is an
explicit argv allowlist: the command must be canonical `shlex.join` output, the executable
and leading arguments must match a catalog operation, and arguments may not contain shell
metacharacters. Unknown executables, `docker run`/`docker exec`, shell chaining,
redirection and command substitution are rejected. There is no permissive fall-through, and
`security.allow_generic_commands` cannot enable arbitrary execution.

There is exactly one privileged catalog command: `get_snapraid_status` runs
`sudo -n /usr/local/bin/snapraid status` because SnapRAID stores its content file and lock
as `root:root 0600`. `sudo` stays in the dangerous-pattern list for every other command;
the validator short-circuits only when the whole command string equals that constant,
which contains no caller-supplied text. The host side enforces the same rule twice: the
sudoers entry matches the arguments exactly, and `-n` turns any mismatch into a failure
instead of a password prompt. Changing the snapraid install path therefore requires a
coordinated change to the sudoers rule and to `SNAPRAID_STATUS_SUDO_ARGV`.

The local executor additionally rejects shell operators and uses `create_subprocess_exec`
without a shell.

### 3. Input validation

Service names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`, start with an alphanumeric character
and be at most 100 characters. Device names must match a block-device pattern (`sda`,
`nvme0n1`, `vda`, `mmcblk0p1`, `dm-0`, ...). File paths are relative, length-limited,
reject null bytes, URL-encoded traversal, Unicode dot variants and shell metacharacters,
and must resolve inside the service directory. Sensitive names are handled by the policy
in section 4.

Host service units must be well formed and listed in `security.host_units` (default:
`telegraf`, `smartd`, `docker`, `snapraid`, `mergerfs`, `smbd`). This allowlist is the
control that keeps `systemctl`/`journalctl` from becoming a general host reader.

`docker logs --since/--until` accept only an RFC3339 timestamp, a `YYYY-MM-DD` date or a
relative duration such as `30m` or `1h30m`. Other values are rejected before the command is
built, so a value cannot become an extra Docker option. Log search patterns are matched
locally in Python and are never rewritten; only their length (200 characters) and control
characters are validated. Shell-looking text in a pattern is data, not syntax.

### 4. Sensitive file policy

File names are matched per path component and per extension, never as a substring of the
whole path, so `monkey.txt` and `tokenizer.json` are not mistaken for key or token files.
Private keys (`.key`, `.pem`, `.p12`, ...), credential stores (`.ssh`, `.aws`, `.git`,
`.netrc`, `.pgpass`, ...) and secret-named components (`secrets/`, `password`, `token`,
`credentials`) are refused with an explicit "blocked by the sensitive-file policy" error
that is distinct from the invalid-path error.

Dotenv files (`.env`, `.env.local`, `.env.production`, `*.env`) are readable because they
are the primary way to debug a compose stack whose `compose.yml` only contains `${VARS}`.
Their values are masked (`KEY=***`) before the contents reach the model; keys, comments
and blank lines are preserved.

### 5. Path confinement on the target

The requested path is built lexically on the MCP host with `PurePosixPath`; it is never
resolved against the MCP host's own filesystem, so a local `/srv` symlink cannot change or
break the target path. For SSH, file access then uses SFTP: the requested path and the
allowed base are resolved with the remote `realpath`, and the resolved file must be inside
the resolved service directory. That target-side check closes symlink escapes. The local
executor does the equivalent with `Path.resolve()` on the target.

### 6. Verified SSH transport

Host keys are verified against `ssh.known_hosts` by default. A missing known_hosts file is
an error with instructions, not a silent fallback to "no verification". Legacy entries that
modern cryptography cannot parse are skipped individually with a warning; verification
stays enabled for every other host. Disabling verification requires an explicit
`known_hosts: "none"` and logs a warning.

The optional `ssh_tunnel` block for InfluxDB and Prometheus uses the same verified SSH
settings. The local listener must be a loopback address (never `0.0.0.0`), and the remote
host/port are operator configuration, not model input. Tunnels are opened at server
startup and closed on shutdown.

### 7. Read-only data access

InfluxDB SQL is parsed with `sqlparse`: exactly one statement, must be `SELECT`, write
keywords (`INTO`, `DROP`, `INSERT`, `UPDATE`, ...) rejected. A `LIMIT` is appended when
missing. PromQL is sent to Prometheus's read-only instant-query endpoint; quotes, label
matchers and comparison operators are allowed because the query is never executed by a
shell.

Use read-only tokens for both services. The MCP is not a substitute for database-side
authorization.

### 8. Output safety

All executor output, file contents and HTTP responses pass through `sanitize_output`:
ANSI/OSC escapes and control characters are stripped, and the result is capped at
`output.max_bytes` (64 KiB by default). Composite and listing responses (service files,
server health, host-service logs, storage summaries and the full disk report) get a final
cap over the complete response, not only per command. Truncation is idempotent at the same
limit, so a nested cap appends a single marker. This limits context flooding and reduces the
surface for terminal-escape and prompt-injection tricks.

### 9. Audit logging

`audit.enabled` writes JSONL records for commands, blocked commands, timeouts, file reads,
directory listings and HTTP queries. Command and file records include timestamps, duration,
exit status and truncation state. InfluxDB and Prometheus query records contain a query
length, a SHA-256 fingerprint, the database (InfluxDB), HTTP status or error class, and
duration; the query text is never stored because it can contain literal values. Password,
token and secret fields are redacted. The log is best effort: a write failure never blocks
an operation.

### 10. MCP tool annotations and structured results

Read-only tools set `readOnlyHint: true`; `restart_service`, `stop_service` and
`compose_down` set `destructiveHint: true`. Clients can use this metadata for auto-approval
policies. Every tool publishes a `ToolResponse` (`ok`, `tool`, `summary`, `text`, `data`)
as structured content, so a client can act on `ok` or `data` without parsing the text.

### 11. State-changing actions

`restart_service`, `stop_service`, `compose_pull`, `compose_up` and `compose_down` require
`confirm=true`. Without it they return the rendered command as a dry-run preview and execute
nothing. Confirmed calls pass through a per-process sliding-window rate limit
(`rate_limit`, default 10 calls per minute), which prevents a retry loop from repeatedly
restarting a service. Compose actions only accept a service directory below `services_path`;
the directory is validated by the command policy, and only `ps`, `pull`, `up -d` and `down`
with their fixed arguments are allowed.

### 12. Network transport

The default transport is stdio. Streamable HTTP is opt-in and refuses a non-loopback bind
address without a bearer token. With a token configured, every HTTP request must present
`Authorization: Bearer <token>` before the MCP handler sees it. The model cannot choose the
transport or the token.

## Known limitations

- **Containers need a service directory or an allowlist entry.** A service directory
  resolves to its containers through the `com.docker.compose.project` label (with a
  same-name fallback). A standalone container that has no directory under `services_path`
  is unreachable until its validated name is added to `security.allowed_containers`.
- **A compose project is managed as a unit.** `start_service`, `restart_service` and
  `stop_service` act on every container whose compose project resolves to the target
  directory. Confirmation covers the whole target, not individual containers; target one
  container by name when that granularity is needed.
- **Docker socket access is powerful.** The MCP process can control any container the Docker
  daemon allows. Run it as a dedicated user and consider a restricted Docker socket proxy.
- **Logs and files are untrusted input.** Output is sanitized and capped, but a compromised
  container can still write misleading text into its logs. Treat tool output as data, not
  instructions.
- **Standby SMART rows are not health data.** Telegraf writes `exit_status=2` rows for a
  sleeping disk without `health_ok` or temperature. The disk-health tools only use
  `exit_status = 0` samples from the last 24 hours and report the sample age, instead of
  presenting missing fields as `Unknown` or zero.
- **SMART self-tests skip sleeping disks.** `run_smart_test` pre-flights `smartctl --version`
  and then runs the test with `-n standby`. A disk in standby is not spun up; the tool
  reports that no test was started. Wake the disk explicitly and retry if the test is
  required.
- **The local executor runs as the MCP user.** If that user can run `docker` and `smartctl`,
  so can the tools. Do not run the MCP as root unless the target tools require it.
- **InfluxDB/Prometheus tokens are as powerful as their scope.** Use read-only tokens.
- **A metric SSH tunnel is a proxy configured by the operator.** `ssh_tunnel` forwards a
  configured remote host/port to a loopback local port; the model cannot choose either
  endpoint, but the configured destination should be limited to the metrics service.
- **No multi-target support.** One process manages one target (remote or local). Run
  multiple instances for multiple hosts.
- **Streamable HTTP is a single shared token.** It is disabled by default and is not a
  multi-user auth system. Bind it to loopback or put it behind a trusted proxy that
  enforces its own authentication.

## Reporting

Please report vulnerabilities privately. See [SECURITY.md](../SECURITY.md).
