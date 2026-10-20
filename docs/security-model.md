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
explicit argv allowlist: the command must be canonical `shlex.join` output and the
**complete argument vector** must match the shape of a catalog operation. For sensitive
families the policy checks the arguments themselves, not just a prefix: `systemctl status`
must be `--no-pager --full <allowed_unit>`, `journalctl` must be
`-u <allowed_unit> -n <int> --no-pager --output short-iso`, `smartctl` accepts only
read-only flags plus `/dev/<valid_device>`, `ls`/`test` stay below `services_path`, and
Docker `inspect`/`stats` formats cannot reference `.Config`, `.Args`, `.Mounts` or
host/network configuration. Every token is also rejected if it contains a control
character (`\x00`–`\x1f`, `\x7f`) or a shell metacharacter. Unknown executables,
`docker run`/`docker exec`, shell chaining, redirection and command substitution are
rejected. There is no permissive fall-through, and `security.allow_generic_commands`
cannot enable arbitrary execution.

There is exactly one privileged catalog command: `get_snapraid_status` runs
`sudo -n /usr/local/bin/snapraid status` because SnapRAID stores its content file and lock
as `root:root 0600`. `sudo` stays in the dangerous-pattern list for every other command;
the validator short-circuits only when the whole command string equals that constant,
which contains no caller-supplied text. The model therefore cannot reach `sudo` through
any tool, even on a host that grants the executor broad passwordless sudo. `-n` makes a
missing or unmatched host rule fail instead of prompting on a non-interactive session.

The host needs either a dedicated sudoers entry for that one command or an existing
blanket passwordless sudo for the executor. The catafalco deployment uses the latter
(`security_sudoers_passwordless` in the `geerlingguy.security` role), where the dedicated
entry is simply redundant. The actual restriction on what can be executed is the command
policy, not the sudoers entry.

The local executor additionally rejects shell operators and uses `create_subprocess_exec`
without a shell.

### 3. Input validation

Service names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`, start with an alphanumeric character
and be at most 100 characters. Device names must match a block-device pattern (`sda`,
`sdaa`–`sdzz`, `nvme0n1`, `vda`, `mmcblk0p1`, `dm-0`, ...). File paths are relative, length-limited,
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

Redaction does not stop at dotenv files. Other readable service files pass through a
general key/value redactor before they are returned: YAML, JSON, INI and command-line
shapes whose key names a password, secret, token, API/private key or authorization value
are masked while the key and file structure stay readable. Keys are split on separators
and matched per word, so `POSTGRES_PASSWORD`, `api_key`, `apiKey`, `db-pass`, `dbpass`
and a bare INI `pass` or `pw` are all recognized, while `tokenizer` and `keyboard` stay
readable. `Authorization: Bearer ...` headers, JWT-shaped values and credentials embedded
in URLs are masked as well.
`systemctl status` and `journalctl -u` output is passed through the same redactor, because
`--full` command lines and journal tails can contain tokens.

### 5. Path confinement on the target

The requested path is built lexically on the MCP host with `PurePosixPath`; it is never
resolved against the MCP host's own filesystem, so a local `/srv` symlink cannot change or
break the target path. For SSH, file access then uses SFTP: the requested path and the
allowed base are resolved with the remote `realpath`, and the resolved file must be inside
the resolved service directory. That target-side check closes symlink escapes. The local
executor does the equivalent with `Path.resolve()` on the target.

Both executors require the resolved target to be a regular file before reading it. FIFOs,
device nodes and other special files are refused instead of opened, and SFTP operations are
time-bounded and local file I/O runs in a worker thread, so a special file cannot hang a
tool call or the event loop.

### 6. Verified SSH transport

Host keys are verified against `ssh.known_hosts` by default. A missing known_hosts file is
an error with instructions, not a silent fallback to "no verification". Legacy entries that
modern cryptography cannot parse are skipped individually with a warning; verification
stays enabled for every other host. Disabling verification requires an explicit
`known_hosts: "none"` and logs a warning.

The optional `ssh_tunnel` block for InfluxDB and Prometheus uses the same verified SSH
settings. The local listener must be a loopback address (never `0.0.0.0`), and the remote
host/port are operator configuration, not model input. Tunnels are opened at server
startup, re-opened on the same loopback port after an SSH disconnect, and closed on
shutdown. The model never chooses the tunnel endpoints.

### 7. Read-only data access

InfluxDB SQL is parsed with `sqlparse`: exactly one statement, must be `SELECT`, write
keywords (`INTO`, `DROP`, `INSERT`, `UPDATE`, ...) rejected and SQL comments (`--`,
`/* ... */`) rejected. The outermost query must have a numeric `LIMIT`; an existing value
above `influxdb.query_limit` is clamped, and a `LIMIT` is appended when the outermost query
has none. `LIMIT` text inside a string literal, an identifier or a nested subquery does not
count. The validator returns the sanitized query and the tools send exactly that value to
the HTTP client, not the original input. PromQL is sent to Prometheus's read-only
instant-query endpoint; quotes, label matchers and comparison operators are allowed because
the query is never executed by a shell.

`disk-health-mcp` builds some queries itself (device tag, disk serial) and the client does
not re-validate those, so the serial and the tag are allowlisted before they are quoted into
a literal: only letters, digits, space and `. _ : # / + -` are accepted, and a value that
does not match is dropped in favour of the device tag. An unreadable or odd serial therefore
degrades the lookup to a tag match instead of entering the query string.

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
directory listings, HTTP queries and Prometheus target requests. Command and file records
include timestamps, duration, exit status and truncation state. InfluxDB and Prometheus
query records contain a query length, a SHA-256 fingerprint, the database (InfluxDB), HTTP
status or error class, and duration; the query text is never stored because it can contain
literal values. Password, token and secret fields are redacted. Policy refusals that happen
before the executor also produce records: `file_blocked_sensitive`, `host_unit_blocked`,
`query_blocked` and `rate_limited`.

The audit directory is created with mode `0700` and the JSONL file is `0600`; an existing
file is tightened to `0600` on the next write. The log is best effort: a write failure never
blocks an operation.

### 10. MCP tool annotations and structured results

Read-only tools set `readOnlyHint: true`; `restart_service`, `stop_service` and
`compose_down` set `destructiveHint: true`. Clients can use this metadata for auto-approval
policies. Every tool publishes a `ToolResponse` (`ok`, `tool`, `summary`, `text`, `data`)
as structured content, so a client can act on `ok` or `data` without parsing the text.

### 11. State-changing actions

`restart_service`, `stop_service`, `compose_pull`, `compose_up` and `compose_down` require
`confirm=true`. Without it they return the rendered command as a dry-run preview and execute
nothing. State-changing calls pass through a per-process sliding-window rate limit
(`rate_limit`, default 10 calls per minute): `start_service`, `restart_service`,
`stop_service`, the compose actions and `disk-health-mcp`'s `run_smart_test`. This prevents
a retry loop from repeatedly restarting a service or starting self-tests. Compose actions
only accept a service directory below `services_path`; the directory is validated by the
command policy, and only `ps`, `pull`, `up -d` and `down` with their fixed arguments are
allowed.

### 12. Network transport

The default transport is stdio. Streamable HTTP is opt-in and refuses a non-loopback bind
address without a bearer token. With a token configured, every HTTP request must present
`Authorization: Bearer <token>` before the MCP handler sees it. The auth scheme is matched
case-insensitively (RFC 9110), while the token itself is compared in constant time. The
model cannot choose the transport or the token.

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
