# Security Model

## Design Principle

**Whitelist operations, don't blacklist commands.**

Only expose the specific, safe operations that AI assistants actually need for debugging services. Remove generic command execution entirely.

## What You **Cannot** Do

- Execute arbitrary commands
- Access files outside `/srv/{service}/`
- Read sensitive files (`.env`, `.ssh/*`, `*.key`, `*.pem`, secrets)
- Use `sudo` or escalate privileges
- Access system files (`/etc/shadow`, `/etc/passwd`)
- Run shells (`bash`, `sh`, `python`, etc.)
- Download/upload arbitrary files
- Modify system configuration
- Use `docker exec`, `docker run`, or `docker build`

## What You **Can** Do

- List services in `/srv/`
- View Docker container logs
- Check service status and resource usage
- Start/stop/restart Docker containers
- Read **non-sensitive** files within `/srv/{service}/`
- List files in service directories
- Search logs for plain-text patterns
- View server health metrics (CPU, memory, disk)

## Security Controls

### 1. No Generic Command Execution

`exec_command()` does not exist. Every tool constructs its own command from validated inputs. There is no code path for raw user input to reach the SSH layer.

### 2. Service Name Validation

Service names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`:

- Must start with an alphanumeric character (prevents Docker option injection like `-help`)
- Only letters, digits, hyphens, and underscores allowed
- Max 100 characters (DoS prevention)
- Additional checks for path traversal patterns, shell metacharacters, and other dangerous content

This blocks:

```text
"myapp;cat /etc/shadow"       # Command separator
"myapp$(whoami)"              # Command substitution
"myapp' && rm -rf / #"        # Quote escape
"-help"                       # Docker option injection
"../etc"                      # Path traversal
```

### 3. File Path Validation

All file access goes through `validate_service_file_path()`, which:

1. Rejects null bytes (`\x00`)
2. Rejects URL-encoded traversal (`%2e%2e%2f`, `%252f`)
3. Rejects Unicode dot variants (fullwidth dots `．．/`, zero-width spaces)
4. Rejects shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``, quotes, `!`, `~`, `#`, `@`, `:`, spaces)
5. Rejects sensitive file patterns (`.env`, `.ssh`, `.git/`, `*.key`, `*.pem`, `secret`, `password`, `token`, `/proc/`, `/sys/`, `/dev/`)
6. Requires relative paths (no absolute `/etc/passwd`)
7. Resolves the path and verifies it stays under `{services_base_path}/{service}/`

This blocks:

```text
"../../../etc/passwd"          # Classic traversal
"~/.ssh/id_rsa"               # Home directory
"%2e%2e%2fetc%2fpasswd"       # URL-encoded
"\uff0e\uff0e/"               # Unicode fullwidth dots
"config\x00.yml"              # Null byte truncation
".env"                        # Sensitive file
".git/config"                  # Git credentials
"my file.txt"                  # Space → word splitting
```

### 4. Path Resolution vs Remote Symlinks

`Path.resolve()` normalizes the path locally, catching local symlink escapes. However, **remote symlinks** on the target server are invisible to local resolution — `cat /srv/myapp/evil` would follow a remote symlink to `/etc/shadow`.

**Mitigation**: Defense in depth. Even if a symlink attack succeeds, the file content is still subject to:
- Sensitive file pattern blocking (`.git/`, `.env`, `*.key`, etc.)
- The fact that the attacker must already have write access to `/srv/` to create the symlink
- Docker container isolation (services typically run in containers with limited filesystem access)

### 5. Docker Option Injection

All Docker commands use `--` before the service name:

```bash
docker logs --tail 100 -- myapp 2>&1
docker restart -- myapp 2>&1
```

This is defense-in-depth: even if service name validation is somehow bypassed, Docker treats the name as an argument, not a flag.

### 6. Search Pattern Sanitization

Log search patterns are stripped of all shell-special characters before being passed to `grep -F`. If the pattern becomes empty after sanitization, a `ValueError` is raised (preventing `grep` from reading stdin and hanging).

This blocks:

```text
"'; cat /etc/passwd #"         # Quote break + command
"$(rm -rf /)"                  # Command substitution
"'|&$"                         # Entirely special chars → ValueError
```

### 7. Command Safety Layer

Commands constructed by the application are validated against a blocklist of truly dangerous patterns:

- Privilege escalation: `sudo`, `su`, `passwd`
- User management: `useradd`, `usermod`, `userdel`
- System changes: `chmod`, `chown`, `mount`
- Destructive: `rm -rf /`, `mkfs`, `fdisk`
- Network: `wget`, `curl`
- Shell execution: `bash`, `sh`, `zsh`, `python`, `perl`, `ruby`
- Sensitive files: `/etc/shadow`, `/etc/passwd`, `/dev/`

### 8. Known Hosts Handling

Known-hosts checking is disabled to accommodate ML-KEM/post-quantum key exchange
algorithms and non-standard key formats that asyncssh 2.22.0 doesn't support.
This is a **TOFU** (trust-on-first-use) trade-off.

## Why Not `exec_command()`?

Even with sudo stripped and command whitelists, generic command execution is fundamentally unsafe because:

1. Command injection via separators (`;`, `|`, `&&`)
2. Credential reading from `.env` files
3. SSH key and secret access
4. Docker-based host filesystem mounting
5. Unpredictable shell behavior across systems

Removing it entirely eliminates the entire attack surface.

## Adding New Tools Safely

When adding a new tool, follow the pattern:

```python
@mcp.tool()
async def my_tool(service: str) -> str:
    if not security.validate_service_name(service):
        return "❌ Invalid service name"

    # Construct command from validated inputs only
    cmd = f"some-specific-command -- {service}"
    return await ssh_manager.execute_safe_command(cmd)
```

**Never** enable `allow_generic_commands: true` in config.
