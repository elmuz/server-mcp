# Quick Start Guide

## Your Secure Remote Server MCP is Ready! 🎉

You now have a **security-first** MCP server for managing remote servers.

## What You Got

An MCP server that provides AI assistants with **safe, controlled operations**:

### ✅ Available Operations

**SSH / Docker** (remote server via SSH):

- List services in `/srv/`
- View Docker container logs
- Check service status and resource usage
- Start/stop/restart containers
- Read service configuration files
- Search logs for patterns
- Monitor server health

**Database Queries** (HTTP/S, no SSH):

- Query InfluxDB v3 using SQL (read-only, SELECT only)
- Query Prometheus using PromQL
- List Prometheus scrape targets and health

### ❌ Blocked Operations

- Generic command execution (removed entirely)
- Access to sensitive files (`.env`, keys, credentials)
- Path traversal outside `/srv/{service}/`
- Privilege escalation (`sudo`, `su`)
- Shell execution (`bash`, `python`, etc.)
- System configuration changes

## Security Model

**Design Principle: Whitelist operations, don't blacklist commands.**

Instead of trying to filter dangerous commands (impossible to do perfectly), we only expose **specific, safe operations** that the AI actually needs.

**Example:**
- ❌ Old approach: `exec_command("docker logs myapp")` with filtering
- ✅ New approach: `get_service_logs("myapp")` - specific, validated, safe

## Next Steps

### 1. Configure Your Server (5 minutes)

```bash
# Copy the example config
cp config.example.yaml config.yaml

# Edit with your server details
nano config.yaml
```

Update these fields:

```yaml
ssh:
  host: "your-server.example.com"
  username: "your-username"
  key_path: "~/.ssh/id_rsa"  # or use password
```

### 2. Test It Works

```bash
# Run security tests (20 tests, all should pass)
uv run pytest tests/test_security.py -v

# Verify tools are registered
uv run python test_tools.py
```

### 3. Use with Qwen Code

The MCP server is **already configured** in `.qwen/settings.json`. Just restart Qwen Code!

**Example conversation:**

```text
You: "Can you check what's wrong with my web-server service?"

Qwen: [Uses get_service_logs tool]
      "I can see the error in the logs..."
      
Qwen: [Uses get_service_status tool]
      "The container is running but using high CPU..."
```

## Security Features

### Path Restriction

All file access limited to `/srv/{service}/`:
- ✅ `get_service_file("myapp", "config.yml")` → `/srv/myapp/config.yml`
- ❌ `get_service_file("myapp", "../../etc/passwd")` → **Blocked**
- ❌ `get_service_file("myapp", ".env")` → **Blocked**

### Service Name Validation

Only safe characters allowed:
- ✅ `myapp`, `web-server`, `database_01`
- ❌ `myapp;rm -rf /` → **Blocked**
- ❌ `app$(whoami)` → **Blocked**

### Sensitive File Protection

These patterns are **always** blocked:
- `.env`, `.env.local`, `.env.production`
- `.ssh/*`, `id_rsa`, `id_ed25519`
- `*.key`, `*.pem` (certificates/keys)
- Files with `secret`, `password`, `token`, `credential` in name

### Command Injection Prevention

All inputs sanitized:
- Shell special characters removed
- No command substitution
- No variable expansion
- No pipe/redirect

## Files Created

```text
src/remote_server_mcp/
├── server.py                # MCP server with 10 secure tools
├── ssh_manager.py           # SSH connection manager
├── security.py              # Security validator (250+ lines)
└── config.py                # Config loader

tests/
└── test_security.py         # 20 comprehensive security tests

config.example.yaml          # Example configuration
test_tools.py                # Tool verification script
```

## Common Commands

```bash
# Run security tests
uv run pytest tests/test_security.py -v

# Verify tools
uv run python test_tools.py

# Run MCP server standalone (for debugging)
uv run python -m remote_server_mcp.server

# View configuration
cat config.yaml
```

## Security Testing

The test suite covers:

✅ **140+ tests** covering:
- Service name validation (valid/invalid names)
- File path validation (valid paths, traversal attacks, sensitive files)
- Search pattern sanitization
- Command safety validation
- Attack scenarios (injection, traversal, data extraction)
- Tool registration verification
- **InfluxDB query validation** (SQL injection, shell injection, write operations)
- **Prometheus query validation** (shell injection, quote escaping)
- **Live database integration tests** (authentication, table access, data parsing)

Run them:

```bash
uv run pytest tests/test_security.py -v
```

## Troubleshooting

**Qwen doesn't see the tools?**
- Restart Qwen Code
- Check `.qwen/settings.json` has the `mcpServers` section

**SSH connection fails?**
- Test manually: `ssh -i ~/.ssh/id_rsa user@server`
- Check `config.yaml` has correct host/credentials

**Tests failing?**

```bash
uv run pytest tests/test_security.py -v
```

## What's MCP?

**MCP (Model Context Protocol)** is like USB-C for AI assistants. Build once, works everywhere:
- Qwen Code ✅
- Claude Desktop ✅
- Any MCP client ✅

Learn more: [modelcontextprotocol.io](https://modelcontextprotocol.io)

## Need Help?

See the full documentation in:
- `README.md` - Complete guide with security details
- `AGENTS.md` - Project overview
- `config.example.yaml` - Configuration reference

---

**Ready to go!** 🚀

Configure your server in `config.yaml` and start asking Qwen Code to help manage your remote servers **safely**!
